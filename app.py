from flask import Flask, request, jsonify, redirect, abort, render_template_string, url_for, session, Response, send_from_directory
import sqlite3
import re
import datetime
import os
import random
import time
import threading
import logging
from collections import defaultdict, deque
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config import get_config
from flask_wtf.csrf import CSRFProtect
import qrcode
from io import BytesIO
import base64

# Flask 애플리케이션 인스턴스 생성
app = Flask(__name__)

# 환경별 설정 적용 (1-10단계)
config_class = get_config()
app.config.from_object(config_class)

# 세션 보안을 위한 시크릿 키 설정
app.secret_key = app.config.get('SECRET_KEY', 'cutlet-secret-key-change-in-production')

# CSRF 보호 비활성화 (render_template_string 사용으로 인해)
# csrf = CSRFProtect(app)

# 데이터베이스 설정 (환경 변수 기반)
DATABASE = app.config['DATABASE_PATH']

# 성능 최적화 및 보안 강화 설정 (1-9단계, 1-10단계 환경 변수화)
# Rate limiting: IP별 요청 제한
RATE_LIMIT_PER_MINUTE = app.config['RATE_LIMIT_PER_MINUTE']
request_counts = defaultdict(deque)  # IP별 요청 시간을 저장
rate_limit_lock = threading.Lock()

# 캐싱: 인기 URL 빠른 응답
URL_CACHE = {}  # short_code -> original_url 캐싱
CACHE_MAX_SIZE = app.config['CACHE_MAX_SIZE']
cache_lock = threading.Lock()

# 로그 설정 (환경 변수 기반)
log_level = getattr(logging, app.config['LOG_LEVEL'], logging.INFO)
log_file = app.config['LOG_FILE']

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Flask 앱 시작 로그
logging.info("🥩 Cutlet URL Shortener starting...")
logging.info(f"Environment: {os.environ.get('FLASK_ENV', 'development')}")
logging.info(f"Debug mode: {app.config['DEBUG']}")
logging.info(f"Database: {DATABASE}")
logging.info(f"Rate limit: {RATE_LIMIT_PER_MINUTE}/min")
logging.info(f"Cache size: {CACHE_MAX_SIZE}")

# 데이터베이스 연결 함수
def get_db_connection():
    """SQLite 데이터베이스에 연결하는 함수"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # 딕셔너리 형태로 결과 반환
    return conn

# 데이터베이스 테이블 생성 함수
def create_tables():
    """users 및 urls 테이블 및 성능 최적화 인덱스를 생성하는 함수 (2-1단계)"""
    conn = get_db_connection()
    try:
        # users 테이블 생성 (2-1단계)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                user_type TEXT NOT NULL DEFAULT 'free',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # urls 테이블 생성 (기존 + user_id 컬럼 추가)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_url TEXT NOT NULL,
                short_code TEXT NOT NULL,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                click_count INTEGER DEFAULT 0,
                expires_at TIMESTAMP,
                tags TEXT,
                is_favorite INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # 클릭 이벤트 상세 로그 테이블 (3-2단계)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS click_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER,
                short_code TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                referrer TEXT,
                device TEXT,
                browser TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE
            )
        ''')
        
        # 성능 최적화를 위한 인덱스 추가 (1-9단계 + 2-1단계)
        conn.execute('CREATE INDEX IF NOT EXISTS idx_short_code ON urls(short_code)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_original_url ON urls(original_url)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_click_count ON urls(click_count DESC)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON urls(created_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON urls(user_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_click_short_code ON click_events(short_code)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_click_created_at ON click_events(created_at)')

        # 광고 노출 로그 (3-5단계)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS ad_impressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER,
                short_code TEXT NOT NULL,
                viewer_user_id INTEGER,
                ip TEXT,
                referrer TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE,
                FOREIGN KEY (viewer_user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_adimp_short_code ON ad_impressions(short_code)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_adimp_created_at ON ad_impressions(created_at)')
        
        # 광고 클릭 로그 (3-6단계)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS ad_clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER,
                short_code TEXT NOT NULL,
                viewer_user_id INTEGER,
                ip TEXT,
                referrer TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE,
                FOREIGN KEY (viewer_user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_adclk_short_code ON ad_clicks(short_code)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_adclk_created_at ON ad_clicks(created_at)')
        
        # 결제 인덱스 보강
        conn.execute('CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at)')

        # 결제/구독 기반 테이블 (3-4단계)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount_cents INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'USD',
                status TEXT NOT NULL, -- success / failed / pending
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                plan TEXT NOT NULL, -- free / premium
                status TEXT NOT NULL, -- active / canceled / past_due
                current_period_end TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        print("✅ users 및 urls 테이블과 성능 인덱스가 성공적으로 생성되었습니다.")
    except Exception as e:
        print(f"❌ 테이블 생성 오류: {e}")
    finally:
        conn.close()

# 데이터베이스 마이그레이션 함수 (2-1단계)
def migrate_database():
    """기존 데이터베이스를 새로운 스키마로 마이그레이션하는 함수"""
    conn = get_db_connection()
    try:
        # urls 테이블에 user_id 컬럼이 있는지 확인
        cursor = conn.execute("PRAGMA table_info(urls)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'user_id' not in columns:
            print("🔄 urls 테이블에 user_id 컬럼을 추가하는 중...")
            conn.execute('ALTER TABLE urls ADD COLUMN user_id INTEGER')
            conn.commit()
            print("✅ urls.user_id 마이그레이션 완료")
        
        # urls 테이블에 expires_at 컬럼이 있는지 확인
        if 'expires_at' not in columns:
            print("🔄 urls 테이블에 expires_at 컬럼을 추가하는 중...")
            conn.execute('ALTER TABLE urls ADD COLUMN expires_at TIMESTAMP')
            conn.commit()
            print("✅ urls.expires_at 마이그레이션 완료")
        
        # urls 테이블에 tags 컬럼이 있는지 확인 (4-4단계)
        if 'tags' not in columns:
            print("🔄 urls 테이블에 tags 컬럼을 추가하는 중...")
            conn.execute('ALTER TABLE urls ADD COLUMN tags TEXT')
            conn.commit()
            print("✅ urls.tags 마이그레이션 완료")
        
        # urls 테이블에 is_favorite 컬럼이 있는지 확인 (4-4단계)
        if 'is_favorite' not in columns:
            print("🔄 urls 테이블에 is_favorite 컬럼을 추가하는 중...")
            conn.execute('ALTER TABLE urls ADD COLUMN is_favorite INTEGER DEFAULT 0')
            conn.commit()
            print("✅ urls.is_favorite 마이그레이션 완료")
        
        print("✅ urls 테이블이 이미 최신 스키마입니다.")
        
        # users 테이블에 user_type, is_active 컬럼이 있는지 확인
        cursor = conn.execute("PRAGMA table_info(users)")
        user_columns = {column[1] for column in cursor.fetchall()}
        
        if 'user_type' not in user_columns:
            print("🔄 users 테이블에 user_type 컬럼을 추가하는 중...")
            conn.execute("ALTER TABLE users ADD COLUMN user_type TEXT NOT NULL DEFAULT 'free'")
            conn.commit()
            print("✅ users.user_type 마이그레이션 완료")
        if 'is_active' not in user_columns:
            print("🔄 users 테이블에 is_active 컬럼을 추가하는 중...")
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
            conn.commit()
            print("✅ users.is_active 마이그레이션 완료")
            
    except Exception as e:
        print(f"❌ 마이그레이션 오류: {e}")
    finally:
        conn.close()

# =====================================
# 로그인 상태 관리 및 데코레이터 (2-4단계)
# =====================================

def generate_csrf_token():
    """CSRF 토큰을 생성하는 함수"""
    if 'csrf_token' not in session:
        session['csrf_token'] = ''.join(random.choices('0123456789abcdef', k=32))
    return session['csrf_token']

def is_logged_in():
    """사용자가 로그인되어 있는지 확인하는 함수"""
    return session.get('logged_in', False)

def get_current_user():
    """현재 로그인된 사용자 정보를 반환하는 함수"""
    if not is_logged_in():
        return None
    
    user_id = session.get('user_id')
    if not user_id:
        return None
    
    conn = get_db_connection()
    try:
        user = conn.execute('''
            SELECT id, username, email, user_type, is_active, created_at 
            FROM users 
            WHERE id = ? 
            LIMIT 1
        ''', (user_id,)).fetchone()
        return user
    except Exception as e:
        print(f"❌ 사용자 정보 조회 오류: {e}")
        return None
    finally:
        conn.close()

def login_required(f):
    """로그인이 필요한 페이지를 보호하는 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect('/login?message=로그인이 필요한 페이지입니다.')
        return f(*args, **kwargs)
    return decorated_function

# 데이터베이스 초기화 함수
def init_database():
    """데이터베이스를 초기화하고 테이블을 생성하는 함수"""
    print("🔄 데이터베이스 초기화 중...")
    create_tables()
    migrate_database()
    
    # 테스트 데이터가 없으면 추가
    conn = get_db_connection()
    try:
        count = conn.execute('SELECT COUNT(*) FROM urls').fetchone()[0]
        if count == 0:
            insert_test_data()
    except Exception as e:
        print(f"❌ 데이터 확인 오류: {e}")
    finally:
        conn.close()

# 테스트 데이터 삽입 함수
def insert_test_data():
    """테스트용 샘플 데이터를 삽입하는 함수"""
    conn = get_db_connection()
    try:
        test_data = [
            ('https://www.google.com', 'google1', 5),
            ('https://www.github.com', 'github1', 3),
            ('https://www.stackoverflow.com', 'stack1', 1)
        ]
        
        for original_url, short_code, click_count in test_data:
            conn.execute('''
                INSERT INTO urls (original_url, short_code, click_count) 
                VALUES (?, ?, ?)
            ''', (original_url, short_code, click_count))
        
        conn.commit()
        print("✅ 테스트 데이터가 성공적으로 삽입되었습니다.")
    except Exception as e:
        print(f"❌ 테스트 데이터 삽입 오류: {e}")
    finally:
        conn.close()

# URL 데이터 조회 함수
def get_all_urls():
    """모든 URL 데이터를 조회하는 함수"""
    conn = get_db_connection()
    try:
        urls = conn.execute('''
            SELECT id, original_url, short_code, created_at, click_count 
            FROM urls 
            ORDER BY created_at DESC
        ''').fetchall()
        return urls
    except Exception as e:
        print(f"❌ 데이터 조회 오류: {e}")
        return []
    finally:
        conn.close()

# URL 추가 함수
def add_url(original_url, short_code, user_id=None, expires_at=None, tags=None, is_favorite=False):
    """새로운 URL을 데이터베이스에 추가하는 함수 (2-1단계: user_id 지원, 4-2단계: 만료일 지원, 4-4단계: 태그/즐겨찾기 지원)"""
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO urls (original_url, short_code, user_id, expires_at, tags, is_favorite) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (original_url, short_code, user_id, expires_at, tags, 1 if is_favorite else 0))
        conn.commit()
        return True
    except Exception as e:
        print(f"❌ URL 추가 오류: {e}")
        return False
    finally:
        conn.close()

# URL 조회 함수 (short_code로 검색)
def get_url_by_short_code(short_code):
    """단축 코드로 URL 정보를 조회하는 함수"""
    conn = get_db_connection()
    try:
        url_data = conn.execute('''
            SELECT id, original_url, short_code, created_at, click_count, expires_at, tags, is_favorite
            FROM urls 
            WHERE short_code = ? 
            LIMIT 1
        ''', (short_code,)).fetchone()
        return url_data
    except Exception as e:
        print(f"❌ URL 조회 오류: {e}")
        return None
    finally:
        conn.close()

# 클릭 수 업데이트 함수
def update_click_count(short_code):
    """단축 코드의 클릭 수를 1 증가시키는 함수"""
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE urls 
            SET click_count = click_count + 1 
            WHERE short_code = ?
        ''', (short_code,))
        conn.commit()
        return True
    except Exception as e:
        print(f"❌ 클릭 수 업데이트 오류: {e}")
        return False
    finally:
        conn.close()

def log_click_event(short_code, request):
    """클릭 이벤트 상세 정보를 click_events 테이블에 저장 (3-2단계)"""
    conn = get_db_connection()
    try:
        # 해당 URL의 id 조회
        url_row = conn.execute('SELECT id FROM urls WHERE short_code = ? LIMIT 1', (short_code,)).fetchone()
        url_id = url_row['id'] if url_row else None
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if ip:
            ip = ip.split(',')[0].strip()
        ua = request.headers.get('User-Agent', '')
        ref = request.headers.get('Referer', '')
        device = 'Mobile' if any(k in ua.lower() for k in ['iphone','android','mobile']) else 'Desktop'
        browser = 'Chrome' if 'chrome' in ua.lower() else ('Firefox' if 'firefox' in ua.lower() else ('Safari' if 'safari' in ua.lower() else 'Other'))
        conn.execute('''
            INSERT INTO click_events (url_id, short_code, ip, user_agent, referrer, device, browser)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (url_id, short_code, ip, ua, ref, device, browser))
        conn.commit()
    except Exception as e:
        print(f"❌ 클릭 이벤트 기록 오류: {e}")
    finally:
        conn.close()

# =====================================
# 관리자 기능을 위한 데이터베이스 함수들 (1-7단계)
# =====================================

def get_all_urls_with_stats():
    """통계 정보를 포함한 모든 URL 데이터를 조회하는 함수 (클릭 수 기준 정렬)"""
    conn = get_db_connection()
    try:
        urls = conn.execute('''
            SELECT id, original_url, short_code, created_at, click_count,
                   LENGTH(original_url) as original_length,
                   ROUND((LENGTH(original_url) - LENGTH(short_code)) * 100.0 / LENGTH(original_url), 1) as space_saved_percent
            FROM urls 
            ORDER BY click_count DESC, created_at DESC
        ''').fetchall()
        return urls
    except Exception as e:
        print(f"❌ 통계 데이터 조회 오류: {e}")
        return []
    finally:
        conn.close()

def get_url_detailed_stats(short_code):
    """단축 코드로 상세 통계 정보를 조회하는 함수"""
    conn = get_db_connection()
    try:
        url_stats = conn.execute('''
            SELECT id, original_url, short_code, created_at, click_count,
                   LENGTH(original_url) as original_length,
                   LENGTH(short_code) as short_length,
                   ROUND((LENGTH(original_url) - LENGTH(short_code)) * 100.0 / LENGTH(original_url), 1) as space_saved_percent,
                   datetime('now') as current_time,
                   ROUND(julianday('now') - julianday(created_at), 1) as days_since_created
            FROM urls 
            WHERE short_code = ? 
            LIMIT 1
        ''', (short_code,)).fetchone()
        return url_stats
    except Exception as e:
        print(f"❌ 상세 통계 조회 오류: {e}")
        return None
    finally:
        conn.close()

def delete_url_by_short_code(short_code):
    """단축 코드로 URL을 삭제하는 함수"""
    conn = get_db_connection()
    try:
        # 먼저 해당 URL이 존재하는지 확인
        existing = conn.execute(
            'SELECT original_url FROM urls WHERE short_code = ?', 
            (short_code,)
        ).fetchone()
        
        if not existing:
            return False, "존재하지 않는 단축 코드입니다."
        
        # 삭제 실행
        conn.execute('DELETE FROM urls WHERE short_code = ?', (short_code,))
        conn.commit()
        
        print(f"✅ URL 삭제 성공: {short_code} -> {existing['original_url']}")
        return True, "URL이 성공적으로 삭제되었습니다."
        
    except Exception as e:
        print(f"❌ URL 삭제 오류: {e}")
        return False, f"삭제 중 오류가 발생했습니다: {str(e)}"
    finally:
        conn.close()

def get_total_statistics():
    """전체 서비스 통계를 조회하는 함수"""
    conn = get_db_connection()
    try:
        stats = conn.execute('''
            SELECT 
                COUNT(*) as total_urls,
                SUM(click_count) as total_clicks,
                AVG(click_count) as avg_clicks_per_url,
                MAX(click_count) as max_clicks,
                MIN(created_at) as first_url_date,
                MAX(created_at) as last_url_date,
                SUM(LENGTH(original_url)) as total_original_length,
                SUM(LENGTH(short_code)) as total_short_length
            FROM urls
        ''').fetchone()
        
        # 가장 인기 있는 URL 조회
        popular_url = conn.execute('''
            SELECT short_code, original_url, click_count 
            FROM urls 
            ORDER BY click_count DESC 
            LIMIT 1
        ''').fetchone()
        
        return {
            'total_urls': stats['total_urls'] or 0,
            'total_clicks': stats['total_clicks'] or 0,
            'avg_clicks_per_url': round(stats['avg_clicks_per_url'] or 0, 1),
            'max_clicks': stats['max_clicks'] or 0,
            'first_url_date': stats['first_url_date'],
            'last_url_date': stats['last_url_date'],
            'total_space_saved': (stats['total_original_length'] or 0) - (stats['total_short_length'] or 0),
            'popular_url': popular_url
        }
        
    except Exception as e:
        print(f"❌ 전체 통계 조회 오류: {e}")
        return {
            'total_urls': 0,
            'total_clicks': 0,
            'avg_clicks_per_url': 0,
            'max_clicks': 0,
            'first_url_date': None,
            'last_url_date': None,
            'total_space_saved': 0,
            'popular_url': None
        }
    finally:
        conn.close()

# =====================================
# URL 단축 알고리즘 (1-2단계)
# =====================================

# Base62 문자셋 정의
BASE62_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def encode_base62(num):
    """숫자를 base62 문자열로 인코딩하는 함수"""
    if num == 0:
        return BASE62_CHARS[0]
    
    result = ""
    while num > 0:
        result = BASE62_CHARS[num % 62] + result
        num //= 62
    
    return result

def decode_base62(base62_str):
    """base62 문자열을 숫자로 디코딩하는 함수"""
    result = 0
    for char in base62_str:
        result = result * 62 + BASE62_CHARS.index(char)
    return result

def generate_unique_short_code(length=6):
    """고유한 단축 코드를 생성하는 함수"""
    max_attempts = 100  # 무한 루프 방지
    
    for attempt in range(max_attempts):
        # 방법 1: 시간 기반 + 랜덤
        timestamp = int(time.time() * 1000)  # 밀리초 단위
        random_num = random.randint(0, 999999)
        combined = timestamp + random_num
        
        # Base62로 인코딩
        short_code = encode_base62(combined)
        
        # 원하는 길이로 조정
        if len(short_code) > length:
            short_code = short_code[-length:]  # 뒤에서부터 자르기
        elif len(short_code) < length:
            # 길이가 부족하면 앞에 랜덤 문자 추가
            while len(short_code) < length:
                short_code = random.choice(BASE62_CHARS) + short_code
        
        # 중복 체크
        if not is_short_code_exists(short_code):
            return short_code
    
    # 모든 시도가 실패하면 완전 랜덤 생성
    return generate_random_short_code(length)

def generate_random_short_code(length=6):
    """완전 랜덤한 단축 코드를 생성하는 함수 (fallback)"""
    max_attempts = 1000
    
    for attempt in range(max_attempts):
        short_code = ''.join(random.choice(BASE62_CHARS) for _ in range(length))
        
        if not is_short_code_exists(short_code):
            return short_code
    
    # 정말 극한 상황에서는 타임스탬프 추가
    timestamp_suffix = encode_base62(int(time.time()))[-3:]
    return ''.join(random.choice(BASE62_CHARS) for _ in range(length-3)) + timestamp_suffix

def is_short_code_exists(short_code):
    """단축 코드가 데이터베이스에 이미 존재하는지 확인하는 함수"""
    conn = get_db_connection()
    try:
        result = conn.execute(
            'SELECT 1 FROM urls WHERE short_code = ? LIMIT 1', 
            (short_code,)
        ).fetchone()
        return result is not None
    except Exception as e:
        print(f"❌ 중복 체크 오류: {e}")
        return True  # 오류 발생시 안전하게 중복으로 판단
    finally:
        conn.close()

def test_short_code_generation(count=10):
    """단축 코드 생성 알고리즘을 테스트하는 함수"""
    print(f"\n🧪 단축 코드 생성 테스트 ({count}개):")
    print("=" * 60)
    
    generated_codes = []
    
    for i in range(count):
        # 다양한 길이로 테스트
        length = 4 + (i % 4)  # 4~7 글자
        short_code = generate_unique_short_code(length)
        
        # Base62 인코딩/디코딩 테스트
        test_num = random.randint(1000, 999999)
        encoded = encode_base62(test_num)
        decoded = decode_base62(encoded)
        
        print(f"  {i+1:2d}. 코드: {short_code:8s} (길이:{len(short_code)}) | "
              f"Base62 테스트: {test_num} → {encoded} → {decoded} "
              f"{'✅' if test_num == decoded else '❌'}")
        
        generated_codes.append(short_code)
    
    # 중복 체크
    unique_codes = set(generated_codes)
    duplicate_count = len(generated_codes) - len(unique_codes)
    
    print("=" * 60)
    print(f"📊 테스트 결과:")
    print(f"  • 생성된 코드 수: {len(generated_codes)}개")
    print(f"  • 고유 코드 수: {len(unique_codes)}개") 
    print(f"  • 중복 발생: {duplicate_count}개")
    print(f"  • 성공률: {(len(unique_codes)/len(generated_codes)*100):.1f}%")
    
    return generated_codes

# =====================================
# URL 단축 기능 (1-3단계)
# =====================================

def is_valid_url(url):
    """URL이 유효한지 검사하는 함수 (1-6단계 강화)"""
    if not url or not isinstance(url, str):
        return False, "URL을 입력해주세요."
    
    # 기본적인 URL 형식 검사
    url = url.strip()
    if not url:
        return False, "URL을 입력해주세요."
    
    # 길이 제한 (너무 긴 URL 방지)
    if len(url) > 2048:
        return False, "URL이 너무 깁니다. (최대 2048자)"
    
    # http:// 또는 https://로 시작하는지 확인
    if not (url.startswith('http://') or url.startswith('https://')):
        return False, "URL은 http:// 또는 https://로 시작해야 합니다."
    
    # 최소 길이 확인 (http://a.b 정도)
    if len(url) < 10:
        return False, "올바른 URL 형식이 아닙니다."
    
    # 금지된 문자 확인
    forbidden_chars = ['<', '>', '"', '{', '}', '|', '\\', '^', '`']
    if any(char in url for char in forbidden_chars):
        return False, "URL에 허용되지 않는 문자가 포함되어 있습니다."
    
    # 보안 강화: 악성 URL 패턴 차단 (1-9단계)
    # 알려진 악성/스팸 도메인 패턴
    malicious_patterns = [
        'bit.ly', 'tinyurl.com', 'ow.ly', 't.co',  # URL 단축 서비스 체인 방지
        'phishing', 'malware', 'virus', 'scam',    # 명백한 악성 키워드
        'click-here', 'free-money', 'winner',      # 스팸 패턴
        'temp-mail', 'guerrillamail', '10minutemail',  # 임시 메일 서비스
    ]
    
    url_lower = url.lower()
    for pattern in malicious_patterns:
        if pattern in url_lower:
            return False, f"보안상 위험한 URL 패턴이 감지되었습니다: {pattern}"
    
    # 위험한 파일 확장자 차단 (파일 다운로드 URL만 체크)
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs']
    # URL 경로에서 마지막 부분만 확인 (쿼리 파라미터 제외)
    url_path = url_lower.split('?')[0].split('#')[0]
    # 파일명 부분만 추출 (마지막 / 이후)
    filename = url_path.split('/')[-1] if '/' in url_path else url_path
    
    # 실제 파일 확장자가 있는 경우만 체크
    if '.' in filename and not filename.endswith('.html') and not filename.endswith('.htm'):
        for ext in dangerous_extensions:
            if filename.endswith(ext):
                return False, f"보안상 위험한 파일 형식입니다: {ext}"
    
    # 의심스러운 포트 번호 차단 (일반적이지 않은 포트)
    import re
    port_match = re.search(r':(\d+)/', url)
    if port_match:
        port = int(port_match.group(1))
        # 일반적인 웹 포트가 아닌 경우 차단
        allowed_ports = [80, 443, 8080, 3000, 3001, 4000, 5000, 8000, 8888, 9000]
        if port not in allowed_ports:
            return False, f"허용되지 않는 포트 번호입니다: {port}"
    
    # 기본적인 도메인 형식 확인 (점이 포함되어야 함)
    try:
        # URL에서 프로토콜 제거 후 도메인 부분만 추출
        url_without_protocol = url.replace('https://', '').replace('http://', '')
        
        # 쿼리 파라미터나 프래그먼트가 있으면 제거
        if '?' in url_without_protocol:
            url_without_protocol = url_without_protocol.split('?')[0]
        if '#' in url_without_protocol:
            url_without_protocol = url_without_protocol.split('#')[0]
            
        domain_part = url_without_protocol.split('/')[0]
        
        # 도메인이 비어있으면 안됨
        if not domain_part:
            return False, "올바른 도메인이 필요합니다."
        
        # 도메인에 점이 있어야 함 (예: google.com)
        if '.' not in domain_part:
            return False, "올바른 도메인 형식이 아닙니다. (예: example.com)"
        
        # 도메인이 점으로만 구성되어 있으면 안됨
        if domain_part.replace('.', '') == '':
            return False, "올바른 도메인 형식이 아닙니다."
        
        # localhost나 내부 IP 허용
        if domain_part.startswith('localhost') or domain_part.startswith('127.0.0.1') or domain_part.startswith('192.168.'):
            return True, ""
        
        # 일반적인 도메인 형식 확인
        domain_parts = domain_part.split('.')
        if len(domain_parts) < 2:
            return False, "올바른 도메인 형식이 아닙니다."
        
        # 도메인의 각 부분이 비어있으면 안됨
        if any(not part for part in domain_parts):
            return False, "올바른 도메인 형식이 아닙니다."
            
    except Exception as e:
        return False, "URL 형식을 확인해주세요."
    
    return True, ""

# Rate Limiting 함수 (1-9단계)
def check_rate_limit(ip_address):
    """IP별 요청 횟수를 확인하여 rate limiting을 적용하는 함수"""
    current_time = time.time()
    
    with rate_limit_lock:
        # 1분 이상 된 요청은 제거
        while (request_counts[ip_address] and 
               current_time - request_counts[ip_address][0] > 60):
            request_counts[ip_address].popleft()
        
        # 현재 요청 수 확인
        if len(request_counts[ip_address]) >= RATE_LIMIT_PER_MINUTE:
            return False, f"요청 횟수 제한을 초과했습니다. 분당 {RATE_LIMIT_PER_MINUTE}회까지 허용됩니다."
        
        # 현재 요청 추가
        request_counts[ip_address].append(current_time)
        return True, ""

# 캐싱 함수들 (1-9단계)
def get_from_cache(short_code):
    """캐시에서 URL을 조회하는 함수"""
    with cache_lock:
        return URL_CACHE.get(short_code)

def add_to_cache(short_code, original_url):
    """캐시에 URL을 추가하는 함수"""
    with cache_lock:
        if len(URL_CACHE) >= CACHE_MAX_SIZE:
            # 가장 오래된 항목 제거 (LRU와 유사)
            oldest_key = next(iter(URL_CACHE))
            del URL_CACHE[oldest_key]
        
        URL_CACHE[short_code] = original_url

def shorten_url_service(original_url, user_id=None, custom_code=None, expires_at=None, tags=None, is_favorite=False):
    """URL을 단축하고 데이터베이스에 저장하는 서비스 함수 (1-6단계 개선 + 2-1단계: user_id 지원, 2-6단계: 로그인 필요)"""
    
    # 로그인한 사용자만 URL 생성 가능 (2-6단계)
    if not user_id:
        return {
            'success': False,
            'error': '로그인이 필요한 서비스입니다.',
            'error_code': 'LOGIN_REQUIRED'
        }
    
    # URL 유효성 검사 (강화된 버전)
    is_valid, error_message = is_valid_url(original_url)
    if not is_valid:
        return {
            'success': False,
            'error': error_message,
            'error_code': 'INVALID_URL'
        }
    
    # URL 정규화 (앞뒤 공백 제거)
    original_url = original_url.strip()
    
    # 이미 같은 URL이 있는지 확인 (사용자별로)
    conn = get_db_connection()
    try:
        existing = conn.execute(
            'SELECT short_code FROM urls WHERE original_url = ? AND user_id = ? LIMIT 1',
            (original_url, user_id)
        ).fetchone()
        
        if existing:
            # 이미 존재하는 URL이면 기존 short_code 반환 (1-6단계 개선)
            base_url = request.host_url.rstrip('/')  # http://localhost:8080
            short_url = f"{base_url}/{existing['short_code']}"
            
            # 캐시에 추가 (1-9단계)
            add_to_cache(existing['short_code'], original_url)
            logging.info(f"Existing URL returned and cached: {existing['short_code']} -> {original_url[:50]}...")
            
            return {
                'success': True,
                'original_url': original_url,
                'short_code': existing['short_code'],
                'short_url': short_url,
                'message': '이미 단축된 URL입니다. 기존 단축 URL을 반환합니다.',
                'is_existing': True  # 기존 URL임을 표시
            }
    except Exception as e:
        print(f"❌ 기존 URL 확인 오류: {e}")
    finally:
        conn.close()
    
    # 새로운 단축 코드 생성 (프리미엄 커스텀 코드 지원)
    try:
        if custom_code:
            # 서버 측 최종 유효성 체크 및 중복 확인
            if not re.match(r'^[A-Za-z0-9-]{3,20}$', custom_code):
                return {
                    'success': False,
                    'error': '커스텀 코드는 3-20자 영문/숫자/하이픈만 가능합니다.',
                    'error_code': 'INVALID_CUSTOM_CODE'
                }
            conn = get_db_connection()
            try:
                exists = conn.execute('SELECT 1 FROM urls WHERE short_code = ? LIMIT 1', (custom_code,)).fetchone()
                if exists:
                    return {
                        'success': False,
                        'error': '이미 사용 중인 커스텀 코드입니다.',
                        'error_code': 'CUSTOM_CODE_EXISTS'
                    }
            finally:
                conn.close()
            short_code = custom_code
        else:
            short_code = generate_unique_short_code(6)  # 6글자 코드 생성
        
        # 데이터베이스에 저장 (user_id 포함, 만료일 포함, 태그/즐겨찾기 포함)
        success = add_url(original_url, short_code, user_id, expires_at, tags, is_favorite)
        
        if success:
            # 단축 URL 생성
            base_url = request.host_url.rstrip('/')  # http://localhost:8080
            short_url = f"{base_url}/{short_code}"
            
            # 캐시에 추가 (1-9단계)
            add_to_cache(short_code, original_url)
            logging.info(f"New URL created and cached: {short_code} -> {original_url[:50]}...")
            
            return {
                'success': True,
                'original_url': original_url,
                'short_code': short_code,
                'short_url': short_url,
                'message': 'URL이 성공적으로 단축되었습니다!',
                'is_existing': False  # 새로 생성된 URL임을 표시
            }
        else:
            return {
                'success': False,
                'error': 'Failed to save URL to database',
                'error_code': 'DATABASE_ERROR'
            }
            
    except Exception as e:
        print(f"❌ URL 단축 오류: {e}")
        return {
            'success': False,
            'error': f'Internal server error: {str(e)}',
            'error_code': 'INTERNAL_ERROR'
        }

# =====================================
# 라우트 (Routes)
# =====================================

# 벌크 URL 단축 API (4-4단계)
@app.route('/bulk-shorten', methods=['POST'])
@login_required
def bulk_shorten():
    """여러 URL을 한 번에 단축하는 API (프리미엄 전용)"""
    
    # 프리미엄 사용자 확인
    current_user = get_current_user()
    if current_user['user_type'] not in ('premium', 'admin'):
        return jsonify({
            'success': False,
            'error': '벌크 URL 단축은 프리미엄 전용 기능입니다.',
            'error_code': 'PREMIUM_REQUIRED'
        }), 403
    
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({
                'success': False,
                'error': 'URL 목록이 필요합니다.',
                'error_code': 'MISSING_URLS'
            }), 400
        
        urls = data.get('urls', [])
        tags = data.get('tags', '')
        expires_at = data.get('expires_at', 'never')
        
        if not urls or len(urls) > 50:  # 최대 50개 URL
            return jsonify({
                'success': False,
                'error': 'URL은 1-50개까지 처리 가능합니다.',
                'error_code': 'INVALID_URL_COUNT'
            }), 400
        
        # 만료일 처리
        expires_at_datetime = None
        if expires_at and expires_at != 'never':
            if expires_at == '1day':
                expires_at_datetime = datetime.datetime.now() + datetime.timedelta(days=1)
            elif expires_at == '7days':
                expires_at_datetime = datetime.datetime.now() + datetime.timedelta(days=7)
            elif expires_at == '30days':
                expires_at_datetime = datetime.datetime.now() + datetime.timedelta(days=30)
        
        results = []
        success_count = 0
        
        for url_data in urls:
            original_url = url_data.get('url', '').strip()
            custom_code = url_data.get('custom_code', '').strip()
            is_favorite = url_data.get('is_favorite', False)
            
            if not original_url:
                results.append({
                    'url': original_url,
                    'success': False,
                    'error': 'URL이 비어있습니다.'
                })
                continue
            
            # URL 유효성 검사
            is_valid, error_message = is_valid_url(original_url)
            if not is_valid:
                results.append({
                    'url': original_url,
                    'success': False,
                    'error': error_message
                })
                continue
            
            # 커스텀 코드 중복 체크
            if custom_code:
                if not re.match(r'^[A-Za-z0-9-]{3,20}$', custom_code):
                    results.append({
                        'url': original_url,
                        'success': False,
                        'error': '커스텀 코드는 3-20자 영문/숫자/하이픈만 가능합니다.'
                    })
                    continue
                
                conn = get_db_connection()
                try:
                    exists = conn.execute('SELECT 1 FROM urls WHERE short_code = ? LIMIT 1', (custom_code,)).fetchone()
                    if exists:
                        results.append({
                            'url': original_url,
                            'success': False,
                            'error': '이미 사용 중인 커스텀 코드입니다.'
                        })
                        continue
                finally:
                    conn.close()
            
            # 단축 코드 생성
            short_code = custom_code if custom_code else generate_unique_short_code(6)
            
            # 데이터베이스에 저장
            success = add_url(original_url, short_code, current_user['id'], expires_at_datetime, tags, is_favorite)
            
            if success:
                base_url = request.host_url.rstrip('/')
                short_url = f"{base_url}/{short_code}"
                
                # 캐시에 추가
                add_to_cache(short_code, original_url)
                
                results.append({
                    'url': original_url,
                    'success': True,
                    'short_code': short_code,
                    'short_url': short_url,
                    'is_favorite': is_favorite
                })
                success_count += 1
            else:
                results.append({
                    'url': original_url,
                    'success': False,
                    'error': 'URL 저장 중 오류가 발생했습니다.'
                })
        
        return jsonify({
            'success': True,
            'total_urls': len(urls),
            'success_count': success_count,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'벌크 처리 중 오류가 발생했습니다: {str(e)}',
            'error_code': 'INTERNAL_ERROR'
        }), 500

# URL 단축 API/폼 엔드포인트 (1-3, 1-5단계)
@app.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    """URL을 단축하는 API/폼 엔드포인트 (1-9단계 보안 강화, 2-6단계: 로그인 필요)"""
    
    # Rate limiting 체크 (1-9단계)
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()  # 프록시 환경에서 실제 IP 추출
    else:
        client_ip = request.remote_addr
    
    rate_ok, rate_error = check_rate_limit(client_ip)
    if not rate_ok:
        logging.warning(f"Rate limit exceeded for IP: {client_ip}")
        if request.is_json:
            return jsonify({
                'success': False,
                'error': rate_error,
                'error_code': 'RATE_LIMIT_EXCEEDED'
            }), 429
        else:
            return redirect(f'/?error={rate_error}')
    
    try:
        # 요청 데이터 가져오기
        if request.is_json:
            # JSON API 요청
            data = request.get_json()
            original_url = data.get('original_url', '').strip() if data else ''
            is_form_request = False
        else:
            # 폼 데이터 요청
            original_url = request.form.get('original_url', '').strip()
            custom_code = request.form.get('custom_code', '').strip()
            expires_at = request.form.get('expires_at', '').strip()
            tags = request.form.get('tags', '').strip()
            is_favorite = request.form.get('is_favorite', '') == 'on'
            is_form_request = True
        
        # original_url이 없으면 에러
        if not original_url:
            if is_form_request:
                # 폼 요청의 경우 메인 페이지로 리다이렉트
                return redirect('/?error=URL을 입력해주세요')
            else:
                # JSON API 요청의 경우 JSON 에러 응답
                return jsonify({
                    'success': False,
                    'error': 'original_url is required',
                    'error_code': 'MISSING_URL'
                }), 400
        
        # 로깅: 요청 기록 (1-9단계)
        logging.info(f"URL shortening request from {client_ip}: {original_url[:100]}...")
        
        # URL 단축 서비스 호출 (user_id 포함)
        user_id = session.get('user_id') if session.get('logged_in') else None

        # (2-7단계) 무료 사용자 월 한도 체크
        if user_id:
            allowed, msg, used, limit_total = can_create_url(user_id)
            if not allowed:
                if is_form_request:
                    return redirect(f"/?error={msg}")
                else:
                    return jsonify({'success': False, 'error': msg, 'error_code': 'PLAN_LIMIT_REACHED'}), 403
        # 프리미엄 사용자만 커스텀 코드 허용
        custom_for_service = None
        if custom_code:
            conn = get_db_connection()
            try:
                user = conn.execute('SELECT user_type FROM users WHERE id = ? LIMIT 1', (user_id,)).fetchone()
                if user and user['user_type'] in ('premium','admin'):
                    custom_for_service = custom_code
                else:
                    # 무료 사용자는 안내 메시지
                    return redirect('/pricing?message=커스텀 URL은 프리미엄 전용 기능입니다.')
            finally:
                conn.close()

        # 만료일 처리
        expires_at_datetime = None
        if expires_at and expires_at != 'never':
            if expires_at == '1day':
                expires_at_datetime = datetime.datetime.now() + datetime.timedelta(days=1)
            elif expires_at == '7days':
                expires_at_datetime = datetime.datetime.now() + datetime.timedelta(days=7)
            elif expires_at == '30days':
                expires_at_datetime = datetime.datetime.now() + datetime.timedelta(days=30)
        
        result = shorten_url_service(original_url, user_id, custom_for_service, expires_at_datetime, tags, is_favorite)
        
        if is_form_request:
            # 폼 요청의 경우 결과 페이지로 리다이렉트
            if result['success']:
                return redirect(url_for('result_page', 
                    original_url=result['original_url'],
                    short_code=result['short_code'],
                    short_url=result['short_url'],
                    message=result['message'],
                    is_existing=str(result.get('is_existing', False)).lower()
                ))
            else:
                # 에러 발생시 메인 페이지로 돌아가기
                error_message = result.get('error', '알 수 없는 오류가 발생했습니다')
                return redirect(f'/?error={error_message}')
        else:
            # JSON API 요청의 경우 JSON 응답
            status_code = 200 if result['success'] else 400
            return jsonify(result), status_code
        
    except Exception as e:
        print(f"❌ /shorten 엔드포인트 오류: {e}")
        
        if request.is_json:
            return jsonify({
                'success': False,
                'error': 'Internal server error',
                'error_code': 'INTERNAL_ERROR'
            }), 500
        else:
            return redirect('/?error=서버 오류가 발생했습니다')

# =====================================
# 사용자 인증 라우트 (2-2단계, 2-3단계)
# =====================================

# 회원가입 페이지 (2-2단계)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """회원가입 페이지 (GET: 폼 표시, POST: 회원가입 처리)"""
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        print(f"🔍 회원가입 요청: username={username}, email={email}")
        
        # 입력 검증
        if not username or not email or not password:
            error_msg = "모든 필드를 입력해주세요."
            print(f"❌ 검증 실패: {error_msg}")
            return render_template_string(SIGNUP_HTML, error=error_msg)
        
        if len(username) < 3 or len(username) > 20:
            error_msg = "사용자명은 3-20자 사이여야 합니다."
            print(f"❌ 검증 실패: {error_msg}")
            return render_template_string(SIGNUP_HTML, error=error_msg)
        
        if len(password) < 6:
            error_msg = "비밀번호는 최소 6자 이상이어야 합니다."
            print(f"❌ 검증 실패: {error_msg}")
            return render_template_string(SIGNUP_HTML, error=error_msg)
        
        if password != confirm_password:
            error_msg = "비밀번호가 일치하지 않습니다."
            print(f"❌ 검증 실패: {error_msg}")
            return render_template_string(SIGNUP_HTML, error=error_msg)
        
        print(f"✅ 검증 통과, 사용자 생성 시도...")
        
        # 사용자 생성
        success, message = create_user(username, email, password)
        
        if success:
            print(f"✅ 사용자 생성 성공: {username}")
            return redirect('/login?message=회원가입이 완료되었습니다. 로그인해주세요.')
        else:
            print(f"❌ 사용자 생성 실패: {message}")
            return render_template_string(SIGNUP_HTML, error=message)
    
    print("📝 회원가입 폼 표시 (GET 요청)")
    return render_template_string(SIGNUP_HTML)

# 로그인 페이지 (2-3단계)
@app.route('/login', methods=['GET', 'POST'])
def login():
    """로그인 페이지 (GET: 폼 표시, POST: 로그인 처리)"""
    
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')
        
        # 입력 검증
        if not username_or_email or not password:
            return render_template_string(LOGIN_HTML, error="사용자명/이메일과 비밀번호를 입력해주세요.")
        
        # 세션에 사용자 정보 저장
        success, user = verify_user_credentials(username_or_email, password)
        
        if success:
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            
            return redirect('/?message=로그인되었습니다.')
        else:
            return render_template_string(LOGIN_HTML, error="사용자명/이메일 또는 비밀번호가 올바르지 않습니다.")
    
    # GET 요청시 메시지 표시
    message = request.args.get('message', '')
    return render_template_string(LOGIN_HTML, message=message)

# 로그아웃 (2-3단계)
@app.route('/logout')
def logout():
    """로그아웃 처리"""
    session.clear()
    return redirect('/?message=로그아웃되었습니다.')

# =====================================
# 개인 대시보드 및 URL 관리 (2-5단계)
# =====================================

# 개인 대시보드 (로그인 필요)
@app.route('/dashboard')
@login_required
def dashboard():
    """사용자 개인 대시보드 페이지"""
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/login?message=로그인이 필요합니다.')
    
    # 디버깅을 위한 로그 추가
    print(f"🔍 대시보드 접근: 사용자 ID {current_user['id']}, 사용자명 {current_user['username']}")
    
    # 사용자의 URL 목록 조회
    user_urls = get_user_urls(current_user['id'])
    print(f"📊 조회된 URL 개수: {len(user_urls)}")
    
    # URL 목록 HTML 생성
    if user_urls:
        url_list_html = ''.join([f'''
        <div class="url-list">
            <div class="url-item" style="{'border-left: 4px solid #ffc107; background-color: #fff3cd;' if url['expires_at'] and (datetime.datetime.fromisoformat(url['expires_at']) - datetime.datetime.now()).days <= 3 else ''}">
                <div class="url-info">
                    <div class="url-title">
                        <a href="{url['original_url']}" target="_blank" style="color: #007bff; text-decoration: none;">
                            {url['original_url'][:50]}{'...' if len(url['original_url']) > 50 else ''}
                        </a>
                    </div>
                    <div class="url-details">
                        단축 코드: <span class="short-code">{url['short_code']}</span> | 
                        생성일: {url['created_at'][:16].replace('T', ' ')} | 
                        클릭 수: {url['click_count']} | 
                        만료일: {url['expires_at'][:16].replace('T', ' ') if url['expires_at'] else '무기한'} | 
                        태그: {url['tags'] if url['tags'] else '없음'} | 
                        상태: <span style="color: {'#dc3545' if url['expires_at'] and datetime.datetime.fromisoformat(url['expires_at']) < datetime.datetime.now() else '#28a745' if url['expires_at'] and (datetime.datetime.fromisoformat(url['expires_at']) - datetime.datetime.now()).days <= 3 else '#6c757d'}">{'만료됨' if url['expires_at'] and datetime.datetime.fromisoformat(url['expires_at']) < datetime.datetime.now() else '만료 임박' if url['expires_at'] and (datetime.datetime.fromisoformat(url['expires_at']) - datetime.datetime.now()).days <= 3 else '활성'}</span>
                    </div>
                </div>
                <div class="url-actions">
                    <a href="/{url['short_code']}" target="_blank" class="btn btn-primary">🔗 테스트</a>
                    <a href="/stats/{url['short_code']}" class="btn btn-info">📈 통계</a>
                    <a href="/analytics/{url['short_code']}" class="btn btn-info">🔬 상세 분석</a>
                    <a href="/qr/{url['short_code']}" class="btn btn-success">📱 QR 코드</a>
                    <button onclick="toggleFavorite({url['id']}, this)" class="btn {'btn-warning' if url['is_favorite'] else 'btn-secondary'}" style="{'background: #ffc107; color: #000;' if url['is_favorite'] else 'background: #6c757d; color: white;'}">
                        {'⭐ 즐겨찾기 해제' if url['is_favorite'] else '☆ 즐겨찾기'}
                    </button>
                    <button onclick="deleteUrl({url['id']}, '{url['short_code']}')" class="btn btn-danger">🗑️ 삭제</button>
                </div>
            </div>
        </div>
        ''' for url in user_urls])
    else:
        url_list_html = '''
        <div class="empty-state">
            <div style="font-size: 4rem; margin-bottom: 20px;">📭</div>
            <h3>아직 생성된 단축 URL이 없습니다</h3>
            <p>첫 번째 URL을 단축해보세요!</p>
        </div>
        '''
    
    # 통계 계산
    total_urls = len(user_urls)
    total_clicks = sum(url['click_count'] for url in user_urls) if user_urls else 0
    active_urls = len([url for url in user_urls if url['click_count'] > 0]) if user_urls else 0
    
    # 가입일 안전하게 설정 (4-4단계 수정)
    try:
        if current_user.get('created_at'):
            created_at = current_user['created_at'][:10] if isinstance(current_user['created_at'], str) else 'N/A'
        else:
            created_at = 'N/A'
    except:
        created_at = 'N/A'
    # (2-7단계) 이번 달 사용량
    used_this_month = count_user_urls_this_month(current_user['id'])
    limit_total, is_unlimited = get_user_limit_info(current_user)
    usage_text = (f"이번 달 {used_this_month}/{limit_total}개 사용 중" if not is_unlimited else "프리미엄(무제한)")
    
    print(f"📈 통계: 총 URL {total_urls}, 총 클릭 {total_clicks}, 활성 URL {active_urls}, 가입일 {created_at}")
    
    # 프리미엄 사용자 확인 (4-4단계)
    is_premium = current_user['user_type'] in ('premium', 'admin')
    
    # 벌크 단축 버튼 HTML 생성
    bulk_button = '''
                    <button onclick="showBulkShorten()" class="btn btn-primary" style="border: none; padding: 8px 16px; border-radius: 8px; background: #007bff; color: white; font-size: 0.9rem; cursor: pointer;">
                        🚀 벌크 단축
                    </button>
                    ''' if is_premium else ''
    
    # HTML 템플릿에 변수 전달
    dashboard_html = DASHBOARD_HTML.format(
        username=current_user['username'],
        created_at=created_at,
        total_urls=total_urls,
        total_clicks=total_clicks,
        active_urls=active_urls,
        url_list=url_list_html,
        usage_text=usage_text,
        bulk_button=bulk_button
    )
    
    return dashboard_html

# URL 즐겨찾기 토글 API (4-4단계)
@app.route('/toggle-favorite/<int:url_id>', methods=['POST'])
@login_required
def toggle_favorite(url_id):
    """URL 즐겨찾기 상태를 토글하는 API"""
    
    current_user = get_current_user()
    if not current_user:
        return jsonify({'success': False, 'error': '로그인이 필요합니다.'}), 401
    
    conn = get_db_connection()
    try:
        # URL이 해당 사용자 소유인지 확인
        url = conn.execute('''
            SELECT id, is_favorite 
            FROM urls 
            WHERE id = ? AND user_id = ? 
            LIMIT 1
        ''', (url_id, current_user['id'])).fetchone()
        
        if not url:
            return jsonify({'success': False, 'error': '해당 URL을 찾을 수 없거나 권한이 없습니다.'}), 404
        
        # 즐겨찾기 상태 토글
        new_favorite_status = 0 if url['is_favorite'] else 1
        conn.execute('UPDATE urls SET is_favorite = ? WHERE id = ?', (new_favorite_status, url_id))
        conn.commit()
        
        return jsonify({
            'success': True,
            'is_favorite': bool(new_favorite_status),
            'message': '즐겨찾기로 설정되었습니다.' if new_favorite_status else '즐겨찾기가 해제되었습니다.'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'즐겨찾기 변경 중 오류가 발생했습니다: {str(e)}'}), 500
    finally:
        conn.close()

# URL 삭제 API (사용자 소유 URL만)
@app.route('/delete-url/<int:url_id>', methods=['POST'])
@login_required
def delete_user_url(url_id):
    """사용자가 소유한 URL을 삭제하는 API"""
    
    current_user = get_current_user()
    if not current_user:
        return jsonify({'success': False, 'error': '로그인이 필요합니다.'}), 401
    
    success, message = delete_url_by_user(url_id, current_user['id'])
    
    return jsonify({
        'success': success,
        'message' if success else 'error': message,
        'url_id': url_id
    }), 200 if success else 400

# CSV 내보내기 API (4-4단계)
@app.route('/export-csv')
@login_required
def export_csv():
    """사용자의 URL 목록을 CSV로 내보내기"""
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/login?message=로그인이 필요합니다.')
    
    conn = get_db_connection()
    try:
        urls = conn.execute('''
            SELECT original_url, short_code, created_at, click_count, expires_at, tags, is_favorite
            FROM urls 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (current_user['id'],)).fetchall()
        
        # CSV 데이터 생성
        csv_data = "원본 URL,단축 코드,생성일,클릭 수,만료일,태그,즐겨찾기\n"
        
        for url in urls:
            original_url = url['original_url'].replace('"', '""')  # CSV 이스케이프
            short_code = url['short_code']
            created_at = url['created_at'][:19].replace('T', ' ') if url['created_at'] else ''
            click_count = str(url['click_count'])
            expires_at = url['expires_at'][:19].replace('T', ' ') if url['expires_at'] else '무기한'
            tags = url['tags'] if url['tags'] else ''
            is_favorite = '⭐' if url['is_favorite'] else ''
            
            csv_data += f'"{original_url}","{short_code}","{created_at}",{click_count},"{expires_at}","{tags}","{is_favorite}"\n'
        
        # CSV 파일 응답
        response = Response(csv_data, mimetype='text/csv; charset=utf-8')
        response.headers['Content-Disposition'] = f'attachment; filename="cutlet_urls_{current_user["username"]}_{datetime.datetime.now().strftime("%Y%m%d")}.csv"'
        
        return response
        
    except Exception as e:
        print(f"❌ CSV 내보내기 오류: {e}")
        return redirect('/dashboard?error=CSV 내보내기 중 오류가 발생했습니다.')
    finally:
        conn.close()

# =====================================
# 프로필 관리 (2-6단계)
# =====================================

# 프로필 페이지 (로그인 필요)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """사용자 프로필 관리 페이지"""
    
    current_user = get_current_user()
    if not current_user:
        return redirect('/login?message=로그인이 필요합니다.')
    
    if request.method == 'POST':
        action = request.form.get('action', '')
        
        if action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # 현재 비밀번호 확인
            success, user = verify_user_credentials(current_user['username'], current_password)
            if not success:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error_message}', '<div class="error-message">⚠️ 현재 비밀번호가 올바르지 않습니다.</div>')
            
            # 새 비밀번호 검증
            if len(new_password) < 6:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error_message}', '<div class="error-message">⚠️ 새 비밀번호는 최소 6자 이상이어야 합니다.</div>')
            
            if new_password != confirm_password:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error_message}', '<div class="error-message">⚠️ 새 비밀번호가 일치하지 않습니다.</div>')
            
            # 비밀번호 변경
            success, message = update_user_password(current_user['id'], new_password)
            if success:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{success_message}', f'<div class="success-message">✅ {message}</div>')
            else:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error}', message)
        
        elif action == 'delete_account':
            confirm_password = request.form.get('confirm_password', '')
        elif action == 'change_email':
            new_email = request.form.get('new_email', '').strip()
            if not new_email or '@' not in new_email or '.' not in new_email:
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error_message}', '<div class="error-message">⚠️ 올바른 이메일을 입력해주세요.</div>')
            # 이메일 중복 체크 및 업데이트
            conn = get_db_connection()
            try:
                exists = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', (new_email, current_user['id'])).fetchone()
                if exists:
                    profile_html = PROFILE_HTML.format(
                        username=current_user['username'],
                        email=current_user['email'],
                        created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                    )
                    return profile_html.replace('{error_message}', '<div class="error-message">⚠️ 이미 사용 중인 이메일입니다.</div>')
                conn.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, current_user['id']))
                conn.commit()
                session['email'] = new_email
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=new_email,
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{success_message}', '<div class="success-message">✅ 이메일이 변경되었습니다.</div>')
            finally:
                conn.close()
        elif action == 'deactivate_account':
            # 계정 비활성화 (로그인 불가)
            conn = get_db_connection()
            try:
                conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (current_user['id'],))
                conn.commit()
            finally:
                conn.close()
            session.clear()
            return redirect('/?message=계정이 비활성화되었습니다.')
            
            # 비밀번호 확인
            success, user = verify_user_credentials(current_user['username'], confirm_password)
            if not success:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error_message}', '<div class="error-message">⚠️ 비밀번호가 올바르지 않습니다.</div>')
            
            # 계정 삭제
            success, message = delete_user_account(current_user['id'])
            if success:
                session.clear()
                return redirect('/?message=계정이 삭제되었습니다.')
            else:
                # HTML 템플릿에 변수 전달
                profile_html = PROFILE_HTML.format(
                    username=current_user['username'],
                    email=current_user['email'],
                    created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A'
                )
                return profile_html.replace('{error}', message)
    
    # HTML 템플릿에 변수 전달
    profile_html = PROFILE_HTML.format(
        username=current_user['username'],
        email=current_user['email'],
        created_at=current_user['created_at'][:16].replace('T', ' ') if current_user['created_at'] else 'N/A',
        success_message='',
        error_message=''
    )
    
    return profile_html

# =====================================
# 관리자 페이지 및 통계 기능 (1-7단계)
# =====================================

# 관리자 메인 페이지
@app.route('/admin')
def admin_page():
    """관리자 페이지 - 모든 단축 URL 목록 및 통계"""
    
    try:
        # 전체 통계 조회
        total_stats = get_total_statistics()
        
        # 모든 URL과 통계 조회
        urls_with_stats = get_all_urls_with_stats()
        
        return '''
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>관리자 페이지 - Cutlet URL 단축 서비스</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    min-height: 100vh;
                    padding: 20px;
                }
                
                .container {
                    max-width: 1400px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                
                .header {
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }
                
                .header h1 {
                    font-size: 2.5rem;
                    margin-bottom: 10px;
                }
                
                .header p {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }
                
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    padding: 30px;
                    background: #f8f9fa;
                }
                
                .stat-card {
                    background: white;
                    padding: 25px;
                    border-radius: 15px;
                    text-align: center;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    border-left: 4px solid #D2691E;
                }
                
                .stat-number {
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: #D2691E;
                    margin-bottom: 5px;
                }
                
                .stat-label {
                    font-size: 0.9rem;
                    color: #666;
                    font-weight: 500;
                }
                
                .content {
                    padding: 30px;
                }
                
                .section-title {
                    font-size: 1.5rem;
                    color: #333;
                    margin-bottom: 20px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                
                .table-container {
                    overflow-x: auto;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                
                table {
                    width: 100%;
                    border-collapse: collapse;
                    background: white;
                }
                
                th {
                    background: #D2691E;
                    color: white;
                    padding: 15px 10px;
                    text-align: left;
                    font-weight: 600;
                    font-size: 0.9rem;
                }
                
                td {
                    padding: 12px 10px;
                    border-bottom: 1px solid #eee;
                    vertical-align: middle;
                }
                
                tr:hover {
                    background: #f8f9fa;
                }
                
                .url-cell {
                    max-width: 300px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                }
                
                .short-code {
                    font-family: monospace;
                    background: #e9ecef;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: bold;
                    color: #495057;
                }
                
                .click-count {
                    font-weight: bold;
                    color: #28a745;
                    text-align: center;
                }
                
                .btn {
                    padding: 6px 12px;
                    border: none;
                    border-radius: 5px;
                    text-decoration: none;
                    font-size: 0.8rem;
                    font-weight: 500;
                    cursor: pointer;
                    margin: 2px;
                    display: inline-block;
                    transition: all 0.3s ease;
                }
                
                .btn-primary {
                    background: #007bff;
                    color: white;
                }
                
                .btn-primary:hover {
                    background: #0056b3;
                }
                
                .btn-danger {
                    background: #dc3545;
                    color: white;
                }
                
                .btn-danger:hover {
                    background: #c82333;
                }
                
                .btn-info {
                    background: #17a2b8;
                    color: white;
                }
                
                .btn-info:hover {
                    background: #138496;
                }
                
                .actions {
                    text-align: center;
                    white-space: nowrap;
                }
                
                .empty-state {
                    text-align: center;
                    padding: 60px 20px;
                    color: #666;
                }
                
                .empty-state i {
                    font-size: 4rem;
                    margin-bottom: 20px;
                    opacity: 0.5;
                }
                
                .navigation {
                    padding: 20px 30px;
                    border-top: 1px solid #eee;
                    text-align: center;
                }
                
                .nav-btn {
                    padding: 12px 25px;
                    margin: 0 10px;
                    border-radius: 10px;
                    text-decoration: none;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                
                .nav-btn.primary {
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    color: white;
                }
                
                .nav-btn.secondary {
                    background: #f8f9fa;
                    color: #D2691E;
                    border: 2px solid #D2691E;
                }
                
                .nav-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                
                @media (max-width: 768px) {
                    .stats-grid {
                        grid-template-columns: repeat(2, 1fr);
                        gap: 15px;
                        padding: 20px;
                    }
                    
                    .stat-card {
                        padding: 20px;
                    }
                    
                    .stat-number {
                        font-size: 2rem;
                    }
                    
                    .content {
                        padding: 20px;
                    }
                    
                    th, td {
                        padding: 8px;
                        font-size: 0.8rem;
                    }
                    
                    .url-cell {
                        max-width: 150px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🥩 Cutlet 관리자</h1>
                    <p>Cut your links, serve them fresh - 통계 및 관리</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">''' + str(total_stats['total_urls']) + '''</div>
                        <div class="stat-label">총 단축 URL</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">''' + str(total_stats['total_clicks']) + '''</div>
                        <div class="stat-label">총 클릭 수</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">''' + str(total_stats['avg_clicks_per_url']) + '''</div>
                        <div class="stat-label">평균 클릭/URL</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">''' + str(total_stats['total_space_saved']) + '''</div>
                        <div class="stat-label">절약된 문자 수</div>
                    </div>
                </div>
                
                <div class="content">
                    <h2 class="section-title">
                        📊 URL 목록 및 통계
                        <span style="font-size: 0.8rem; color: #666; font-weight: normal;">(클릭 수 기준 정렬)</span>
                    </h2>
                    
                    ''' + (''.join([f'''
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>단축 코드</th>
                                    <th>원본 URL</th>
                                    <th>클릭 수</th>
                                    <th>생성일</th>
                                    <th>공간 절약</th>
                                    <th>작업</th>
                                </tr>
                            </thead>
                            <tbody>
                    '''] + [f'''
                                <tr>
                                    <td><span class="short-code">{url['short_code']}</span></td>
                                    <td class="url-cell" title="{url['original_url']}">{url['original_url']}</td>
                                    <td class="click-count">{url['click_count']}</td>
                                    <td>{url['created_at'][:16].replace('T', ' ')}</td>
                                    <td>{url['space_saved_percent']}%</td>
                                    <td class="actions">
                                        <a href="/stats/{url['short_code']}" class="btn btn-info">📈 통계</a>
                                        <a href="/{url['short_code']}" target="_blank" class="btn btn-primary">🔗 테스트</a>
                                        <button onclick="deleteUrl('{url['short_code']}')" class="btn btn-danger">🗑️ 삭제</button>
                                    </td>
                                </tr>
                    ''' for url in urls_with_stats] + ['''
                            </tbody>
                        </table>
                    </div>
                    ''']) if urls_with_stats else '''
                    <div class="empty-state">
                        <div style="font-size: 4rem; margin-bottom: 20px;">📭</div>
                        <h3>아직 생성된 단축 URL이 없습니다</h3>
                        <p>첫 번째 URL을 단축해보세요!</p>
                    </div>
                    ''') + '''
                </div>
                
                <div class="navigation">
                    <a href="/" class="nav-btn primary">🔗 URL 단축하기</a>
                    <a href="/test" class="nav-btn secondary">🧪 테스트 페이지</a>
                </div>
            </div>
            
            <script>
                function deleteUrl(shortCode) {
                    if (confirm('정말로 이 단축 URL을 삭제하시겠습니까?\\n\\n단축 코드: ' + shortCode + '\\n\\n⚠️ 이 작업은 되돌릴 수 없습니다.')) {
                        fetch('/delete/' + shortCode, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            }
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                alert('✅ ' + data.message);
                                location.reload(); // 페이지 새로고침
                            } else {
                                alert('❌ ' + data.error);
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            alert('❌ 삭제 중 오류가 발생했습니다.');
                        });
                    }
                }
                
                // 테이블 행 클릭시 통계 페이지로 이동
                document.querySelectorAll('tbody tr').forEach(row => {
                    row.addEventListener('click', function(e) {
                        // 버튼 클릭이 아닌 경우에만 통계 페이지로 이동
                        if (!e.target.classList.contains('btn') && e.target.tagName !== 'BUTTON') {
                            const shortCode = this.querySelector('.short-code').textContent;
                            window.location.href = '/stats/' + shortCode;
                        }
                    });
                    
                    row.style.cursor = 'pointer';
                });
            </script>
        </body>
        </html>
        '''
        
    except Exception as e:
        print(f"❌ 관리자 페이지 오류: {e}")
        return f'''
        <h1>관리자 페이지 오류</h1>
        <p>오류가 발생했습니다: {str(e)}</p>
        <a href="/">메인 페이지로 돌아가기</a>
        '''

# =====================================
# 3-1단계: 가격 정책/업그레이드 안내
# =====================================

@app.route('/pricing')
def pricing_page():
    """요금제 소개 페이지 (UI만)"""
    return '''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>요금제 - Cutlet</title>
        <style>
            * { box-sizing: border-box; margin:0; padding:0; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%); min-height:100vh; padding: 30px; }
            .container { max-width: 1100px; margin: 0 auto; background:#fff; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow:hidden; }
            .header { background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%); color:#fff; padding: 30px; text-align: center; }
            .header h1 { font-size: 2.2rem; margin-bottom: 8px; }
            .header p { opacity: .9; }
            .content { padding: 30px; }
            .plans { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:20px; margin-top: 10px; }
            .card { border:1px solid #eee; border-radius: 16px; padding: 24px; box-shadow: 0 10px 24px rgba(0,0,0,.06); }
            .card h2 { font-size: 1.5rem; margin-bottom: 8px; }
            .price { font-size: 2rem; font-weight:700; color:#D2691E; margin: 12px 0 16px; }
            ul { list-style: none; }
            li { margin: 8px 0; color:#555; }
            .check { color:#228B22; margin-right:6px; }
            .x { color:#dc3545; margin-right:6px; }
            .btn { display:inline-block; margin-top:14px; padding: 12px 20px; border-radius:10px; text-decoration:none; font-weight:600; }
            .btn-primary { background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%); color:#fff; }
            .btn-secondary { background:#f8f9fa; color:#D2691E; border:2px solid #D2691E; }
            .compare { margin-top: 30px; overflow-x:auto; }
            table { width:100%; border-collapse: collapse; }
            th, td { border:1px solid #eee; padding: 14px; text-align:center; }
            th { background:#fafafa; }
            .footer { padding: 20px 30px; text-align:center; border-top:1px solid #eee; }
            .links a { color:#D2691E; text-decoration:none; margin:0 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>요금제</h1>
                <p>필요에 맞게 선택하세요. 무료로 시작하고, 성장하면 프리미엄으로 업그레이드하세요.</p>
            </div>
            <div class="content">
                <div class="plans">
                    <div class="card">
                        <h2>무료</h2>
                        <div class="price">$0 / 월</div>
                        <ul>
                            <li><span class="check">✓</span> 월 10개 URL</li>
                            <li><span class="check">✓</span> 기본 통계</li>
                            <li><span class="x">✗</span> 상세 분석</li>
                            <li><span class="x">✗</span> 커스텀 URL</li>
                            <li><span class="x">✗</span> 우선 지원</li>
                        </ul>
                        <a href="/signup" class="btn btn-secondary">무료로 시작</a>
                    </div>
                    <div class="card">
                        <h2>프리미엄</h2>
                        <div class="price">$4.99 / 월</div>
                        <ul>
                            <li><span class="check">✓</span> 무제한 URL</li>
                            <li><span class="check">✓</span> 상세 분석</li>
                            <li><span class="check">✓</span> 커스텀 URL</li>
                            <li><span class="check">✓</span> 우선 지원</li>
                        </ul>
                        <a href="/upgrade" class="btn btn-primary">프리미엄 업그레이드</a>
                    </div>
                </div>

                <div class="compare">
                    <h2 style="text-align:center; margin: 30px 0 15px;">무료 vs 프리미엄 비교</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>기능</th>
                                <th>무료</th>
                                <th>프리미엄</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td>월 단축 가능량</td><td>10</td><td>무제한</td></tr>
                            <tr><td>기본 통계</td><td>제공</td><td>제공</td></tr>
                            <tr><td>상세 분석</td><td>미제공</td><td>제공</td></tr>
                            <tr><td>커스텀 URL</td><td>미제공</td><td>제공</td></tr>
                            <tr><td>우선 고객 지원</td><td>미제공</td><td>제공</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="footer">
                <div class="links">
                    <a href="/">메인</a>
                    <a href="/dashboard">대시보드</a>
                    <a href="/profile">프로필</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/upgrade')
@login_required
def upgrade_prepare():
    """업그레이드 안내(결제 준비) 페이지 - UI만, 실제 결제 없음"""
    current_user = get_current_user()
    username = current_user['username'] if current_user else '사용자'
    return f'''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>업그레이드 준비 - Cutlet</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; padding: 30px; }}
            .wrap {{ max-width: 720px; margin: 0 auto; background:#fff; border-radius: 16px; border:1px solid #eee; box-shadow: 0 10px 24px rgba(0,0,0,.06); padding: 30px; }}
            .title {{ font-size: 1.8rem; margin-bottom: 10px; color:#333; }}
            .desc {{ color:#666; margin-bottom: 20px; }}
            .note {{ background:#fff8f0; border:1px solid #ffe0c2; color:#8a5a00; padding:12px 14px; border-radius:10px; margin-bottom:16px; }}
            .actions a {{ display:inline-block; margin-right:10px; padding: 12px 20px; border-radius:10px; text-decoration:none; font-weight:600; }}
            .primary {{ background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%); color:#fff; }}
            .secondary {{ background:#f8f9fa; color:#D2691E; border:2px solid #D2691E; }}
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="title">프리미엄 업그레이드 준비</div>
            <div class="desc">{username}님, 프리미엄은 무제한 URL, 상세 분석, 커스텀 URL을 제공합니다. 월 구독료는 $4.99 입니다.</div>
            <div class="note">지금은 결제 연동 준비 단계입니다. 실제 결제는 아직 제공되지 않으며, 이후 결제 수단 연결(Stripe 등) 후 진행됩니다.</div>
            <div class="actions">
                <a href="/pricing" class="secondary">요금제 보기</a>
                <a href="/dashboard" class="primary">대시보드로 돌아가기</a>
            </div>
        </div>
    </body>
    </html>
    '''

# =====================================
# 3-2단계: 프리미엄 전용 상세 분석 페이지
# =====================================

def premium_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect('/login?message=로그인이 필요합니다.')
        if user['user_type'] not in ('premium', 'admin'):
            return redirect('/pricing?message=프리미엄 전용 기능입니다. 업그레이드 해주세요.')
        return f(*args, **kwargs)
    return wrapper

def get_click_aggregations(short_code):
    conn = get_db_connection()
    try:
        daily = conn.execute('''
            SELECT strftime('%Y-%m-%d', created_at) as d, COUNT(*) c
            FROM click_events WHERE short_code = ?
            GROUP BY d ORDER BY d DESC LIMIT 30
        ''', (short_code,)).fetchall()
        hourly = conn.execute('''
            SELECT strftime('%H', created_at) as h, COUNT(*) c
            FROM click_events WHERE short_code = ?
            GROUP BY h ORDER BY h
        ''', (short_code,)).fetchall()
        geo = conn.execute('''
            SELECT COALESCE(ip, 'unknown') as g, COUNT(*) c
            FROM click_events WHERE short_code = ?
            GROUP BY g ORDER BY c DESC LIMIT 10
        ''', (short_code,)).fetchall()
        device = conn.execute('''
            SELECT COALESCE(device,'Other') d, COUNT(*) c
            FROM click_events WHERE short_code = ?
            GROUP BY d ORDER BY c DESC
        ''', (short_code,)).fetchall()
        browser = conn.execute('''
            SELECT COALESCE(browser,'Other') b, COUNT(*) c
            FROM click_events WHERE short_code = ?
            GROUP BY b ORDER BY c DESC
        ''', (short_code,)).fetchall()
        ref = conn.execute('''
            SELECT COALESCE(referrer,'Direct') r, COUNT(*) c
            FROM click_events WHERE short_code = ?
            GROUP BY r ORDER BY c DESC LIMIT 10
        ''', (short_code,)).fetchall()
        return daily, hourly, geo, device, browser, ref
    finally:
        conn.close()

@app.route('/analytics/<short_code>')
@login_required
@premium_required
def analytics_page(short_code):
    url = get_url_by_short_code(short_code)
    if not url:
        return redirect('/404')
    daily, hourly, geo, device, browser, ref = get_click_aggregations(short_code)
    # 간단 차트: CSS 막대그래프(의존성 최소화)
    def bars(rows, max_width=300):
        total = max([r[1] for r in rows] + [1])
        items = []
        for label, count in rows:
            width = int(max_width * (count/total))
            items.append(f'<div style="display:flex;align-items:center;gap:10px;margin:6px 0;"><div style="width:120px;color:#555;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{label}</div><div style="background:#D2691E;height:12px;border-radius:8px;width:{width}px;"></div><div style="color:#333;min-width:30px;text-align:right;">{count}</div></div>')
        return ''.join(items)

    daily_html = bars([(row['d'], row['c']) for row in daily])
    hourly_html = bars([(row['h'] + '시', row['c']) for row in hourly])
    geo_html = bars([(row['g'], row['c']) for row in geo])
    device_html = bars([(row['d'], row['c']) for row in device])
    browser_html = bars([(row['b'], row['c']) for row in browser])
    ref_html = bars([(row['r'], row['c']) for row in ref])

    return f'''
    <!DOCTYPE html>
    <html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>상세 분석 - {short_code}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#f8f9fa; padding:24px; }}
        .wrap {{ max-width:1000px; margin:0 auto; }}
        .card {{ background:#fff; border:1px solid #eee; border-radius:16px; box-shadow:0 10px 24px rgba(0,0,0,.06); padding: 20px; margin-bottom:18px; }}
        h1 {{ color:#D2691E; margin-bottom:10px; }}
        h2 {{ font-size:1.2rem; margin: 6px 0 12px; color:#333; }}
        .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:18px; }}
        a.btn {{ display:inline-block; padding:10px 16px; border-radius:10px; text-decoration:none; font-weight:600; background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff; }}
        .meta {{ color:#666; margin-bottom:8px; }}
    </style></head>
    <body>
        <div class="wrap">
            <h1>🔬 상세 분석</h1>
            <div class="meta">단축 코드: <b>{short_code}</b> • 원본 URL: <a href="{url['original_url']}" target="_blank">{url['original_url']}</a></div>
            <div class="grid">
                <div class="card"><h2>📅 일별 클릭</h2>{daily_html or '<div>데이터 없음</div>'}</div>
                <div class="card"><h2>⏰ 시간대별 클릭</h2>{hourly_html or '<div>데이터 없음</div>'}</div>
                <div class="card"><h2>🌍 IP/지역(간이)</h2>{geo_html or '<div>데이터 없음</div>'}</div>
                <div class="card"><h2>🖥️ 디바이스</h2>{device_html or '<div>데이터 없음</div>'}</div>
                <div class="card"><h2>🧭 브라우저</h2>{browser_html or '<div>데이터 없음</div>'}</div>
                <div class="card"><h2>🔗 레퍼러</h2>{ref_html or '<div>데이터 없음</div>'}</div>
            </div>
            <div style="text-align:center;margin-top:12px;">
                <a class="btn" href="/dashboard">📊 대시보드로 돌아가기</a>
            </div>
        </div>
    </body></html>
    '''

# =====================================
# 3-4단계: 결제 시스템 기반 구축 (UI 및 시뮬레이션)
# =====================================

def ensure_subscription_row(user_id):
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT user_id FROM subscriptions WHERE user_id = ?', (user_id,)).fetchone()
        if not row:
            conn.execute('INSERT INTO subscriptions (user_id, plan, status, current_period_end) VALUES (?, "free", "active", NULL)', (user_id,))
            conn.commit()
    finally:
        conn.close()

@app.route('/checkout')
@login_required
def checkout_page():
    user = get_current_user()
    ensure_subscription_row(user['id'])
    return f'''
    <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>체크아웃 - Cutlet</title>
    <style>body {{font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;background:#f8f9fa;padding:24px;}} .wrap {{max-width:760px;margin:0 auto;background:#fff;border:1px solid #eee;border-radius:16px;box-shadow:0 10px 24px rgba(0,0,0,.06);padding:24px;}} .title {{font-size:1.8rem;margin-bottom:10px;color:#333}} .plan {{background:#fff8f0;border:1px solid #ffe0c2;color:#8a5a00;border-radius:10px;padding:12px 14px;margin-bottom:16px}} .btn {{display:inline-block;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:600;margin-right:10px}} .primary {{background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%);color:#fff}} .secondary {{background:#f8f9fa;color:#D2691E;border:2px solid #D2691E}}</style>
    </head><body>
        <div class="wrap">
            <div class="title">체크아웃</div>
            <div class="plan">프리미엄 요금제: <b>$4.99 / 월</b> • 무제한 URL, 상세 분석, 커스텀 URL</div>
            <p style="color:#666">지금은 결제 연동 준비 단계입니다. 아래 테스트 결제 버튼을 사용하면 프리미엄이 즉시 활성화됩니다.</p>
            <div style="margin-top:12px;">
                <a class="btn secondary" href="/pricing">요금제 보기</a>
                <a class="btn primary" href="/payment/test-charge">테스트 결제(프리미엄 활성화)</a>
            </div>
        </div>
    </body></html>
    '''

@app.route('/payment/test-charge')
@login_required
def payment_test_charge():
    user = get_current_user()
    # 결제 시뮬레이션: 결제 성공 처리 및 프리미엄 전환
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO payments (user_id, amount_cents, status, description) VALUES (?, ?, ?, ?)', (user['id'], 499, 'success', 'Test premium activation'))
        # 구독 갱신: 다음 결제일 +30일(간이)
        next_date = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
        ensure_subscription_row(user['id'])
        conn.execute('UPDATE subscriptions SET plan = "premium", status = "active", current_period_end = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?', (next_date, user['id']))
        conn.execute('UPDATE users SET user_type = "premium" WHERE id = ?', (user['id'],))
        conn.commit()
    finally:
        conn.close()
    return redirect('/payment/success')

@app.route('/payment/success')
@login_required
def payment_success():
    return '''
    <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>결제 성공</title>
    <style>body {font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#f8fff8; padding:24px;} .wrap {max-width:720px; margin:0 auto; background:#fff; border:1px solid #e6ffec; border-radius:16px; box-shadow:0 10px 24px rgba(0,0,0,.06); padding:24px;} .title {color:#228B22; font-size:1.6rem; margin-bottom:10px;} a.btn {display:inline-block; padding:10px 16px; border-radius:10px; text-decoration:none; font-weight:600; background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff;}</style></head>
    <body><div class="wrap"><div class="title">결제가 성공적으로 처리되었습니다</div><p>프리미엄이 활성화되었습니다. 무제한 URL, 상세 분석, 커스텀 URL을 이용하실 수 있습니다.</p><a href="/dashboard" class="btn">대시보드로 이동</a></div></body></html>
    '''

@app.route('/payment/cancel')
@login_required
def payment_cancel():
    return '''
    <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>결제 취소</title>
    <style>body {font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#fff8f8; padding:24px;} .wrap {max-width:720px; margin:0 auto; background:#fff; border:1px solid #ffe0e0; border-radius:16px; box-shadow:0 10px 24px rgba(0,0,0,.06); padding:24px;} .title {color:#c53030; font-size:1.6rem; margin-bottom:10px;} a.btn {display:inline-block; padding:10px 16px; border-radius:10px; text-decoration:none; font-weight:600; background:#f8f9fa; color:#D2691E; border:2px solid #D2691E;}</style></head>
    <body><div class="wrap"><div class="title">결제가 취소되었습니다</div><p>필요하실 때 언제든 다시 진행하실 수 있습니다.</p><a href="/pricing" class="btn">요금제 보기</a></div></body></html>
    '''

@app.route('/subscription')
@login_required
def subscription_page():
    user = get_current_user()
    conn = get_db_connection()
    try:
        sub = conn.execute('SELECT plan, status, current_period_end FROM subscriptions WHERE user_id = ? LIMIT 1', (user['id'],)).fetchone()
        last_payment = conn.execute('SELECT status, amount_cents, datetime(created_at) as t FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', (user['id'],)).fetchone()
    finally:
        conn.close()
    plan = (sub['plan'] if sub else 'free')
    status = (sub['status'] if sub else 'inactive')
    next_date = (sub['current_period_end'] if sub and sub['current_period_end'] else '—')
    last_txt = (f"최근 결제: {(last_payment['amount_cents']/100):.2f} USD, {last_payment['status']} ({last_payment['t']})" if last_payment else '최근 결제 없음')
    return f'''
    <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>구독 관리</title>
    <style>body {{font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#f8f9fa; padding:24px;}} .wrap {{max-width:820px; margin:0 auto;}} .card {{background:#fff; border:1px solid #eee; border-radius:16px; box-shadow:0 10px 24px rgba(0,0,0,.06); padding:20px; margin-bottom:16px;}} .btn {{display:inline-block; padding:10px 16px; border-radius:10px; text-decoration:none; font-weight:600;}} .primary {{background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff;}} .secondary {{background:#f8f9fa; color:#D2691E; border:2px solid #D2691E;}}</style></head>
    <body>
        <div class="wrap">
            <div class="card"><h2>현재 플랜</h2><p>플랜: <b>{plan}</b> • 상태: <b>{status}</b></p><p>다음 결제일: {next_date}</p></div>
            <div class="card"><h2>결제/구독 작업</h2>
                <a href="/checkout" class="btn primary">결제하기</a>
                <a href="/pricing" class="btn secondary">요금제 보기</a>
            </div>
            <div class="card"><h2>최근 결제 내역</h2><p>{last_txt}</p></div>
        </div>
    </body></html>
    '''

# =====================================
# 3-6단계: 수익 대시보드 (관리자 전용)
# =====================================

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect('/login?message=로그인이 필요합니다.')
        if user['user_type'] != 'admin':
            return redirect('/?error=관리자 전용 페이지입니다.')
        return f(*args, **kwargs)
    return wrapper

@app.route('/revenue')
@login_required
@admin_required
def revenue_dashboard():
    conn = get_db_connection()
    try:
        total_users = conn.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
        premium_users = conn.execute("SELECT COUNT(*) AS c FROM users WHERE user_type IN ('premium','admin')").fetchone()['c']
        ad_imps = conn.execute("SELECT COUNT(*) AS c FROM ad_impressions").fetchone()['c']
        ad_clicks = conn.execute("SELECT COUNT(*) AS c FROM ad_clicks").fetchone()['c']
        monthly = conn.execute('''
            SELECT strftime('%Y-%m', created_at) AS ym, COUNT(*) AS imps
            FROM ad_impressions
            GROUP BY ym ORDER BY ym DESC LIMIT 6
        ''').fetchall()
        est_revenue = (ad_imps/1000.0)*1.5 + ad_clicks*0.05
        p30 = conn.execute("SELECT COALESCE(SUM(amount_cents),0) AS s FROM payments WHERE status='success' AND created_at >= datetime('now','-30 day')").fetchone()['s'] or 0
        est_total = est_revenue + (p30/100.0)
    finally:
        conn.close()
    rows = ''.join([f"<tr><td>{r['ym']}</td><td>{r['imps']}</td><td>${(r['imps']/1000.0)*1.5:.2f}</td></tr>" for r in monthly])
    return f'''
    <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>수익 대시보드</title>
    <style>
        body {{ font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#f8f9fa; padding:24px; }}
        .wrap {{ max-width:1100px; margin:0 auto; }}
        .cards {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap:16px; margin-bottom:18px; }}
        .card {{ background:#fff; border:1px solid #eee; border-radius:16px; box-shadow:0 10px 24px rgba(0,0,0,.06); padding:20px; }}
        .num {{ font-size:1.8rem; color:#D2691E; font-weight:700; }}
        table {{ width:100%; border-collapse:collapse; background:#fff; border:1px solid #eee; border-radius:12px; overflow:hidden; }}
        th,td {{ border-bottom:1px solid #f1f1f1; padding:12px; text-align:center; }}
        th {{ background:#fafafa; }}
        .btn {{ display:inline-block; margin-top:12px; padding:10px 16px; border-radius:10px; text-decoration:none; font-weight:600; background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff; }}
    </style></head>
    <body>
        <div class="wrap">
            <h1>💰 수익 대시보드</h1>
            <div class="cards">
                <div class="card"><div>총 사용자 수</div><div class="num">{total_users}</div></div>
                <div class="card"><div>프리미엄 사용자</div><div class="num">{premium_users}</div></div>
                <div class="card"><div>광고 노출</div><div class="num">{ad_imps}</div></div>
                <div class="card"><div>광고 클릭</div><div class="num">{ad_clicks}</div></div>
                <div class="card"><div>최근 30일 총 예상 수익</div><div class="num">${est_total:.2f}</div><div style="color:#666;font-size:.9rem">(광고 추정 + 프리미엄 결제액)</div></div>
            </div>
            <h2>📅 월별 광고 노출 및 추정 수익</h2>
            <table>
                <thead><tr><th>월</th><th>노출수</th><th>추정 수익</th></tr></thead>
                <tbody>{rows or '<tr><td colspan="3">데이터 없음</td></tr>'}</tbody>
            </table>
            <div style="text-align:center;">
                <a class="btn" href="/admin">관리자 페이지로</a>
            </div>
        </div>
    </body></html>
    '''

# =====================================
# 4-1단계: QR 코드 생성 기능
# =====================================

def generate_qr_code(url, size=10, border=4):
    """QR 코드를 생성하고 base64 인코딩된 이미지를 반환합니다."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=size,
        border=border,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 이미지를 BytesIO에 저장
    img_buffer = BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    # base64로 인코딩
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    return img_base64

@app.route('/qr/<short_code>')
def qr_page(short_code):
    """QR 코드 표시 페이지"""
    conn = get_db_connection()
    try:
        url_data = conn.execute('SELECT * FROM urls WHERE short_code = ?', (short_code,)).fetchone()
        if not url_data:
            return redirect('/?error=존재하지 않는 단축 URL입니다.')
        
        full_url = f"http://{request.host}/{short_code}"
        qr_image = generate_qr_code(full_url)
        
        return f'''
        <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>QR 코드 - {short_code}</title>
        <style>
            body {{ font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%); min-height:100vh; padding:20px; display:flex; align-items:center; justify-content:center; }}
            .container {{ background:#fff; border-radius:20px; box-shadow:0 20px 40px rgba(0,0,0,0.1); padding:40px; max-width:500px; width:100%; text-align:center; }}
            .title {{ font-size:2rem; color:#D2691E; font-weight:bold; margin-bottom:20px; }}
            .qr-container {{ background:#f8f9fa; border-radius:15px; padding:30px; margin:20px 0; }}
            .qr-image {{ max-width:100%; height:auto; border-radius:10px; }}
            .url-info {{ background:#e9f7ef; border-radius:10px; padding:15px; margin:15px 0; word-break:break-all; }}
            .original-url {{ color:#666; font-size:0.9rem; margin-top:10px; }}
            .btn {{ display:inline-block; margin:10px 5px; padding:12px 20px; border-radius:10px; text-decoration:none; font-weight:600; transition:all 0.3s ease; }}
            .btn-primary {{ background:linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff; }}
            .btn-secondary {{ background:#6c757d; color:#fff; }}
            .btn:hover {{ transform:translateY(-2px); box-shadow:0 5px 15px rgba(0,0,0,0.2); }}
        </style></head>
        <body>
            <div class="container">
                <div class="title">📱 QR 코드</div>
                <div class="url-info">
                    <strong>단축 URL:</strong> {full_url}<br>
                    <div class="original-url">원본: {url_data['original_url']}</div>
                </div>
                <div class="qr-container">
                    <img src="data:image/png;base64,{qr_image}" alt="QR 코드" class="qr-image">
                </div>
                <div>
                    <a href="/qr/{short_code}/download" class="btn btn-primary">📥 PNG 다운로드</a>
                    <a href="/dashboard" class="btn btn-secondary">📊 대시보드로</a>
                    <a href="/" class="btn btn-secondary">🏠 메인으로</a>
                </div>
                <div style="margin-top:20px; color:#666; font-size:0.9rem;">
                    QR 코드를 스캔하면 단축 URL로 바로 이동합니다.
                </div>
            </div>
        </body></html>
        '''
    finally:
        conn.close()

@app.route('/qr/<short_code>/download')
def qr_download(short_code):
    """QR 코드 PNG 다운로드"""
    conn = get_db_connection()
    try:
        url_data = conn.execute('SELECT * FROM urls WHERE short_code = ?', (short_code,)).fetchone()
        if not url_data:
            return redirect('/?error=존재하지 않는 단축 URL입니다.')
        
        full_url = f"http://{request.host}/{short_code}"
        
        # QR 코드 생성 (다운로드용으로 더 큰 사이즈)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=15,  # 더 큰 사이즈
            border=4,
        )
        qr.add_data(full_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # BytesIO에 저장
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        # Response 생성
        return Response(
            img_buffer.getvalue(),
            mimetype='image/png',
            headers={'Content-Disposition': f'attachment; filename="qr_{short_code}.png"'}
        )
        
    finally:
        conn.close()

# 개별 URL 상세 통계 페이지
@app.route('/stats/<short_code>')
def stats_page(short_code):
    """개별 URL 상세 통계 페이지"""
    
    try:
        # 상세 통계 조회
        url_stats = get_url_detailed_stats(short_code)
        
        if not url_stats:
            return f'''
            <h1>통계를 찾을 수 없습니다</h1>
            <p>단축 코드 '{short_code}'에 대한 정보가 없습니다.</p>
            <a href="/admin">관리자 페이지로 돌아가기</a>
            ''', 404
        
        # 클릭 성능 계산
        avg_clicks_per_day = round(url_stats['click_count'] / max(url_stats['days_since_created'], 0.1), 1)
        
        # 성능 등급 계산
        if url_stats['click_count'] >= 10:
            performance_grade = "🔥 인기"
            performance_color = "#28a745"
        elif url_stats['click_count'] >= 5:
            performance_grade = "⭐ 보통"
            performance_color = "#ffc107"
        else:
            performance_grade = "📊 시작"
            performance_color = "#6c757d"
        
        return f'''
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>📈 {short_code} 통계 - Cutlet</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                
                .header {{
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                
                .header h1 {{
                    font-size: 2.5rem;
                    margin-bottom: 10px;
                }}
                
                .header .short-code {{
                    font-family: monospace;
                    background: rgba(255,255,255,0.2);
                    padding: 8px 16px;
                    border-radius: 8px;
                    font-size: 1.2rem;
                    display: inline-block;
                    margin-top: 10px;
                }}
                
                .content {{
                    padding: 30px;
                }}
                
                .url-info {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 15px;
                    margin-bottom: 30px;
                    border-left: 4px solid #667eea;
                }}
                
                .url-info h3 {{
                    color: #495057;
                    margin-bottom: 15px;
                }}
                
                .url-display {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    word-break: break-all;
                    font-family: monospace;
                    border: 1px solid #dee2e6;
                    margin-bottom: 10px;
                }}
                
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .stat-card {{
                    background: white;
                    padding: 25px;
                    border-radius: 15px;
                    text-align: center;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    border-left: 4px solid #D2691E;
                }}
                
                .stat-number {{
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: #D2691E;
                    margin-bottom: 5px;
                }}
                
                .stat-label {{
                    font-size: 0.9rem;
                    color: #666;
                    font-weight: 500;
                }}
                
                .performance-card {{
                    background: {performance_color};
                    color: white;
                    padding: 20px;
                    border-radius: 15px;
                    text-align: center;
                    margin-bottom: 30px;
                }}
                
                .performance-grade {{
                    font-size: 1.5rem;
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                
                .progress-section {{
                    margin-bottom: 30px;
                }}
                
                .progress-item {{
                    margin-bottom: 15px;
                }}
                
                .progress-label {{
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 5px;
                    font-weight: 500;
                }}
                
                .progress-bar {{
                    background: #e9ecef;
                    border-radius: 10px;
                    height: 12px;
                    overflow: hidden;
                }}
                
                .progress-fill {{
                    height: 100%;
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    border-radius: 10px;
                    transition: width 0.8s ease;
                }}
                
                .actions {{
                    display: flex;
                    gap: 15px;
                    justify-content: center;
                    flex-wrap: wrap;
                    margin-bottom: 30px;
                }}
                
                .btn {{
                    padding: 12px 24px;
                    border: none;
                    border-radius: 10px;
                    text-decoration: none;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    display: inline-block;
                }}
                
                .btn-primary {{
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    color: white;
                }}
                
                .btn-secondary {{
                    background: #6c757d;
                    color: white;
                }}
                
                .btn-danger {{
                    background: #dc3545;
                    color: white;
                }}
                
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }}
                
                .navigation {{
                    padding: 20px 30px;
                    border-top: 1px solid #eee;
                    text-align: center;
                }}
                
                @media (max-width: 768px) {{
                    .stats-grid {{
                        grid-template-columns: 1fr 1fr;
                        gap: 15px;
                    }}
                    
                    .actions {{
                        flex-direction: column;
                        align-items: center;
                    }}
                    
                    .btn {{
                        width: 100%;
                        max-width: 250px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📈 URL 상세 통계</h1>
                    <div class="short-code">{url_stats['short_code']}</div>
                </div>
                
                <div class="content">
                    <div class="performance-card">
                        <div class="performance-grade">{performance_grade}</div>
                        <div>평균 {avg_clicks_per_day} 클릭/일</div>
                    </div>
                    
                    <div class="url-info">
                        <h3>🔗 URL 정보</h3>
                        <strong>원본 URL:</strong>
                        <div class="url-display">{url_stats['original_url']}</div>
                        <strong>단축 URL:</strong>
                        <div class="url-display">http://localhost:8080/{url_stats['short_code']}</div>
                        <p><strong>생성일:</strong> {url_stats['created_at'][:16].replace('T', ' ')}</p>
                        <p><strong>경과 일수:</strong> {url_stats['days_since_created']}일</p>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">{url_stats['click_count']}</div>
                            <div class="stat-label">총 클릭 수</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{avg_clicks_per_day}</div>
                            <div class="stat-label">일평균 클릭</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{url_stats['space_saved_percent']}%</div>
                            <div class="stat-label">공간 절약률</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{url_stats['original_length'] - url_stats['short_length']}</div>
                            <div class="stat-label">절약된 문자</div>
                        </div>
                    </div>
                    
                    <div class="progress-section">
                        <h3 style="margin-bottom: 20px; color: #495057;">📊 성능 지표</h3>
                        
                        <div class="progress-item">
                            <div class="progress-label">
                                <span>클릭 활성도</span>
                                <span>{min(url_stats['click_count'] * 10, 100)}%</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {min(url_stats['click_count'] * 10, 100)}%"></div>
                            </div>
                        </div>
                        
                        <div class="progress-item">
                            <div class="progress-label">
                                <span>공간 효율성</span>
                                <span>{url_stats['space_saved_percent']}%</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {min(url_stats['space_saved_percent'], 100)}%"></div>
                            </div>
                        </div>
                        
                        <div class="progress-item">
                            <div class="progress-label">
                                <span>일일 성과</span>
                                <span>{min(avg_clicks_per_day * 20, 100)}%</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {min(avg_clicks_per_day * 20, 100)}%"></div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="actions">
                        <a href="/{url_stats['short_code']}" target="_blank" class="btn btn-primary">🔗 링크 테스트</a>
                        <button onclick="copyToClipboard('http://localhost:8080/{url_stats['short_code']}')" class="btn btn-secondary">📋 링크 복사</button>
                        <button onclick="deleteUrl('{url_stats['short_code']}')" class="btn btn-danger">🗑️ URL 삭제</button>
                    </div>
                </div>
                
                <div class="navigation">
                    <a href="/admin" class="btn btn-secondary">⬅️ 관리자 페이지</a>
                    <a href="/" class="btn btn-primary">🔗 새 URL 단축</a>
                </div>
            </div>
            
            <script>
                function copyToClipboard(text) {{
                    navigator.clipboard.writeText(text).then(function() {{
                        alert('✅ 링크가 클립보드에 복사되었습니다!');
                    }}, function(err) {{
                        console.error('복사 실패: ', err);
                        alert('❌ 복사에 실패했습니다.');
                    }});
                }}
                
                function deleteUrl(shortCode) {{
                    if (confirm('정말로 이 단축 URL을 삭제하시겠습니까?\\n\\n단축 코드: ' + shortCode + '\\n\\n⚠️ 이 작업은 되돌릴 수 없습니다.')) {{
                        fetch('/delete/' + shortCode, {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }}
                        }})
                        .then(response => response.json())
                        .then(data => {{
                            if (data.success) {{
                                alert('✅ ' + data.message);
                                window.location.href = '/admin'; // 관리자 페이지로 이동
                            }} else {{
                                alert('❌ ' + data.error);
                            }}
                        }})
                        .catch(error => {{
                            console.error('Error:', error);
                            alert('❌ 삭제 중 오류가 발생했습니다.');
                        }});
                    }}
                }}
                
                // 페이지 로드시 애니메이션 효과
                document.addEventListener('DOMContentLoaded', function() {{
                    const progressFills = document.querySelectorAll('.progress-fill');
                    setTimeout(() => {{
                        progressFills.forEach(fill => {{
                            fill.style.width = fill.style.width;
                        }});
                    }}, 500);
                }});
            </script>
        </body>
        </html>
        '''
        
    except Exception as e:
        print(f"❌ 통계 페이지 오류: {e}")
        return f'''
        <h1>통계 페이지 오류</h1>
        <p>오류가 발생했습니다: {str(e)}</p>
        <a href="/admin">관리자 페이지로 돌아가기</a>
        '''

# URL 삭제 API
@app.route('/delete/<short_code>', methods=['POST'])
def delete_url_api(short_code):
    """URL 삭제 API 엔드포인트"""
    
    try:
        success, message = delete_url_by_short_code(short_code)
        
        return jsonify({
            'success': success,
            'message' if success else 'error': message,
            'short_code': short_code
        }), 200 if success else 400
        
    except Exception as e:
        print(f"❌ URL 삭제 API 오류: {e}")
        return jsonify({
            'success': False,
            'error': f'삭제 중 내부 오류가 발생했습니다: {str(e)}',
            'short_code': short_code
        }), 500

# favicon.ico 핸들러 추가 (1-6단계, 1-8단계 브랜딩)
@app.route('/favicon.ico')
def favicon():
    """Cutlet 브랜드 파비콘 응답"""
    #  이모지를 SVG로 변환한 파비콘
    favicon_svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
        <text x="50%" y="50%" style="dominant-baseline:central;text-anchor:middle;font-size:24px;">🥩</text>
    </svg>'''
    
    return favicon_svg, 200, {'Content-Type': 'image/svg+xml'}

# URL 리다이렉트 엔드포인트 (1-4단계)
@app.route('/<short_code>')
def redirect_to_original(short_code):
    """단축 코드를 통해 원본 URL로 리다이렉트하는 엔드포인트"""
    
    try:
        # 특수 경로들 제외 (1-6단계 개선)
        if short_code in ['favicon.ico', 'robots.txt', 'sitemap.xml']:
            abort(404)
        
        # 단축 코드 유효성 검사 (기본적인 형식 확인)
        if not short_code or len(short_code) < 3 or len(short_code) > 10:
            print(f"⚠️ 잘못된 단축 코드 형식: {short_code}")
            abort(404)
        
        # 단축 코드에 허용되지 않는 문자가 있는지 확인
        allowed_chars = set(BASE62_CHARS)
        if not all(c in allowed_chars for c in short_code):
            print(f"⚠️ 허용되지 않는 문자가 포함된 단축 코드: {short_code}")
            abort(404)
        
        # 캐시에서 먼저 확인 (1-9단계 성능 최적화)
        cached_url = get_from_cache(short_code)
        if cached_url:
            logging.info(f"Cache hit for {short_code} -> {cached_url}")
            # 만료 체크 (4-2단계)
            url_data = get_url_by_short_code(short_code)
            if url_data and url_data.get('expires_at'):
                expires_at = datetime.datetime.fromisoformat(url_data['expires_at'])
                if datetime.datetime.now() > expires_at:
                    return redirect(url_for('expired_link', short_code=short_code))
            
            # 프리미엄은 바로 이동, 무료는 광고 페이지로 이동
            user = get_current_user()
            if user and user['user_type'] in ('premium','admin'):
                update_click_count(short_code)
                try:
                    log_click_event(short_code, request)
                except Exception:
                    pass
                return redirect(cached_url)
            else:
                return redirect(url_for('ads_page', short_code=short_code))
        
        # 캐시에 없으면 데이터베이스에서 URL 조회
        url_data = get_url_by_short_code(short_code)
        
        if url_data is None:
            logging.warning(f"Invalid short code requested: {short_code}")
            print(f"⚠️ 존재하지 않는 단축 코드: {short_code}")
            abort(404)
        
        # 만료 체크 (4-2단계)
        if url_data.get('expires_at'):
            expires_at = datetime.datetime.fromisoformat(url_data['expires_at'])
            if datetime.datetime.now() > expires_at:
                return redirect(url_for('expired_link', short_code=short_code))
        
        # 조회된 URL을 캐시에 저장
        original_url = url_data['original_url']
        add_to_cache(short_code, original_url)
        
        # 프리미엄은 바로 이동, 무료는 광고 페이지로 이동
        user = get_current_user()
        if user and user['user_type'] in ('premium','admin'):
            update_success = update_click_count(short_code)
            try:
                log_click_event(short_code, request)
            except Exception:
                pass
            return redirect(original_url)
        else:
            return redirect(url_for('ads_page', short_code=short_code))
        
    except Exception as e:
        print(f"❌ 리다이렉트 오류: {e}")
        abort(500)

# 만료된 링크 안내 페이지 (4-2단계)
@app.route('/expired/<short_code>')
def expired_link(short_code):
    """만료된 링크에 대한 안내 페이지"""
    return f'''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>링크 만료 - Cutlet</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
                max-width: 600px;
                width: 100%;
                text-align: center;
            }}
            .expired-icon {{
                font-size: 4rem;
                color: #dc3545;
                margin-bottom: 20px;
            }}
            .title {{
                font-size: 2rem;
                font-weight: bold;
                color: #333;
                margin-bottom: 10px;
            }}
            .message {{
                font-size: 1.1rem;
                color: #666;
                margin-bottom: 30px;
                line-height: 1.6;
            }}
            .btn {{
                display: inline-block;
                padding: 12px 24px;
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                color: white;
                text-decoration: none;
                border-radius: 10px;
                font-weight: 600;
                transition: transform 0.2s;
            }}
            .btn:hover {{
                transform: translateY(-2px);
            }}
            .short-code {{
                background: #f8f9fa;
                padding: 10px;
                border-radius: 8px;
                font-family: monospace;
                color: #666;
                margin: 20px 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="expired-icon">⏰</div>
            <h1 class="title">링크가 만료되었습니다</h1>
            <p class="message">
                요청하신 단축 링크 <span class="short-code">{short_code}</span>는 만료되었습니다.<br>
                링크의 소유자에게 새로운 링크를 요청하거나,<br>
                직접 URL을 입력하여 접속해주세요.
            </p>
            <a href="/" class="btn">홈으로 돌아가기</a>
        </div>
    </body>
    </html>
    '''

# PWA 관련 라우트 (4-3단계)
@app.route('/manifest.json')
def manifest():
    """PWA manifest.json 파일 제공"""
    return send_from_directory('.', 'manifest.json', mimetype='application/json')

@app.route('/sw.js')
def service_worker():
    """Service Worker 파일 제공"""
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/offline.html')
def offline_page():
    """오프라인 페이지 제공"""
    return send_from_directory('static', 'offline.html')

@app.route('/pwa-test')
def pwa_test():
    """PWA 기능 테스트 페이지"""
    return '''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PWA 테스트 - Cutlet</title>
        <meta name="theme-color" content="#D2691E">
        <link rel="manifest" href="/manifest.json">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
            }
            .title {
                font-size: 2.5rem;
                color: #D2691E;
                text-align: center;
                margin-bottom: 30px;
            }
            .test-section {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 15px;
                margin: 20px 0;
            }
            .test-title {
                font-size: 1.3rem;
                color: #333;
                margin-bottom: 15px;
            }
            .test-item {
                display: flex;
                align-items: center;
                margin: 10px 0;
                padding: 10px;
                background: white;
                border-radius: 10px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .test-icon {
                font-size: 1.5rem;
                margin-right: 15px;
                width: 30px;
                text-align: center;
            }
            .test-text {
                color: #495057;
                flex: 1;
            }
            .test-status {
                font-weight: bold;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 0.9rem;
            }
            .status-success { background: #d4edda; color: #155724; }
            .status-error { background: #f8d7da; color: #721c24; }
            .status-warning { background: #fff3cd; color: #856404; }
            .btn {
                display: inline-block;
                padding: 12px 24px;
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                color: white;
                text-decoration: none;
                border-radius: 10px;
                font-weight: 600;
                margin: 10px;
                border: none;
                cursor: pointer;
            }
            .btn:hover { transform: translateY(-2px); }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="title">📱 PWA 기능 테스트</h1>
            
            <div class="test-section">
                <h2 class="test-title">🔧 PWA 기본 기능</h2>
                <div class="test-item">
                    <div class="test-icon">📋</div>
                    <div class="test-text">Manifest.json</div>
                    <div class="test-status status-success" id="manifestStatus">확인 중...</div>
                </div>
                <div class="test-item">
                    <div class="test-icon">⚙️</div>
                    <div class="test-text">Service Worker</div>
                    <div class="test-status status-success" id="swStatus">확인 중...</div>
                </div>
                <div class="test-item">
                    <div class="test-icon">🎨</div>
                    <div class="test-text">앱 아이콘</div>
                    <div class="test-status status-success" id="iconStatus">확인 중...</div>
                </div>
            </div>
            
            <div class="test-section">
                <h2 class="test-title">📱 설치 기능</h2>
                <div class="test-item">
                    <div class="test-icon">📥</div>
                    <div class="test-text">설치 프롬프트</div>
                    <div class="test-status status-warning" id="installStatus">대기 중...</div>
                </div>
                <div class="test-item">
                    <div class="test-icon">🏠</div>
                    <div class="test-text">홈 화면 추가</div>
                    <div class="test-status status-warning" id="homeStatus">대기 중...</div>
                </div>
            </div>
            
            <div class="test-section">
                <h2 class="test-title">🌐 네트워크 상태</h2>
                <div class="test-item">
                    <div class="test-icon">📡</div>
                    <div class="test-text">온라인 상태</div>
                    <div class="test-status status-success" id="onlineStatus">확인 중...</div>
                </div>
                <div class="test-item">
                    <div class="test-icon">💾</div>
                    <div class="test-text">캐시 상태</div>
                    <div class="test-status status-success" id="cacheStatus">확인 중...</div>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <button onclick="runTests()" class="btn">🧪 테스트 실행</button>
                <button onclick="installPWA()" class="btn" id="installBtn" style="display: none;">📱 앱 설치</button>
                <a href="/" class="btn">🏠 홈으로</a>
            </div>
        </div>
        
        <script>
            let deferredPrompt;
            
            // PWA 설치 프롬프트 감지
            window.addEventListener('beforeinstallprompt', (e) => {
                e.preventDefault();
                deferredPrompt = e;
                document.getElementById('installBtn').style.display = 'inline-block';
                document.getElementById('installStatus').textContent = '사용 가능';
                document.getElementById('installStatus').className = 'test-status status-success';
            });
            
            // 설치 버튼 클릭
            function installPWA() {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    deferredPrompt.userChoice.then((choiceResult) => {
                        if (choiceResult.outcome === 'accepted') {
                            document.getElementById('installStatus').textContent = '설치됨';
                            document.getElementById('homeStatus').textContent = '사용 가능';
                            document.getElementById('installBtn').style.display = 'none';
                        }
                        deferredPrompt = null;
                    });
                }
            }
            
            // 테스트 실행
            function runTests() {
                // Manifest 확인
                fetch('/manifest.json')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('manifestStatus').textContent = '정상';
                        document.getElementById('manifestStatus').className = 'test-status status-success';
                    })
                    .catch(() => {
                        document.getElementById('manifestStatus').textContent = '오류';
                        document.getElementById('manifestStatus').className = 'test-status status-error';
                    });
                
                // Service Worker 확인
                if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.getRegistrations()
                        .then(registrations => {
                            if (registrations.length > 0) {
                                document.getElementById('swStatus').textContent = '등록됨';
                                document.getElementById('swStatus').className = 'test-status status-success';
                            } else {
                                document.getElementById('swStatus').textContent = '미등록';
                                document.getElementById('swStatus').className = 'test-status status-warning';
                            }
                        });
                } else {
                    document.getElementById('swStatus').textContent = '지원 안됨';
                    document.getElementById('swStatus').className = 'test-status status-error';
                }
                
                // 아이콘 확인
                const icon = new Image();
                icon.onload = () => {
                    document.getElementById('iconStatus').textContent = '정상';
                    document.getElementById('iconStatus').className = 'test-status status-success';
                };
                icon.onerror = () => {
                    document.getElementById('iconStatus').textContent = '오류';
                    document.getElementById('iconStatus').className = 'test-status status-error';
                };
                icon.src = '/static/icons/icon-192x192.png';
                
                // 온라인 상태
                document.getElementById('onlineStatus').textContent = navigator.onLine ? '온라인' : '오프라인';
                document.getElementById('onlineStatus').className = navigator.onLine ? 'test-status status-success' : 'test-status status-warning';
                
                // 캐시 상태
                if ('caches' in window) {
                    caches.keys()
                        .then(keys => {
                            document.getElementById('cacheStatus').textContent = keys.length > 0 ? '활성' : '비활성';
                            document.getElementById('cacheStatus').className = keys.length > 0 ? 'test-status status-success' : 'test-status status-warning';
                        });
                } else {
                    document.getElementById('cacheStatus').textContent = '지원 안됨';
                    document.getElementById('cacheStatus').className = 'test-status status-error';
                }
            }
            
            // Service Worker 등록
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.register('/sw.js')
                    .then(registration => {
                        console.log('✅ Service Worker 등록 성공:', registration.scope);
                    })
                    .catch(error => {
                        console.log('❌ Service Worker 등록 실패:', error);
                    });
            }
            
            // 페이지 로드 시 자동 테스트
            window.addEventListener('load', runTests);
        </script>
    </body>
    </html>
    '''

# 404 에러 핸들러
@app.errorhandler(404)
def not_found_error(error):
    """404 에러 페이지"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - 페이지를 찾을 수 없습니다 - Cutlet Project</title>
        <meta charset="UTF-8">
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                margin-top: 100px; 
                background-color: #f8f9fa;
            }
            .error-container {
                max-width: 600px;
                margin: 0 auto;
                padding: 40px;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .error-code { 
                font-size: 72px; 
                color: #dc3545; 
                font-weight: bold;
                margin-bottom: 20px;
            }
            .error-message { 
                font-size: 24px; 
                color: #6c757d; 
                margin-bottom: 30px;
            }
            .error-description {
                font-size: 16px;
                color: #868e96;
                margin-bottom: 40px;
                line-height: 1.6;
            }
            .btn {
                display: inline-block;
                padding: 12px 24px;
                margin: 10px;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
            }
            .btn-primary {
                background-color: #007bff;
                color: white;
            }
            .btn-secondary {
                background-color: #6c757d;
                color: white;
            }
            .btn:hover {
                opacity: 0.8;
            }
        </style>
    </head>
    <body>
        <div class="error-container">
            <div class="error-code">404</div>
            <div class="error-message">페이지를 찾을 수 없습니다</div>
            <div class="error-description">
                요청하신 단축 URL이 존재하지 않거나 잘못된 형식입니다.<br>
                URL을 다시 확인해 주세요.
            </div>
            
            <div class="help-section" style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 30px 0; text-align: left;">
                <h4 style="color: #495057; margin-bottom: 15px;">🔍 문제 해결 방법:</h4>
                <ul style="color: #6c757d; line-height: 1.8;">
                    <li>단축 코드가 정확한지 확인해주세요</li>
                    <li>대소문자를 구분하니 정확히 입력해주세요</li>
                    <li>링크를 다시 생성해보세요</li>
                    <li>문제가 계속되면 새로 단축해보세요</li>
                </ul>
            </div>
            
            <div>
                <a href="/" class="btn btn-primary">🔗 새로 단축하기</a>
                <a href="/test" class="btn btn-secondary">🧪 테스트 페이지</a>
            </div>
            
            <div style="margin-top: 30px; font-size: 14px; color: #adb5bd;">
                <p>💡 올바른 단축 URL 형식: http://localhost:8080/abc123</p>
                <p>📧 문제가 지속되면 관리자에게 문의하세요</p>
            </div>
        </div>
    </body>
    </html>
    ''', 404

# 500 에러 핸들러
@app.errorhandler(500)
def internal_error(error):
    """500 내부 서버 오류 페이지"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>500 - 내부 서버 오류 - Cutlet Project</title>
        <meta charset="UTF-8">
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                margin-top: 100px; 
                background-color: #f8f9fa;
            }
            .error-container {
                max-width: 600px;
                margin: 0 auto;
                padding: 40px;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .error-code { 
                font-size: 72px; 
                color: #dc3545; 
                font-weight: bold;
                margin-bottom: 20px;
            }
            .error-message { 
                font-size: 24px; 
                color: #6c757d; 
                margin-bottom: 30px;
            }
            .btn {
                display: inline-block;
                padding: 12px 24px;
                margin: 10px;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                background-color: #007bff;
                color: white;
            }
            .btn:hover {
                opacity: 0.8;
            }
        </style>
    </head>
    <body>
        <div class="error-container">
            <div class="error-code">500</div>
            <div class="error-message">내부 서버 오류</div>
            <div class="error-description">
                죄송합니다. 서버에서 오류가 발생했습니다.<br>
                잠시 후 다시 시도해 주세요.
            </div>
            
            <div>
                <a href="/" class="btn">🏠 홈페이지로 돌아가기</a>
            </div>
        </div>
    </body>
    </html>
    ''', 500

# 메인 페이지 라우트 (1-5단계: 웹 인터페이스)
@app.route('/')
def main_page():
    """URL 단축 서비스 메인 페이지"""
    
    # 에러 메시지 확인
    error_message = request.args.get('error', '')
    # 성공 메시지 확인
    success_message = request.args.get('message', '')
    
    # 에러 알림 HTML
    error_html = ''
    if error_message:
        error_html = f'''
        <div class="error-alert" id="errorAlert">
            <div class="error-content">
                <span class="error-icon">⚠️</span>
                <span class="error-text">{error_message}</span>
                <button class="error-close" onclick="closeError()">&times;</button>
            </div>
        </div>
        '''
    
    # 성공 알림 HTML
    success_html = ''
    if success_message:
        success_html = f'''
        <div class="success-alert" id="successAlert">
            <div class="success-content">
                <span class="success-icon">✅</span>
                <span class="success-text">{success_message}</span>
                <button class="success-close" onclick="closeSuccess()">&times;</button>
            </div>
        </div>
        '''
    
    html_content = '''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🥩 Cutlet - Cut your links, serve them fresh</title>
        
        <!-- PWA 메타 태그 (4-3단계) -->
        <meta name="theme-color" content="#D2691E">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="default">
        <meta name="apple-mobile-web-app-title" content="Cutlet">
        <meta name="mobile-web-app-capable" content="yes">
        <meta name="msapplication-TileColor" content="#D2691E">
        <meta name="msapplication-config" content="/browserconfig.xml">
        
        <!-- PWA 링크 -->
        <link rel="manifest" href="/manifest.json">
        <link rel="icon" type="image/png" sizes="192x192" href="/static/icons/icon-192x192.png">
        <link rel="icon" type="image/png" sizes="512x512" href="/static/icons/icon-512x512.png">
        <link rel="apple-touch-icon" href="/static/icons/icon-192x192.png">
        <link rel="shortcut icon" href="/static/icons/icon-192x192.png">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
                            body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
            
            .container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
                max-width: 600px;
                width: 100%;
                text-align: center;
            }
            
            .logo {
                font-size: 3.5rem;
                font-weight: bold;
                color: #D2691E;
                margin-bottom: 5px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            }
            
            .brand-emoji {
                font-size: 4rem;
                margin-bottom: 10px;
                text-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }
            
            .subtitle {
                color: #666;
                font-size: 1.2rem;
                margin-bottom: 40px;
            }
            
            .url-form {
                margin-bottom: 30px;
            }
            
            .form-group {
                margin-bottom: 20px;
                text-align: left;
            }
            
            .form-label {
                display: block;
                font-weight: 600;
                color: #333;
                margin-bottom: 8px;
                font-size: 1.1rem;
            }
            
            .url-input {
                width: 100%;
                padding: 15px 20px;
                border: 2px solid #e1e5e9;
                border-radius: 10px;
                font-size: 1rem;
                transition: all 0.3s ease;
                outline: none;
            }
            
            .url-input:focus {
                border-color: #D2691E;
                box-shadow: 0 0 0 3px rgba(210, 105, 30, 0.1);
            }
            
            .url-input::placeholder {
                color: #aaa;
            }
            
            .submit-btn {
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 1.1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                margin-top: 10px;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
            }
            
            .submit-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(210, 105, 30, 0.3);
                background: linear-gradient(135deg, #CD853F 0%, #D2691E 100%);
            }
            
            .submit-btn:active {
                transform: translateY(0);
            }
            
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 20px;
                margin-top: 40px;
                padding-top: 30px;
                border-top: 1px solid #eee;
            }
            
            .feature {
                text-align: center;
                padding: 15px;
            }
            
            .feature-icon {
                font-size: 2rem;
                margin-bottom: 10px;
            }
            
            .feature-title {
                font-weight: 600;
                color: #333;
                margin-bottom: 5px;
            }
            
            .feature-desc {
                font-size: 0.9rem;
                color: #666;
            }
            
            .links {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
                align-items: center;
                gap: 10px;
            }
            
            .link {
                display: inline-block;
                margin: 0 10px;
                color: #D2691E;
                text-decoration: none;
                font-weight: 500;
                transition: color 0.3s ease;
            }
            
            .link:hover {
                color: #CD853F;
                text-decoration: underline;
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 30px 20px;
                    margin: 10px;
                }
                
                .logo {
                    font-size: 2.5rem;
                }
                
                .subtitle {
                    font-size: 1rem;
                }
                
                .features {
                    grid-template-columns: 1fr;
                    gap: 15px;
                }
            }
            
            .loading {
                display: none;
                color: #D2691E;
                margin-top: 15px;
                padding: 15px;
                background: #fff8f0;
                border-radius: 10px;
                border: 2px solid #D2691E;
                text-align: center;
                animation: fadeIn 0.3s ease-in;
            }
            
            .spinner {
                display: inline-block;
                width: 24px;
                height: 24px;
                border: 3px solid #e1e5e9;
                border-top: 3px solid #D2691E;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin-right: 15px;
                vertical-align: middle;
            }
            
            .loading-text {
                font-weight: 600;
                font-size: 1rem;
                vertical-align: middle;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .submit-btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none !important;
            }
            
            .submit-btn:disabled:hover {
                box-shadow: none;
                transform: none !important;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            .error-alert {
                position: fixed;
                top: 20px;
                left: 50%;
                transform: translateX(-50%);
                background: #fee;
                border: 2px solid #fcc;
                border-radius: 10px;
                padding: 0;
                max-width: 500px;
                width: 90%;
                box-shadow: 0 4px 15px rgba(220, 53, 69, 0.3);
                z-index: 1000;
                animation: slideDown 0.3s ease-out;
            }
            
            .error-content {
                display: flex;
                align-items: center;
                padding: 15px 20px;
            }
            
            .error-icon {
                font-size: 1.2rem;
                margin-right: 10px;
                color: #dc3545;
            }
            
            .error-text {
                flex: 1;
                color: #721c24;
                font-weight: 500;
            }
            
            .error-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: #dc3545;
                cursor: pointer;
                padding: 0;
                margin-left: 10px;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                transition: background-color 0.3s ease;
            }
            
            .error-close:hover {
                background-color: rgba(220, 53, 69, 0.1);
            }
            
            @keyframes slideDown {
                from {
                    opacity: 0;
                    transform: translateX(-50%) translateY(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateX(-50%) translateY(0);
                }
            }
            
            @keyframes slideUp {
                from {
                    opacity: 1;
                    transform: translateX(-50%) translateY(0);
                }
                to {
                    opacity: 0;
                    transform: translateX(-50%) translateY(-20px);
                }
            }
            
            .user-info {
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.9rem;
                margin: 0 10px;
                display: inline-flex;
                align-items: center;
                white-space: nowrap;
            }
            
            .success-alert {
                position: fixed;
                top: 20px;
                left: 50%;
                transform: translateX(-50%);
                background: #d4edda;
                border: 2px solid #c3e6cb;
                border-radius: 10px;
                padding: 0;
                max-width: 500px;
                width: 90%;
                box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
                z-index: 1000;
                animation: slideDown 0.3s ease-out;
            }
            
            .success-content {
                display: flex;
                align-items: center;
                padding: 15px 20px;
            }
            
            .success-icon {
                font-size: 1.2rem;
                margin-right: 10px;
                color: #28a745;
            }
            
            .success-text {
                flex: 1;
                color: #155724;
                font-weight: 500;
            }
            
            .success-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: #28a745;
                cursor: pointer;
                padding: 0;
                margin-left: 10px;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                transition: background-color 0.3s ease;
            }
            
            .success-close:hover {
                background-color: rgba(40, 167, 69, 0.1);
            }
            
            .login-required-message {
                background: #f8f9fa;
                border: 2px solid #e9ecef;
                border-radius: 15px;
                padding: 40px;
                text-align: center;
                margin-bottom: 30px;
            }
            
            .message-icon {
                font-size: 4rem;
                margin-bottom: 20px;
                opacity: 0.7;
            }
            
            .login-required-message h3 {
                color: #495057;
                margin-bottom: 15px;
                font-size: 1.5rem;
            }
            
            .login-required-message p {
                color: #6c757d;
                margin-bottom: 25px;
                font-size: 1.1rem;
            }
            
            .auth-buttons {
                display: flex;
                gap: 15px;
                justify-content: center;
                flex-wrap: wrap;
            }
            
            .btn {
                padding: 12px 25px;
                border: none;
                border-radius: 10px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                transition: all 0.3s ease;
                min-width: 140px;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                color: white;
            }
            
            .btn-secondary {
                background: #f8f9fa;
                color: #D2691E;
                border: 2px solid #D2691E;
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="brand-emoji">🥩</div>
            <div class="logo">Cutlet</div>
            <div class="subtitle">Cut your links, serve them fresh</div>
            <div style="color: #888; font-size: 0.9rem; margin-bottom: 20px; font-style: italic;">
                ''' + ('빠르고 간편한 URL 단축 서비스' if not session.get('logged_in') else f'환영합니다, {session.get("username", "사용자")}님! 🎉') + '''
            </div>
            
            ''' + ('''
            <div class="login-required-message">
                <div class="message-icon">🔒</div>
                <h3>회원제 서비스입니다</h3>
                <p>URL 단축 서비스를 이용하려면 먼저 로그인해주세요.<br>무료로 가입하고 모든 기능을 이용하세요!</p>
                <div class="auth-buttons">
                    <a href="/login" class="btn btn-primary">🔐 로그인</a>
                    <a href="/signup" class="btn btn-secondary">📝 회원가입</a>
                </div>
            </div>
            ''' if not session.get('logged_in') else '''
            <div class="welcome-user" style="background: #e8f5e8; border: 2px solid #28a745; border-radius: 15px; padding: 20px; margin-bottom: 30px; text-align: center;">
                <div style="font-size: 1.2rem; color: #155724; margin-bottom: 10px;">🎉 로그인되었습니다!</div>
                <div style="color: #666; font-size: 1rem;">이제 URL 단축 서비스를 자유롭게 이용하실 수 있습니다.</div>
            </div>
            
            <form class="url-form" action="/shorten" method="POST" onsubmit="showLoading()">
                <div class="form-group">
                    <label for="original_url" class="form-label">단축할 URL을 입력하세요</label>
                    <input 
                        type="url" 
                        id="original_url" 
                        name="original_url" 
                        class="url-input"
                        placeholder="https://example.com/very/long/url"
                        required
                        pattern="https?://.*"
                        title="URL은 http:// 또는 https://로 시작해야 합니다"
                    >
                </div>
                <div class="form-group">
                    <label for="custom_code" class="form-label">원하는 URL로 설정 (프리미엄)</label>
                    <input 
                        type="text"
                        id="custom_code"
                        name="custom_code"
                        class="url-input"
                        placeholder="예: my-awesome-link"
                        pattern="[A-Za-z0-9-]{3,20}"
                        title="3-20자 영문/숫자/하이픈만 허용"
                    >
                    <div style="font-size:0.9rem;color:#888;margin-top:6px;">예: cutlet.me/my-awesome-link • 무료 사용자는 <a href="/pricing" style="color:#D2691E; text-decoration:none;">프리미엄 업그레이드</a> 후 이용 가능합니다.</div>
                </div>
                
                <div class="form-group">
                    <label for="expires_at" class="form-label">만료일 설정 (선택사항)</label>
                    <select id="expires_at" name="expires_at" class="url-input">
                        <option value="never">무기한</option>
                        <option value="1day">1일 후</option>
                        <option value="7days">7일 후</option>
                        <option value="30days">30일 후</option>
                    </select>
                    <div style="font-size:0.9rem;color:#888;margin-top:6px;">링크의 자동 만료일을 설정할 수 있습니다. 만료된 링크는 접속할 수 없습니다.</div>
                </div>
                
                <div class="form-group">
                    <label for="tags" class="form-label">태그 (선택사항)</label>
                    <input 
                        type="text"
                        id="tags"
                        name="tags"
                        class="url-input"
                        placeholder="예: #마케팅 #개인 #업무"
                        pattern="[#\w\s]+"
                        title="태그는 #으로 시작하고 영문/숫자/공백만 허용합니다"
                    >
                    <div style="font-size:0.9rem;color:#888;margin-top:6px;">태그를 입력하면 URL을 쉽게 분류하고 찾을 수 있습니다. #으로 시작하는 태그를 입력하세요.</div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <input 
                            type="checkbox"
                            id="is_favorite"
                            name="is_favorite"
                            style="margin-right: 8px;"
                        >
                        ⭐ 즐겨찾기로 설정
                    </label>
                    <div style="font-size:0.9rem;color:#888;margin-top:6px;">중요한 URL을 즐겨찾기로 설정하면 대시보드에서 쉽게 찾을 수 있습니다.</div>
                </div>
                
                <button type="submit" class="submit-btn" id="submitBtn">
                    🚀 URL 단축하기
                </button>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <span class="loading-text">URL을 단축하는 중입니다...</span>
                </div>
            </form>
            ''') + '''
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-title">빠른 처리</div>
                    <div class="feature-desc">즉시 단축 URL 생성</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">📊</div>
                    <div class="feature-title">클릭 추적</div>
                    <div class="feature-desc">클릭 수 자동 카운팅</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-title">안전한 링크</div>
                    <div class="feature-desc">유효성 검사 완료</div>
                </div>
                ''' + ('''
                <div class="feature">
                    <div class="feature-icon">👤</div>
                    <div class="feature-title">개인 관리</div>
                    <div class="feature-desc">내 URL 대시보드</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">⚙️</div>
                    <div class="feature-title">프로필 설정</div>
                    <div class="feature-desc">계정 관리 및 보안</div>
                </div>
                ''' if session.get('logged_in') else '') + '''
            </div>
            
            <div class="links">
                <a href="/test" class="link">🧪 테스트 페이지</a>
                <a href="/admin" class="link">🛠️ 관리자 페이지</a>
                <a href="#" class="link" onclick="showApiDocs()">📖 API 문서</a>
                <a href="/pricing" class="link">💳 요금제</a>
                ''' + ('''
                <a href="/login" class="link">🔐 로그인</a>
                <a href="/signup" class="link">📝 회원가입</a>
                ''' if not session.get('logged_in') else f'''
                <span class="user-info">👤 환영합니다, {session.get('username', '사용자')}님!</span>
                <a href="/dashboard" class="link">📊 대시보드</a>
                <a href="/profile" class="link">⚙️ 프로필</a>
                <a href="/logout" class="link">🚪 로그아웃</a>
                ''') + '''
            </div>
        </div>
        
        <script>
            // 폼 제출시 로딩 상태 표시 (1-6단계 개선)
            function showLoading() {
                const submitBtn = document.getElementById('submitBtn');
                const loadingDiv = document.getElementById('loading');
                
                // 버튼 비활성화 및 숨기기
                submitBtn.disabled = true;
                submitBtn.style.display = 'none';
                
                // 로딩 표시
                loadingDiv.style.display = 'block';
                
                return true; // 폼 제출 계속
            }
            
            // PWA 설치 프롬프트 (4-3단계)
            let deferredPrompt;
            
            window.addEventListener('beforeinstallprompt', (e) => {
                e.preventDefault();
                deferredPrompt = e;
                
                // 설치 버튼 표시
                showInstallButton();
            });
            
            function showInstallButton() {
                // 설치 버튼이 이미 있으면 중복 생성 방지
                if (document.getElementById('installButton')) return;
                
                const installBtn = document.createElement('div');
                installBtn.id = 'installButton';
                installBtn.innerHTML = `
                    <div style="position: fixed; top: 20px; right: 20px; z-index: 1000; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); padding: 15px; max-width: 300px;">
                        <div style="display: flex; align-items: center; margin-bottom: 10px;">
                            <span style="font-size: 1.5rem; margin-right: 10px;">📱</span>
                            <div>
                                <div style="font-weight: bold; color: #333;">Cutlet 앱 설치</div>
                                <div style="font-size: 0.9rem; color: #666;">홈 화면에 추가하여 더 편리하게 사용하세요</div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="installApp()" style="background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%); color: white; border: none; padding: 8px 16px; border-radius: 8px; font-weight: 600; cursor: pointer;">설치</button>
                            <button onclick="dismissInstall()" style="background: #f8f9fa; color: #666; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer;">나중에</button>
                        </div>
                    </div>
                `;
                document.body.appendChild(installBtn);
            }
            
            function installApp() {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    deferredPrompt.userChoice.then((choiceResult) => {
                        if (choiceResult.outcome === 'accepted') {
                            console.log('✅ PWA 설치 완료');
                        } else {
                            console.log('❌ PWA 설치 취소됨');
                        }
                        deferredPrompt = null;
                        dismissInstall();
                    });
                }
            }
            
            function dismissInstall() {
                const installBtn = document.getElementById('installButton');
                if (installBtn) {
                    installBtn.remove();
                }
            }
            
            // Service Worker 등록 (4-3단계)
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', () => {
                    navigator.serviceWorker.register('/sw.js')
                        .then((registration) => {
                            console.log('✅ Service Worker 등록 성공:', registration.scope);
                        })
                        .catch((error) => {
                            console.log('❌ Service Worker 등록 실패:', error);
                        });
                });
            }
            
            // API 문서 안내
            function showApiDocs() {
                alert('API 문서는 /test 페이지에서 확인하실 수 있습니다!');
            }
            
            // 에러 알림 닫기
            function closeError() {
                const errorAlert = document.getElementById('errorAlert');
                if (errorAlert) {
                    errorAlert.style.animation = 'slideUp 0.3s ease-in';
                    setTimeout(function() {
                        errorAlert.remove();
                    }, 300);
                }
            }
            
            // 성공 알림 닫기
            function closeSuccess() {
                const successAlert = document.getElementById('successAlert');
                if (successAlert) {
                    successAlert.style.animation = 'slideUp 0.3s ease-in';
                    setTimeout(function() {
                        successAlert.remove();
                    }, 300);
                }
            }
            
            // 실시간 URL 유효성 검사 (1-6단계 강화)
            document.getElementById('original_url').addEventListener('input', function() {
                const url = this.value.trim();
                const submitBtn = document.getElementById('submitBtn');
                
                // 기본 상태로 리셋
                this.style.borderColor = '#e1e5e9';
                this.style.backgroundColor = 'white';
                
                if (!url) {
                    // 빈 입력
                    submitBtn.style.opacity = '0.6';
                    submitBtn.disabled = true;
                    return;
                }
                
                if (url.length > 2048) {
                    // 너무 긴 URL
                    this.style.borderColor = '#dc3545';
                    this.style.backgroundColor = '#fff5f5';
                    submitBtn.style.opacity = '0.6';
                    submitBtn.disabled = true;
                    return;
                }
                
                if (url.startsWith('http://') || url.startsWith('https://')) {
                    // 올바른 프로토콜
                    if (url.length >= 10 && url.includes('.')) {
                        this.style.borderColor = '#228B22';
                        this.style.backgroundColor = '#f0fff4';
                        submitBtn.style.opacity = '1';
                        submitBtn.disabled = false;
                    } else {
                        this.style.borderColor = '#FF8C00';
                        this.style.backgroundColor = '#fff8f0';
                        submitBtn.style.opacity = '0.8';
                        submitBtn.disabled = false;
                    }
                } else {
                    // 잘못된 프로토콜
                    this.style.borderColor = '#dc3545';
                    this.style.backgroundColor = '#fff5f5';
                    submitBtn.style.opacity = '0.6';
                    submitBtn.disabled = true;
                }
            });
            
            // 폼 제출 전 최종 검증
            document.querySelector('.url-form').addEventListener('submit', function(e) {
                const url = document.getElementById('original_url').value.trim();
                
                if (!url) {
                    e.preventDefault();
                    alert('URL을 입력해주세요.');
                    return false;
                }
                
                if (!(url.startsWith('http://') || url.startsWith('https://'))) {
                    e.preventDefault();
                    alert('URL은 http:// 또는 https://로 시작해야 합니다.');
                    return false;
                }
                
                if (url.length > 2048) {
                    e.preventDefault();
                    alert('URL이 너무 깁니다. (최대 2048자)');
                    return false;
                }
                
                // 통과하면 로딩 표시
                return showLoading();
            });
            
            // 페이지 로드시 초기 상태 설정
            document.addEventListener('DOMContentLoaded', function() {
                const urlInput = document.getElementById('original_url');
                const submitBtn = document.getElementById('submitBtn');
                
                // 초기 상태: 버튼 비활성화
                submitBtn.style.opacity = '0.6';
                submitBtn.disabled = true;
                
                // URL 입력 필드에 포커스
                urlInput.focus();
            });
            
            // 에러 알림 자동 닫기 (7초 후)
            setTimeout(function() {
                const errorAlert = document.getElementById('errorAlert');
                if (errorAlert) {
                    closeError();
                }
            }, 7000);
            
            // 성공 알림 자동 닫기 (7초 후)
            setTimeout(function() {
                const successAlert = document.getElementById('successAlert');
                if (successAlert) {
                    closeSuccess();
                }
            }, 7000);
            
            // 키보드 단축키 (Ctrl+Enter로 폼 제출)
            document.addEventListener('keydown', function(e) {
                if (e.ctrlKey && e.key === 'Enter') {
                    const submitBtn = document.getElementById('submitBtn');
                    if (!submitBtn.disabled) {
                        document.querySelector('.url-form').submit();
                    }
                }
            });
        </script>
    </body>
    </html>
    '''

    # error_html과 success_html을 body 시작 부분에 삽입
    if error_html or success_html:
        body_start = '<body>'
        body_content = body_start + '\n        '
        if error_html:
            body_content += error_html + '\n        '
        if success_html:
            body_content += success_html + '\n        '
        html_content = html_content.replace(body_start, body_content)

    return html_content

# =====================================
# 3-5단계: 광고 리다이렉트 페이지 (무료 사용자용)
# =====================================

@app.route('/ads/<short_code>')
def ads_page(short_code):
    url = get_url_by_short_code(short_code)
    if not url:
        abort(404)
    
    # 만료 체크 (4-2단계)
    if url.get('expires_at'):
        expires_at = datetime.datetime.fromisoformat(url['expires_at'])
        if datetime.datetime.now() > expires_at:
            return redirect(url_for('expired_link', short_code=short_code))
    
    original_url = url['original_url']
    # 광고 노출 기록
    conn = get_db_connection()
    try:
        url_row = conn.execute('SELECT id FROM urls WHERE short_code = ?', (short_code,)).fetchone()
        viewer_user_id = session.get('user_id') if session.get('logged_in') else None
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if ip:
            ip = ip.split(',')[0].strip()
        ref = request.headers.get('Referer', '')
        conn.execute('INSERT INTO ad_impressions (url_id, short_code, viewer_user_id, ip, referrer) VALUES (?, ?, ?, ?, ?)', (url_row['id'] if url_row else None, short_code, viewer_user_id, ip, ref))
        conn.commit()
    finally:
        conn.close()
    
    base_styles = """
        * { box-sizing: border-box; }
        body { font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg,#D2691E 0%,#CD853F 100%); min-height:100vh; padding:30px; }
        .wrap { max-width:900px; margin:0 auto; background:#fff; border-radius:20px; box-shadow:0 20px 40px rgba(0,0,0,.1); overflow:hidden; }
        .header { background: linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff; padding:24px; display:flex; align-items:center; justify-content:space-between; }
        .title { font-size:1.6rem; font-weight:700; }
        .content { padding:24px; display:grid; grid-template-columns: 2fr 1fr; gap:18px; }
        .ad { border:1px dashed #ddd; height:250px; display:flex; align-items:center; justify-content:center; color:#999; border-radius:10px; background:#fafafa; }
        .sidebar .ad { height:600px; }
        .info { color:#555; margin-top:10px; }
        .countdown { font-weight:700; color:#D2691E; }
        .btn { display:inline-block; padding:10px 16px; border-radius:10px; text-decoration:none; font-weight:600; }
        .primary { background: linear-gradient(135deg,#D2691E 0%,#CD853F 100%); color:#fff; }
        .secondary { background:#f8f9fa; color:#D2691E; border:2px solid #D2691E; }
        .footer { padding:18px 24px; border-top:1px solid #eee; text-align:center; }
    """
    original_url_repr = {repr(original_url)}
    return f'''
    <!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>광고 - Cutlet</title>
    <style>{base_styles}</style>
    <!-- Google AdSense Placeholder: 실제 배포 시 아래 스크립트를 교체/활성화 -->
    <!--
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=YOUR-CLIENT-ID" crossorigin="anonymous"></script>
    -->
    </head><body>
        <div class="wrap">
            <div class="header">
                <div class="title">잠시 후 원본 페이지로 이동합니다</div>
                <div>프리미엄은 광고 없이 바로 이동</div>
            </div>
            <div class="content">
                <div>
                    <div class="ad">
                        <!-- adsense-top (728x90 / 970x250) -->
                        <!-- <ins class="adsbygoogle" style="display:block" data-ad-client="YOUR-CLIENT-ID" data-ad-slot="TOP-SLOT" data-ad-format="auto" data-full-width-responsive="true"></ins> -->
                        여기에 광고가 표시됩니다 (AdSense 준비 영역 728×90 또는 970×250)
                    </div>
                    <p class="info">원본 페이지: <a href="{original_url}" target="_blank">{original_url}</a></p>
                    <p class="info">광고를 제거하려면 <a href="/pricing" style="color:#D2691E; text-decoration:none; font-weight:700;">프리미엄 가입</a>을 이용하세요.</p>
                    <p class="info">자동 이동까지 <span id="sec" class="countdown">5</span>초</p>
                    <a id="skip" class="btn secondary" href="{original_url}" style="pointer-events:none; opacity:.6;">건너뛰기</a>
                </div>
                <div class="sidebar">
                    <div class="ad">
                        <!-- adsense-side (300x600) -->
                        <!-- <ins class="adsbygoogle" style="display:block" data-ad-client="YOUR-CLIENT-ID" data-ad-slot="SIDE-SLOT" data-ad-format="auto" data-full-width-responsive="true"></ins> -->
                        사이드 광고(300×600)
                    </div>
                </div>
            </div>
            <div class="footer">
                <a class="btn primary" href="/checkout">프리미엄 가입하고 광고 제거</a>
            </div>
        </div>
        <script>
            let s = 5; 
            const sec = document.getElementById('sec'); 
            const skip = document.getElementById('skip');
            const url = {original_url_repr};
            const timer = setInterval(function() {{
                s -= 1; 
                sec.textContent = s; 
                if (s <= 0) {{ 
                    clearInterval(timer); 
                    skip.style.opacity = '1'; 
                    skip.style.pointerEvents = 'auto'; 
                    window.location.href = url; 
                }} 
            }}, 1000);
        </script>
    </body></html>
    '''

# 결과 페이지 라우트 (1-5단계)
@app.route('/result')
def result_page():
    """URL 단축 결과를 보여주는 페이지"""
    
    # URL 파라미터에서 데이터 가져오기 (1-6단계 개선)
    original_url = request.args.get('original_url', '')
    short_code = request.args.get('short_code', '')
    short_url = request.args.get('short_url', '')
    message = request.args.get('message', 'URL이 성공적으로 단축되었습니다!')
    is_existing = request.args.get('is_existing', 'false').lower() == 'true'
    
    if not original_url or not short_code or not short_url:
        # 파라미터가 없으면 메인 페이지로 리다이렉트
        return redirect('/')
    
    return f'''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>URL 단축 완료 - Cutlet</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            
            .container {{
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
                max-width: 700px;
                width: 100%;
                text-align: center;
            }}
            
            .success-icon {{
                font-size: 4rem;
                color: #22c55e;
                margin-bottom: 20px;
            }}
            
            .title {{
                font-size: 2rem;
                font-weight: bold;
                color: #333;
                margin-bottom: 10px;
            }}
            
            .message {{
                color: #666;
                font-size: 1.1rem;
                margin-bottom: 40px;
            }}
            
            .url-section {{
                background: #f8f9fa;
                border-radius: 15px;
                padding: 30px;
                margin-bottom: 30px;
                text-align: left;
            }}
            
            .url-label {{
                font-weight: 600;
                color: #333;
                margin-bottom: 10px;
                font-size: 1rem;
            }}
            
            .url-display {{
                background: white;
                border: 2px solid #e1e5e9;
                border-radius: 10px;
                padding: 15px;
                font-family: monospace;
                font-size: 1rem;
                word-break: break-all;
                margin-bottom: 10px;
                position: relative;
            }}
            
            .short-url {{
                color: #667eea;
                font-weight: bold;
                font-size: 1.2rem;
            }}
            
            .original-url {{
                color: #666;
            }}
            
            .copy-btn {{
                background: #667eea;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 15px;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
                margin-top: 10px;
            }}
            
            .copy-btn:hover {{
                background: #5a67d8;
                transform: translateY(-1px);
            }}
            
            .copy-btn.copied {{
                background: #22c55e;
            }}
            
            .action-buttons {{
                display: flex;
                gap: 15px;
                justify-content: center;
                flex-wrap: wrap;
                margin-top: 30px;
            }}
            
            .btn {{
                padding: 12px 25px;
                border: none;
                border-radius: 10px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                transition: all 0.3s ease;
                min-width: 140px;
            }}
            
            .btn-primary {{
                background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
                color: white;
            }}
            
            .btn-secondary {{
                background: #f8f9fa;
                color: #D2691E;
                border: 2px solid #D2691E;
            }}
            
            .btn-success {{
                background: #22c55e;
                color: white;
            }}
            
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }}
            
            .stats {{
                background: #e8f4f8;
                border-radius: 10px;
                padding: 20px;
                margin-top: 30px;
            }}
            
            .stats-title {{
                font-weight: 600;
                color: #333;
                margin-bottom: 15px;
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 15px;
            }}
            
            .stat-item {{
                text-align: center;
            }}
            
            .stat-number {{
                font-size: 1.5rem;
                font-weight: bold;
                color: #D2691E;
            }}
            
            .stat-label {{
                font-size: 0.9rem;
                color: #666;
            }}
            
            .existing-notice {{
                background: #fef7e0;
                color: #b45309;
                padding: 15px;
                border-radius: 10px;
                margin: 20px 0;
                border-left: 4px solid #D2691E;
                font-weight: 500;
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 30px 20px;
                    margin: 10px;
                }}
                
                .title {{
                    font-size: 1.5rem;
                }}
                
                .action-buttons {{
                    flex-direction: column;
                    align-items: center;
                }}
                
                .btn {{
                    width: 100%;
                    max-width: 250px;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">{'🔄' if is_existing else '✅'}</div>
            <div class="title">{'기존 단축 URL 발견!' if is_existing else 'URL 단축 완료!'}</div>
            <div class="message">{message}</div>
            {'<div class="existing-notice">💡 이미 단축된 URL이므로 기존 단축 URL을 제공합니다.</div>' if is_existing else ''}
            
            <div class="url-section">
                <div class="url-label">📎 단축된 URL</div>
                <div class="url-display short-url" id="shortUrl">{short_url}</div>
                <button class="copy-btn" onclick="copyToClipboard('shortUrl', this)">
                    📋 복사하기
                </button>
                
                <div class="url-label" style="margin-top: 25px;">🔗 원본 URL</div>
                <div class="url-display original-url">{original_url}</div>
            </div>
            
            <div class="action-buttons">
                <a href="/" class="btn btn-primary">🔗 다시 단축하기</a>
                <a href="{short_url}" class="btn btn-success" target="_blank">🚀 링크 테스트</a>
                <a href="/stats/{short_code}" class="btn btn-secondary">📈 상세 통계</a>
                <a href="/admin" class="btn btn-secondary">🛠️ 관리자 페이지</a>
            </div>
            
            <div class="stats">
                <div class="stats-title">📈 서비스 통계</div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-number">{len(short_code)}</div>
                        <div class="stat-label">글자 단축</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{((len(original_url) - len(short_url)) / len(original_url) * 100):.0f}%</div>
                        <div class="stat-label">공간 절약</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">0</div>
                        <div class="stat-label">현재 클릭</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">∞</div>
                        <div class="stat-label">유효 기간</div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            function copyToClipboard(elementId, button) {{
                const element = document.getElementById(elementId);
                const text = element.textContent;
                
                navigator.clipboard.writeText(text).then(function() {{
                    button.textContent = '✅ 복사됨!';
                    button.classList.add('copied');
                    
                    setTimeout(function() {{
                        button.textContent = '📋 복사하기';
                        button.classList.remove('copied');
                    }}, 2000);
                }}, function(err) {{
                    console.error('복사 실패: ', err);
                    // 폴백: 텍스트 선택
                    const range = document.createRange();
                    range.selectNode(element);
                    window.getSelection().removeAllRanges();
                    window.getSelection().addRange(range);
                    
                    button.textContent = '텍스트가 선택되었습니다';
                    setTimeout(function() {{
                        button.textContent = '📋 복사하기';
                    }}, 2000);
                }});
            }}
        </script>
    </body>
    </html>
    '''

# 추가 테스트 페이지 (데이터베이스 테스트 포함)
@app.route('/test')
def test_page():
    # 데이터베이스 연결 테스트
    try:
        urls = get_all_urls()
        db_status = "✅ 데이터베이스 연결 성공!"
        
        # URL 데이터 HTML 생성
        url_list_html = ""
        if urls:
            url_list_html = "<h3>📊 저장된 URL 데이터:</h3><table border='1' style='border-collapse: collapse; width: 100%;'>"
            url_list_html += "<tr style='background-color: #f0f0f0;'><th>ID</th><th>원본 URL</th><th>단축 코드</th><th>생성일</th><th>클릭 수</th></tr>"
            
            for url in urls:
                url_list_html += f"""
                <tr>
                    <td style='padding: 8px;'>{url['id']}</td>
                    <td style='padding: 8px;'><a href="{url['original_url']}" target="_blank">{url['original_url']}</a></td>
                    <td style='padding: 8px;'><strong>{url['short_code']}</strong></td>
                    <td style='padding: 8px;'>{url['created_at']}</td>
                    <td style='padding: 8px;'>{url['click_count']}</td>
                </tr>
                """
            url_list_html += "</table>"
        else:
            url_list_html = "<p>❌ 데이터가 없습니다.</p>"
            
    except Exception as e:
        db_status = f"❌ 데이터베이스 연결 실패: {e}"
        url_list_html = ""
    
    # URL 단축 알고리즘 테스트 (1-2단계)
    try:
        # Base62 인코딩/디코딩 테스트
        test_numbers = [123, 4567, 123456, 7890123]
        base62_test_html = "<h3>🔢 Base62 인코딩/디코딩 테스트:</h3>"
        base62_test_html += "<table border='1' style='border-collapse: collapse; width: 100%;'>"
        base62_test_html += "<tr style='background-color: #e8f4f8;'><th>원본 숫자</th><th>Base62 인코딩</th><th>디코딩 결과</th><th>상태</th></tr>"
        
        for num in test_numbers:
            encoded = encode_base62(num)
            decoded = decode_base62(encoded)
            status = "✅ 성공" if num == decoded else "❌ 실패"
            
            base62_test_html += f"""
            <tr>
                <td style='padding: 8px; text-align: center;'>{num}</td>
                <td style='padding: 8px; text-align: center;'><strong>{encoded}</strong></td>
                <td style='padding: 8px; text-align: center;'>{decoded}</td>
                <td style='padding: 8px; text-align: center;'>{status}</td>
            </tr>
            """
        base62_test_html += "</table>"
        
        # 단축 코드 생성 테스트
        shortcode_test_html = "<h3>🎲 단축 코드 생성 테스트:</h3>"
        shortcode_test_html += "<table border='1' style='border-collapse: collapse; width: 100%;'>"
        shortcode_test_html += "<tr style='background-color: #fff2e8;'><th>번호</th><th>생성된 코드</th><th>길이</th><th>중복 여부</th><th>상태</th></tr>"
        
        generated_codes = []
        for i in range(8):  # 8개 생성
            length = 4 + (i % 3)  # 4~6 글자
            short_code = generate_unique_short_code(length)
            is_duplicate = short_code in generated_codes
            duplicate_status = "⚠️ 중복" if is_duplicate else "✅ 고유"
            exists_in_db = is_short_code_exists(short_code)
            db_status = "⚠️ DB 중복" if exists_in_db else "✅ DB 고유"
            
            shortcode_test_html += f"""
            <tr>
                <td style='padding: 8px; text-align: center;'>{i+1}</td>
                <td style='padding: 8px; text-align: center;'><strong>{short_code}</strong></td>
                <td style='padding: 8px; text-align: center;'>{len(short_code)}</td>
                <td style='padding: 8px; text-align: center;'>{duplicate_status}</td>
                <td style='padding: 8px; text-align: center;'>{db_status}</td>
            </tr>
            """
            generated_codes.append(short_code)
        
        shortcode_test_html += "</table>"
        
        # 알고리즘 정보
        algorithm_info = f"""
        <h3>⚙️ 알고리즘 정보:</h3>
        <ul>
            <li><strong>Base62 문자셋:</strong> {BASE62_CHARS}</li>
            <li><strong>문자 개수:</strong> 62개 (0-9: 10개, a-z: 26개, A-Z: 26개)</li>
            <li><strong>생성 방식:</strong> 시간 기반 + 랜덤 조합</li>
            <li><strong>중복 방지:</strong> 데이터베이스 조회로 확인</li>
            <li><strong>길이:</strong> 4~7글자 (가변)</li>
            <li><strong>예상 경우의 수 (6글자):</strong> 62^6 = 56,800,235,584개</li>
        </ul>
        """
        
        algorithm_status = "✅ URL 단축 알고리즘 테스트 성공!"
        
    except Exception as e:
        algorithm_status = f"❌ URL 단축 알고리즘 테스트 실패: {e}"
        base62_test_html = ""
        shortcode_test_html = ""
        algorithm_info = ""
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>데이터베이스 및 알고리즘 테스트 - Cutlet Project</title>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ margin-top: 20px; }}
            th {{ background-color: #4CAF50; color: white; padding: 10px; }}
            .status {{ font-size: 18px; margin: 20px 0; }}
            .success {{ color: green; }}
            .error {{ color: red; }}
        </style>
    </head>
    <body>
        <h2>🧪 데이터베이스 테스트 페이지</h2>
        
        <div class="status">
            <strong>데이터베이스 상태:</strong> {db_status}
        </div>
        
        <div>
            <strong>데이터베이스 파일:</strong> cutlet.db<br>
            <strong>테이블:</strong> urls (id, original_url, short_code, created_at, click_count)
        </div>
        
        {url_list_html}
        
        <h3>🔧 데이터베이스 정보:</h3>
        <ul>
            <li><strong>데이터베이스 타입:</strong> SQLite</li>
            <li><strong>파일 위치:</strong> 프로젝트 루트 디렉토리</li>
            <li><strong>테이블 구조:</strong> urls 테이블 (URL 단축 서비스용)</li>
            <li><strong>자동 초기화:</strong> 앱 시작시 테이블 생성 및 테스트 데이터 삽입</li>
        </ul>
        
        <hr style="margin: 40px 0; border: 1px solid #ddd;">
        
        <h2>🎯 URL 단축 알고리즘 테스트 (1-2단계)</h2>
        
        <div class="status">
            <strong>알고리즘 상태:</strong> {algorithm_status}
        </div>
        
        {base62_test_html}
        
        {shortcode_test_html}
        
        {algorithm_info}
        
        <hr style="margin: 40px 0; border: 1px solid #ddd;">
        
        <h2>🚀 URL 단축 API 기능 (1-3단계)</h2>
        
        <div class="status">
            <strong>API 상태:</strong> ✅ URL 단축 API 사용 가능!
        </div>
        
        <h3>📡 API 엔드포인트:</h3>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; font-family: monospace;">
            <strong>POST</strong> /shorten<br>
            <strong>Content-Type:</strong> application/json
        </div>
        
        <h3>🔧 사용 방법:</h3>
        
        <h4>💻 curl 예제:</h4>
        <div style="background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; font-family: monospace; overflow-x: auto;">
# 성공 예제<br>
curl -X POST http://localhost:8080/shorten \\<br>
&nbsp;&nbsp;-H "Content-Type: application/json" \\<br>
&nbsp;&nbsp;-d '{{"original_url": "https://www.google.com"}}'<br><br>

# 실패 예제 (잘못된 URL)<br>
curl -X POST http://localhost:8080/shorten \\<br>
&nbsp;&nbsp;-H "Content-Type: application/json" \\<br>
&nbsp;&nbsp;-d '{{"original_url": "invalid-url"}}'
        </div>
        
        <h4>📝 요청 형식:</h4>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace;">
{{<br>
&nbsp;&nbsp;"original_url": "https://example.com"<br>
}}
        </div>
        
        <h4>✅ 성공 응답:</h4>
        <div style="background-color: #d4edda; padding: 15px; border-radius: 5px; font-family: monospace;">
{{<br>
&nbsp;&nbsp;"success": true,<br>
&nbsp;&nbsp;"original_url": "https://example.com",<br>
&nbsp;&nbsp;"short_code": "a1B2c3",<br>
&nbsp;&nbsp;"short_url": "http://localhost:8080/a1B2c3",<br>
&nbsp;&nbsp;"message": "URL successfully shortened"<br>
}}
        </div>
        
        <h4>❌ 실패 응답:</h4>
        <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px; font-family: monospace;">
{{<br>
&nbsp;&nbsp;"success": false,<br>
&nbsp;&nbsp;"error": "Invalid URL format. URL must start with http:// or https://",<br>
&nbsp;&nbsp;"error_code": "INVALID_URL"<br>
}}
        </div>
        
        <h3>📋 주요 기능:</h3>
        <ul>
            <li><strong>URL 유효성 검사:</strong> http:// 또는 https://로 시작하는 URL만 허용</li>
            <li><strong>중복 방지:</strong> 같은 URL이 이미 있으면 기존 short_code 반환</li>
            <li><strong>고유 코드 생성:</strong> Base62 인코딩으로 6글자 짧은 코드 생성</li>
            <li><strong>에러 코드:</strong> INVALID_URL, MISSING_URL, DATABASE_ERROR, INTERNAL_ERROR</li>
            <li><strong>JSON 응답:</strong> 모든 응답은 JSON 형태로 제공</li>
        </ul>
        
        <h3>🧪 테스트 URL 예제:</h3>
        <ul>
            <li>https://www.google.com</li>
            <li>https://github.com</li>
            <li>https://stackoverflow.com</li>
            <li>http://example.com</li>
        </ul>
        
        <hr style="margin: 40px 0; border: 1px solid #ddd;">
        
        <h2>🔄 URL 리다이렉트 기능 (1-4단계)</h2>
        
        <div class="status">
            <strong>리다이렉트 상태:</strong> ✅ URL 리다이렉트 기능 사용 가능!
        </div>
        
        <h3>🌐 리다이렉트 사용법:</h3>
        
        <h4>1️⃣ 단축 URL 생성:</h4>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace;">
        # API로 단축 URL 생성<br>
        curl -X POST http://localhost:8080/shorten \\<br>
        &nbsp;&nbsp;-H "Content-Type: application/json" \\<br>
        &nbsp;&nbsp;-d '{{"original_url": "https://www.google.com"}}'<br><br>
        
        # 응답 예제<br>
        {{"short_url": "http://localhost:8080/a1B2c3"}}
        </div>
        
        <h4>2️⃣ 브라우저에서 접속:</h4>
        <div style="background-color: #e8f5e8; padding: 15px; border-radius: 5px;">
            <p>단축 URL을 브라우저 주소창에 입력하면 자동으로 원본 URL로 이동합니다.</p>
            <p><strong>예시:</strong> http://localhost:8080/a1B2c3 → https://www.google.com</p>
        </div>
        
        <h4>3️⃣ 테스트 가능한 단축 코드:</h4>
        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px;">
            <p>현재 데이터베이스에 저장된 테스트 단축 코드들:</p>
            <ul style="text-align: left; display: inline-block;">
                <li><a href="/google1" target="_blank">http://localhost:8080/google1</a> → Google</li>
                <li><a href="/github1" target="_blank">http://localhost:8080/github1</a> → GitHub</li>
                <li><a href="/stack1" target="_blank">http://localhost:8080/stack1</a> → StackOverflow</li>
            </ul>
            <p style="font-size: 12px; color: #856404;">⚠️ 클릭하면 실제로 해당 사이트로 이동하며, 클릭 수가 증가합니다.</p>
        </div>
        
        <h4>🔢 클릭 수 추적:</h4>
        <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px;">
            <p>단축 URL을 클릭할 때마다 자동으로 클릭 수가 증가합니다.</p>
            <p>현재 클릭 수는 위의 "저장된 URL 데이터" 테이블에서 확인할 수 있습니다.</p>
        </div>
        
        <h4>❌ 404 에러 테스트:</h4>
        <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px;">
            <p>존재하지 않는 단축 코드로 접속해 보세요:</p>
            <ul style="text-align: left; display: inline-block;">
                <li><a href="/nonexistent" target="_blank">http://localhost:8080/nonexistent</a> (404 에러 페이지)</li>
                <li><a href="/invalid@code" target="_blank">http://localhost:8080/invalid@code</a> (잘못된 문자)</li>
            </ul>
        </div>
        
        <h3>📋 리다이렉트 주요 기능:</h3>
        <ul>
            <li><strong>즉시 리다이렉트:</strong> 유효한 단축 코드 접속시 즉시 원본 URL로 이동</li>
            <li><strong>클릭 수 추적:</strong> 각 단축 URL의 클릭 수 자동 증가</li>
            <li><strong>유효성 검사:</strong> Base62 문자만 허용 (0-9, a-z, A-Z)</li>
            <li><strong>에러 처리:</strong> 존재하지 않는 코드는 예쁜 404 페이지 표시</li>
            <li><strong>로그 기록:</strong> 서버 터미널에서 리다이렉트 로그 확인 가능</li>
        </ul>
        
        <hr style="margin: 40px 0; border: 1px solid #ddd;">
        
        <h2>🌐 웹 인터페이스 기능 (1-5단계)</h2>
        
        <div class="status">
            <strong>웹 UI 상태:</strong> ✅ 사용자 친화적인 웹 인터페이스 사용 가능!
        </div>
        
        <h3>🖥️ 웹 인터페이스 사용법:</h3>
        
        <h4>1️⃣ 메인 페이지에서 URL 단축:</h4>
        <div style="background-color: #e8f5e8; padding: 15px; border-radius: 5px;">
            <p><strong>단계:</strong></p>
            <ol style="text-align: left; display: inline-block; margin: 0;">
                <li><a href="/" style="color: #667eea; text-decoration: none; font-weight: bold;">메인 페이지</a>에서 URL 입력</li>
                <li>"🚀 URL 단축하기" 버튼 클릭</li>
                <li>결과 페이지에서 단축 URL 확인 및 복사</li>
                <li>"🚀 링크 테스트" 버튼으로 즉시 테스트</li>
            </ol>
        </div>
        
        <h4>2️⃣ 웹 UI 주요 특징:</h4>
        <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px;">
            <ul style="text-align: left; display: inline-block;">
                <li><strong>🎨 모던 디자인:</strong> 그라디언트 배경과 카드 레이아웃</li>
                <li><strong>📱 반응형:</strong> 모바일, 태블릿, 데스크톱 모두 지원</li>
                <li><strong>⚡ 실시간 검증:</strong> URL 입력시 즉시 유효성 확인</li>
                <li><strong>🔄 로딩 상태:</strong> 처리 중 스피너 및 상태 표시</li>
                <li><strong>📋 원클릭 복사:</strong> 클립보드 API로 간편 복사</li>
                <li><strong>⚠️ 에러 알림:</strong> 예쁜 에러 메시지와 자동 닫기</li>
                <li><strong>📊 통계 표시:</strong> 글자 수 절약, 공간 절약률 등</li>
            </ul>
        </div>
        
        <h4>3️⃣ 사용 시나리오:</h4>
        <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px;">
            <p><strong>💼 비즈니스:</strong> 마케팅 링크, 소셜미디어 공유</p>
            <p><strong>👨‍💻 개발자:</strong> API 테스트, 문서 링크 단축</p>
            <p><strong>👥 개인:</strong> 긴 URL 공유, 북마크 정리</p>
            <p><strong>📈 분석:</strong> 클릭 수 추적, 링크 성과 분석</p>
        </div>
        
        <h4>4️⃣ 브라우저 호환성:</h4>
        <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px;">
            <p><strong>✅ 지원:</strong> Chrome, Firefox, Safari, Edge (최신 버전)</p>
            <p><strong>🔧 필요 기능:</strong> JavaScript 활성화, 클립보드 API (HTTPS 환경)</p>
            <p><strong>📱 모바일:</strong> iOS Safari, Android Chrome</p>
        </div>
        
        <h3>🎯 완성된 기능 목록:</h3>
        <div style="background-color: #e8f4f8; padding: 20px; border-radius: 10px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                <div style="text-align: left;">
                    <h4>🔧 백엔드 (API)</h4>
                    <ul>
                        <li>✅ SQLite 데이터베이스</li>
                        <li>✅ Base62 단축 알고리즘</li>
                        <li>✅ URL 단축 API</li>
                        <li>✅ 자동 리다이렉트</li>
                        <li>✅ 클릭 수 추적</li>
                        <li>✅ 에러 처리</li>
                    </ul>
                </div>
                <div style="text-align: left;">
                    <h4>🎨 프론트엔드 (UI)</h4>
                    <ul>
                        <li>✅ URL 입력 폼</li>
                        <li>✅ 결과 페이지</li>
                        <li>✅ 복사 기능</li>
                        <li>✅ 반응형 디자인</li>
                        <li>✅ 에러 알림</li>
                        <li>✅ 로딩 상태</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div style="margin-top: 30px;">
            <a href="/" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">🏠 메인 페이지로 돌아가기</a>
            <a href="/admin" style="background-color: #9C27B0; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;">🛠️ 관리자 페이지</a>
            <a href="/test" style="background-color: #2196F3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;">🔄 테스트 새로고침</a>
        </div>
    </body>
    </html>
    '''

# =====================================
# 사용자 관리 함수들 (2-1단계)
# =====================================

def create_user(username, email, password):
    """새로운 사용자를 생성하는 함수"""
    conn = get_db_connection()
    try:
        password_hash = generate_password_hash(password)
        conn.execute('''
            INSERT INTO users (username, email, password_hash, user_type, is_active) 
            VALUES (?, ?, ?, 'free', 1)
        ''', (username, email, password_hash))
        conn.commit()
        return True, "사용자가 성공적으로 생성되었습니다."
    except sqlite3.IntegrityError:
        return False, "사용자명 또는 이메일이 이미 존재합니다."
    except Exception as e:
        return False, f"사용자 생성 중 오류가 발생했습니다: {str(e)}"
    finally:
        conn.close()

def get_user_by_username(username):
    """사용자명으로 사용자 정보를 조회하는 함수"""
    conn = get_db_connection()
    try:
        user = conn.execute('''
            SELECT id, username, email, password_hash, user_type, is_active, created_at 
            FROM users 
            WHERE username = ? 
            LIMIT 1
        ''', (username,)).fetchone()
        return user
    except Exception as e:
        print(f"❌ 사용자 조회 오류: {e}")
        return None
    finally:
        conn.close()

def get_user_by_email(email):
    """이메일로 사용자 정보를 조회하는 함수"""
    conn = get_db_connection()
    try:
        user = conn.execute('''
            SELECT id, username, email, password_hash, user_type, is_active, created_at 
            FROM users 
            WHERE email = ? 
            LIMIT 1
        ''', (email,)).fetchone()
        return user
    except Exception as e:
        print(f"❌ 사용자 조회 오류: {e}")
        return None
    finally:
        conn.close()

def verify_user_credentials(username_or_email, password):
    """사용자 인증 정보를 검증하는 함수"""
    # 사용자명 또는 이메일로 사용자 찾기
    user = get_user_by_username(username_or_email)
    if not user:
        user = get_user_by_email(username_or_email)
    
    if user:
        # sqlite3.Row은 dict.get을 지원하지 않으므로 안전하게 처리
        try:
            user_keys = set(user.keys()) if hasattr(user, 'keys') else set()
        except Exception:
            user_keys = set()
        is_active = user['is_active'] if 'is_active' in user_keys else 1
        if is_active and check_password_hash(user['password_hash'], password):
            return True, user
        else:
            return False, None
    else:
        return False, None

# =====================================
# 사용자 등급/제한 관련 유틸 (2-7단계)
# =====================================

def count_user_urls_this_month(user_id):
    """해당 사용자가 이번 달에 생성한 URL 수를 반환"""
    conn = get_db_connection()
    try:
        count = conn.execute('''
            SELECT COUNT(*) FROM urls
            WHERE user_id = ?
              AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
        ''', (user_id,)).fetchone()[0]
        return int(count)
    except Exception:
        return 0
    finally:
        conn.close()

def get_user_limit_info(user_row):
    """사용자 등급에 따른 월 한도 정보를 반환 (limit_total, is_unlimited)"""
    user_type = (user_row['user_type'] if isinstance(user_row, sqlite3.Row) else user_row.get('user_type')) if user_row else 'free'
    if user_type in ('premium', 'admin'):
        return None, True
    return 10, False

def can_create_url(user_id):
    """URL 생성 가능 여부와 메시지를 반환"""
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT id, username, user_type, is_active FROM users WHERE id = ? LIMIT 1', (user_id,)).fetchone()
        if not user:
            return False, '사용자 정보를 찾을 수 없습니다.', 0, 10
        if not user['is_active']:
            return False, '비활성화된 계정입니다.', 0, 10
        limit_total, is_unlimited = get_user_limit_info(user)
        used = count_user_urls_this_month(user_id)
        if is_unlimited:
            return True, '', used, None
        if used >= limit_total:
            return False, f"무료 플랜 월 {limit_total}개 생성 한도에 도달했습니다. 프로필에서 프리미엄으로 업그레이드하세요.", used, limit_total
        return True, '', used, limit_total
    finally:
        conn.close()

def get_user_urls(user_id):
    """특정 사용자의 URL 목록을 조회하는 함수"""
    conn = get_db_connection()
    try:
        print(f"🔍 사용자 ID {user_id}의 URL 조회 중...")
        
        # 먼저 해당 사용자 ID로 URL이 있는지 확인
        count = conn.execute('SELECT COUNT(*) FROM urls WHERE user_id = ?', (user_id,)).fetchone()[0]
        print(f"📊 사용자 ID {user_id}의 URL 개수: {count}")
        
        # 모든 URL을 조회해서 user_id 확인
        all_urls = conn.execute('SELECT id, original_url, short_code, created_at, click_count, user_id FROM urls').fetchall()
        print(f"📊 전체 URL 개수: {len(all_urls)}")
        for url in all_urls:
            print(f"  - URL ID {url[0]}: user_id = {url[5]}")
        
        urls = conn.execute('''
            SELECT id, original_url, short_code, created_at, click_count, expires_at, tags, is_favorite
            FROM urls 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        
        print(f"✅ 사용자 ID {user_id}의 URL 조회 완료: {len(urls)}개")
        return urls
    except Exception as e:
        print(f"❌ 사용자 URL 조회 오류: {e}")
        return []
    finally:
        conn.close()

def update_user_password(user_id, new_password):
    """사용자 비밀번호를 업데이트하는 함수"""
    conn = get_db_connection()
    try:
        password_hash = generate_password_hash(new_password)
        conn.execute('''
            UPDATE users 
            SET password_hash = ? 
            WHERE id = ?
        ''', (password_hash, user_id))
        conn.commit()
        return True, "비밀번호가 성공적으로 변경되었습니다."
    except Exception as e:
        return False, f"비밀번호 변경 중 오류가 발생했습니다: {str(e)}"
    finally:
        conn.close()

def delete_user_account(user_id):
    """사용자 계정을 삭제하는 함수"""
    conn = get_db_connection()
    try:
        # 사용자의 URL들을 먼저 삭제
        conn.execute('DELETE FROM urls WHERE user_id = ?', (user_id,))
        # 사용자 계정 삭제
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        return True, "계정이 성공적으로 삭제되었습니다."
    except Exception as e:
        return False, f"계정 삭제 중 오류가 발생했습니다: {str(e)}"
    finally:
        conn.close()

def delete_url_by_user(url_id, user_id):
    """사용자가 소유한 URL을 삭제하는 함수"""
    conn = get_db_connection()
    try:
        # URL이 해당 사용자 소유인지 확인
        url = conn.execute('''
            SELECT id, original_url, short_code 
            FROM urls 
            WHERE id = ? AND user_id = ? 
            LIMIT 1
        ''', (url_id, user_id)).fetchone()
        
        if not url:
            return False, "해당 URL을 찾을 수 없거나 삭제 권한이 없습니다."
        
        # URL 삭제
        conn.execute('DELETE FROM urls WHERE id = ?', (url_id,))
        conn.commit()
        
        return True, f"URL '{url['short_code']}'이(가) 성공적으로 삭제되었습니다."
        
    except Exception as e:
        return False, f"URL 삭제 중 오류가 발생했습니다: {str(e)}"
    finally:
        conn.close()

# =====================================
# URL 데이터 조회 함수
# =====================================

# =====================================
# HTML 템플릿 (2-2단계, 2-3단계)
# =====================================

# 회원가입 페이지 HTML
SIGNUP_HTML = '''
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>회원가입 - Cutlet</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            color: #D2691E;
            margin-bottom: 10px;
        }
        
        .brand-emoji {
            font-size: 3rem;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
            font-size: 1rem;
        }
        
        .form-input {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s ease;
            outline: none;
        }
        
        .form-input:focus {
            border-color: #D2691E;
            box-shadow: 0 0 0 3px rgba(210, 105, 30, 0.1);
        }
        
        .submit-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(210, 105, 30, 0.3);
        }
        
        .error-message {
            background: #fee;
            color: #721c24;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
            text-align: left;
        }
        
        .links {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .link {
            display: inline-block;
            margin: 0 10px;
            color: #D2691E;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }
        
        .link:hover {
            color: #CD853F;
            text-decoration: underline;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 30px 20px;
                margin: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="brand-emoji">🥩</div>
        <div class="logo">Cutlet</div>
        <div class="subtitle">회원가입</div>
        
        ''' + (f'<div class="error-message">⚠️ {{error}}</div>' if 'error' in locals() else '') + '''
        
        <form method="POST" action="/signup">
            <div class="form-group">
                <label for="username" class="form-label">사용자명</label>
                <input 
                    type="text" 
                    id="username" 
                    name="username" 
                    class="form-input"
                    placeholder="3-20자 사이의 사용자명"
                    required
                    minlength="3"
                    maxlength="20"
                >
            </div>
            
            <div class="form-group">
                <label for="email" class="form-label">이메일</label>
                <input 
                    type="email" 
                    id="email" 
                    name="email" 
                    class="form-input"
                    placeholder="example@email.com"
                    required
                >
            </div>
            
            <div class="form-group">
                <label for="password" class="form-label">비밀번호</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input"
                    placeholder="최소 6자 이상"
                    required
                    minlength="6"
                >
            </div>
            
            <div class="form-group">
                <label for="confirm_password" class="form-label">비밀번호 확인</label>
                <input 
                    type="password" 
                    id="confirm_password" 
                    name="confirm_password" 
                    class="form-input"
                    placeholder="비밀번호를 다시 입력하세요"
                    required
                    minlength="6"
                >
            </div>
            
            <button type="submit" class="submit-btn">
                📝 회원가입
            </button>
        </form>
        
        <div class="links">
            <a href="/" class="link">🏠 메인 페이지</a>
            <a href="/login" class="link">🔐 로그인</a>
        </div>
    </div>
</body>
</html>
'''

# 로그인 페이지 HTML
LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - Cutlet</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            color: #D2691E;
            margin-bottom: 10px;
        }
        
        .brand-emoji {
            font-size: 3rem;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
            font-size: 1rem;
        }
        
        .form-input {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s ease;
            outline: none;
        }
        
        .form-input:focus {
            border-color: #D2691E;
            box-shadow: 0 0 0 3px rgba(210, 105, 30, 0.1);
        }
        
        .submit-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(210, 105, 30, 0.3);
        }
        
        .error-message {
            background: #fee;
            color: #721c24;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
            text-align: left;
        }
        
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #c3e6cb;
            text-align: left;
        }
        
        .links {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .link {
            display: inline-block;
            margin: 0 10px;
            color: #D2691E;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }
        
        .link:hover {
            color: #CD853F;
            text-decoration: underline;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 30px 20px;
                margin: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="brand-emoji">🥩</div>
        <div class="logo">Cutlet</div>
        <div class="subtitle">로그인</div>
        
        ''' + (f'<div class="error-message">⚠️ {{error}}</div>' if 'error' in locals() else '') + '''
        ''' + (f'<div class="success-message">✅ {{message}}</div>' if 'message' in locals() else '') + '''
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username_or_email" class="form-label">사용자명 또는 이메일</label>
                <input 
                    type="text" 
                    id="username_or_email" 
                    name="username_or_email" 
                    class="form-input"
                    placeholder="사용자명 또는 이메일을 입력하세요"
                    required
                >
            </div>
            
            <div class="form-group">
                <label for="password" class="form-label">비밀번호</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input"
                    placeholder="비밀번호를 입력하세요"
                    required
                >
            </div>
            
            <button type="submit" class="submit-btn">
                🔐 로그인
            </button>
        </form>
        
        <div class="links">
            <a href="/" class="link">🏠 메인 페이지</a>
            <a href="/signup" class="link">📝 회원가입</a>
        </div>
    </div>
</body>
</html>
'''

# 대시보드 페이지 HTML (2-5단계)
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>대시보드 - Cutlet</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .header .user-info {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .welcome-section {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .welcome-title {{
            font-size: 1.8rem;
            color: #495057;
            margin-bottom: 10px;
        }}
        
        .welcome-subtitle {{
            color: #6c757d;
            font-size: 1.1rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 4px solid #D2691E;
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #D2691E;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 0.9rem;
            color: #666;
            font-weight: 500;
        }}
        
        .section-title {{
            font-size: 1.5rem;
            color: #333;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .url-list {{
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .url-item {{
            padding: 20px;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: background-color 0.3s ease;
        }}
        
        .url-item:hover {{
            background: #f8f9fa;
        }}
        
        .url-item:last-child {{
            border-bottom: none;
        }}
        
        .url-info {{
            flex: 1;
        }}
        
        .url-title {{
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
            font-size: 1.1rem;
        }}
        
        .url-details {{
            color: #666;
            font-size: 0.9rem;
        }}
        
        .short-code {{
            font-family: monospace;
            background: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            color: #495057;
        }}
        
        .url-actions {{
            display: flex;
            gap: 10px;
        }}
        
        .btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .btn-primary {{
            background: #007bff;
            color: white;
        }}
        
        .btn-primary:hover {{
            background: #0056b3;
        }}
        
        .btn-danger {{
            background: #dc3545;
            color: white;
        }}
        
        .btn-danger:hover {{
            background: #c82333;
        }}
        
        .btn-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .btn-info:hover {{
            background: #138496;
        }}
        
        .btn-success {{
            background: #28a745;
            color: white;
        }}
        
        .btn-success:hover {{
            background: #218838;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        
        .empty-state i {{
            font-size: 4rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }}
        
        .navigation {{
            padding: 20px 30px;
            border-top: 1px solid #eee;
            text-align: center;
        }}
        
        .nav-btn {{
            padding: 12px 25px;
            margin: 0 10px;
            border-radius: 10px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }}
        
        .nav-btn.primary {{
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
        }}
        
        .nav-btn.secondary {{
            background: #f8f9fa;
            color: #D2691E;
            border: 2px solid #D2691E;
        }}
        
        .nav-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        @media (max-width: 768px) {{
            .content {{
                padding: 20px;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
                gap: 15px;
            }}
            
            .url-item {{
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }}
            
            .url-actions {{
                width: 100%;
                justify-content: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 개인 대시보드</h1>
            <div class="user-info">환영합니다, {username}님!</div>
        </div>
        
        <div class="content">
            <div class="welcome-section">
                <div class="welcome-title">🥩 Cutlet 대시보드</div>
                <div class="welcome-subtitle">당신의 URL 단축 서비스 현황을 확인하세요 • {usage_text}</div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_urls}</div>
                    <div class="stat-label">총 단축 URL</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_clicks}</div>
                    <div class="stat-label">총 클릭 수</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{created_at}</div>
                    <div class="stat-label">가입일</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{active_urls}</div>
                    <div class="stat-label">활성 URL</div>
                </div>
            </div>
            
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 class="section-title" style="margin: 0;">
                    🔗 내 URL 목록
                    <span style="font-size: 0.8rem; color: #666; font-weight: normal;">(최신순)</span>
                </h2>
                <div style="display: flex; gap: 10px;">
                    <a href="/export-csv" class="btn btn-success" style="text-decoration: none; padding: 8px 16px; border-radius: 8px; background: #28a745; color: white; font-size: 0.9rem;">
                        📊 CSV 내보내기
                    </a>
                    {bulk_button}
                </div>
            </div>
            
            {url_list}
        </div>
        
        <div class="navigation">
            <a href="/" class="nav-btn primary">🔗 새 URL 단축</a>
            <a href="/profile" class="nav-btn secondary">⚙️ 프로필 설정</a>
        </div>
    </div>
    
            <!-- 벌크 URL 단축 모달 (4-4단계) -->
        <div id="bulkModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000;">
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border-radius: 20px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto;">
                <h3 style="margin-bottom: 20px; color: #D2691E;">🚀 벌크 URL 단축</h3>
                <p style="color: #666; margin-bottom: 20px;">여러 URL을 한 번에 단축할 수 있습니다. (최대 50개)</p>
                
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">공통 태그 (선택사항)</label>
                    <input type="text" id="bulkTags" placeholder="예: #벌크 #마케팅" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px;">
                </div>
                
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">공통 만료일 (선택사항)</label>
                    <select id="bulkExpiresAt" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px;">
                        <option value="never">무기한</option>
                        <option value="1day">1일 후</option>
                        <option value="7days">7일 후</option>
                        <option value="30days">30일 후</option>
                    </select>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">URL 목록 (한 줄에 하나씩)</label>
                    <textarea id="bulkUrls" placeholder="https://example1.com&#10;https://example2.com&#10;https://example3.com" style="width: 100%; height: 200px; padding: 10px; border: 1px solid #ddd; border-radius: 8px; font-family: monospace;"></textarea>
                </div>
                
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button onclick="closeBulkModal()" style="padding: 10px 20px; border: 1px solid #ddd; background: #f8f9fa; border-radius: 8px; cursor: pointer;">취소</button>
                    <button onclick="submitBulkUrls()" style="padding: 10px 20px; background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%); color: white; border: none; border-radius: 8px; cursor: pointer;">🚀 단축하기</button>
                </div>
            </div>
        </div>
        
        <script>
            // 즐겨찾기 토글 함수 (4-4단계)
            function toggleFavorite(urlId, button) {{
                fetch(`/toggle-favorite/${{urlId}}`, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        // 버튼 상태 업데이트
                        if (data.is_favorite) {{
                            button.textContent = '⭐ 즐겨찾기 해제';
                            button.className = 'btn btn-warning';
                            button.style.background = '#ffc107';
                            button.style.color = '#000';
                        }} else {{
                            button.textContent = '☆ 즐겨찾기';
                            button.className = 'btn btn-secondary';
                            button.style.background = '#6c757d';
                            button.style.color = 'white';
                        }}
                        alert('✅ ' + data.message);
                    }} else {{
                        alert('❌ ' + data.error);
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    alert('❌ 즐겨찾기 변경 중 오류가 발생했습니다.');
                }});
            }}
            
            // 벌크 URL 단축 모달 표시
            function showBulkShorten() {{
                document.getElementById('bulkModal').style.display = 'block';
            }}
            
            // 벌크 URL 단축 모달 닫기
            function closeBulkModal() {{
                document.getElementById('bulkModal').style.display = 'none';
            }}
            
            // 벌크 URL 제출
            function submitBulkUrls() {{
                const urlsText = document.getElementById('bulkUrls').value.trim();
                const tags = document.getElementById('bulkTags').value.trim();
                const expiresAt = document.getElementById('bulkExpiresAt').value;
                
                if (!urlsText) {{
                    alert('URL을 입력해주세요.');
                    return;
                }}
                
                const urls = urlsText.split('\\n').filter(url => url.trim()).map(url => ({{
                    url: url.trim(),
                    is_favorite: false
                }}));
                
                if (urls.length > 50) {{
                    alert('URL은 최대 50개까지 처리 가능합니다.');
                    return;
                }}
                
                const data = {{
                    urls: urls,
                    tags: tags,
                    expires_at: expiresAt
                }};
                
                fetch('/bulk-shorten', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify(data)
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert(`✅ 벌크 단축 완료!\\n총 ${{data.total_urls}}개 중 ${{data.success_count}}개 성공`);
                        closeBulkModal();
                        location.reload(); // 페이지 새로고침
                    }} else {{
                        alert('❌ ' + data.error);
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    alert('❌ 벌크 단축 중 오류가 발생했습니다.');
                }});
            }}
            
            function deleteUrl(urlId, shortCode) {{
                if (confirm(`정말로 이 단축 URL을 삭제하시겠습니까?\\n\\n단축 코드: ${{shortCode}}\\n\\n⚠️ 이 작업은 되돌릴 수 없습니다.`)) {{
                    fetch(`/delete-url/${{urlId}}`, {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
    
                        }}
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            alert('✅ ' + data.message);
                            location.reload(); // 페이지 새로고침
                        }} else {{
                            alert('❌ ' + data.error);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error:', error);
                        alert('❌ 삭제 중 오류가 발생했습니다.');
                    }});
                }}
            }}
        </script>
</body>
</html>
'''

# 프로필 페이지 HTML (2-6단계)
PROFILE_HTML = '''
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>프로필 설정 - Cutlet</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .header .user-info {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .profile-section {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        
        .profile-title {{
            font-size: 1.5rem;
            color: #495057;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .profile-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .info-item {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .info-label {{
            font-weight: 600;
            color: #495057;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }}
        
        .info-value {{
            color: #333;
            font-size: 1.1rem;
        }}
        
        .form-section {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .form-title {{
            font-size: 1.3rem;
            color: #495057;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-label {{
            display: block;
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
            font-size: 1rem;
        }}
        
        .form-input {{
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s ease;
            outline: none;
        }}
        
        .form-input:focus {{
            border-color: #D2691E;
            box-shadow: 0 0 0 3px rgba(210, 105, 30, 0.1);
        }}
        
        .btn {{
            padding: 12px 25px;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-right: 10px;
            margin-bottom: 10px;
        }}
        
        .btn-primary {{
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
        }}
        
        .btn-danger {{
            background: #dc3545;
            color: white;
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        .message {{
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: left;
        }}
        
        .success-message {{
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        
        .error-message {{
            background: #fee;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        
        .danger-zone {{
            background: #fff5f5;
            border: 2px solid #fed7d7;
            border-radius: 15px;
            padding: 25px;
            margin-top: 30px;
        }}
        
        .danger-zone h3 {{
            color: #c53030;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .danger-zone p {{
            color: #742a2a;
            margin-bottom: 20px;
            line-height: 1.6;
        }}
        
        .navigation {{
            padding: 20px 30px;
            border-top: 1px solid #eee;
            text-align: center;
        }}
        
        .nav-btn {{
            padding: 12px 25px;
            margin: 0 10px;
            border-radius: 10px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }}
        
        .nav-btn.primary {{
            background: linear-gradient(135deg, #D2691E 0%, #CD853F 100%);
            color: white;
        }}
        
        .nav-btn.secondary {{
            background: #f8f9fa;
            color: #D2691E;
            border: 2px solid #D2691E;
        }}
        
        .nav-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        @media (max-width: 768px) {{
            .content {{
                padding: 20px;
            }}
            
            .profile-info {{
                grid-template-columns: 1fr;
            }}
            
            .btn {{
                width: 100%;
                margin-right: 0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ 프로필 설정</h1>
            <div class="user-info">{username}님의 계정 정보</div>
        </div>
        
        <div class="content">
            {success_message}
            {error_message}
            
            <div class="profile-section">
                <h2 class="profile-title">👤 계정 정보</h2>
                <div class="profile-info">
                    <div class="info-item">
                        <div class="info-label">사용자명</div>
                        <div class="info-value">{username}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">이메일</div>
                        <div class="info-value">{email}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">가입일</div>
                        <div class="info-value">{created_at}</div>
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <h2 class="form-title">🔐 비밀번호 변경</h2>
                <form method="POST" action="/profile">
                    <input type="hidden" name="action" value="change_password">
                    
                    <div class="form-group">
                        <label for="current_password" class="form-label">현재 비밀번호</label>
                        <input 
                            type="password" 
                            id="current_password" 
                            name="current_password" 
                            class="form-input"
                            placeholder="현재 비밀번호를 입력하세요"
                            required
                        >
                    </div>
                    
                    <div class="form-group">
                        <label for="new_password" class="form-label">새 비밀번호</label>
                        <input 
                            type="password" 
                            id="new_password" 
                            name="new_password" 
                            class="form-input"
                            placeholder="새 비밀번호를 입력하세요 (최소 6자)"
                            required
                            minlength="6"
                        >
                    </div>
                    
                    <div class="form-group">
                        <label for="confirm_password" class="form-label">새 비밀번호 확인</label>
                        <input 
                            type="password" 
                            id="confirm_password" 
                            name="confirm_password" 
                            class="form-input"
                            placeholder="새 비밀번호를 다시 입력하세요"
                            required
                            minlength="6"
                        >
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        🔐 비밀번호 변경
                    </button>
                </form>
            </div>
            
            <div class="danger-zone">
                <h3>⚠️ 위험 구역</h3>
                <p>
                    계정 삭제는 되돌릴 수 없는 작업입니다. 
                    삭제하면 모든 데이터가 영구적으로 사라집니다.
                </p>
                
                <form method="POST" action="/profile" style="margin-bottom:20px">
                    <input type="hidden" name="action" value="change_email">
                    <div class="form-group">
                        <label for="new_email" class="form-label">이메일 변경</label>
                        <input type="email" id="new_email" name="new_email" class="form-input" placeholder="새 이메일을 입력하세요" required>
                    </div>
                    <button type="submit" class="btn btn-primary">✉️ 이메일 변경</button>
                </form>

                <form method="POST" action="/profile" onsubmit="return confirm('계정을 비활성화하시겠습니까? 다시 로그인하려면 관리자에게 문의가 필요할 수 있습니다.')" style="margin-bottom:20px">
                    <input type="hidden" name="action" value="deactivate_account">
                    <button type="submit" class="btn btn-danger">🚫 계정 비활성화</button>
                </form>

                <form method="POST" action="/profile" onsubmit="return confirmDelete()">
                    <input type="hidden" name="action" value="delete_account">
                    
                    <div class="form-group">
                        <label for="confirm_password" class="form-label">계정 삭제를 위해 비밀번호를 입력하세요</label>
                        <input 
                            type="password" 
                            id="confirm_password" 
                            name="confirm_password" 
                            class="form-input"
                            placeholder="비밀번호를 입력하세요"
                            required
                        >
                    </div>
                    
                    <button type="submit" class="btn btn-danger">
                        🗑️ 계정 삭제
                    </button>
                </form>
            </div>
        </div>
        
        <div class="navigation">
            <a href="/dashboard" class="nav-btn primary">📊 대시보드</a>
            <a href="/" class="nav-btn secondary">🏠 메인 페이지</a>
        </div>
    </div>
    
    <script>
        function confirmDelete() {{
            return confirm('정말로 계정을 삭제하시겠습니까?\\n\\n⚠️ 이 작업은 되돌릴 수 없으며, 모든 데이터가 영구적으로 삭제됩니다.\\n\\n계속하시겠습니까?');
        }}
    </script>
</body>
</html>
'''



if __name__ == '__main__':
    # 앱 시작 시 데이터베이스 초기화
    init_database()
    
    # 환경 변수 기반 서버 실행 (1-10단계)
    host = app.config['HOST']
    port = app.config['PORT']
    debug = app.config['DEBUG']
    
    logging.info(f"🚀 Starting Cutlet server on {host}:{port}")
    logging.info(f"🥩 Cut your links, serve them fresh!")
    
    # 개발 환경에서는 Flask 내장 서버, 프로덕션에서는 Gunicorn 권장
    app.run(debug=debug, host=host, port=port)
