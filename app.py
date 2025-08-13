from flask import Flask, request, jsonify, redirect, abort, render_template_string, url_for
import sqlite3
import datetime
import os
import random
import time
import threading
import logging
from collections import defaultdict, deque
from config import get_config

# Flask 애플리케이션 인스턴스 생성
app = Flask(__name__)

# 환경별 설정 적용 (1-10단계)
config_class = get_config()
app.config.from_object(config_class)

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
    """urls 테이블 및 성능 최적화 인덱스를 생성하는 함수 (1-9단계)"""
    conn = get_db_connection()
    try:
        # urls 테이블 생성
        conn.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_url TEXT NOT NULL,
                short_code TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                click_count INTEGER DEFAULT 0
            )
        ''')
        
        # 성능 최적화를 위한 인덱스 추가 (1-9단계)
        conn.execute('CREATE INDEX IF NOT EXISTS idx_short_code ON urls(short_code)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_original_url ON urls(original_url)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_click_count ON urls(click_count DESC)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON urls(created_at)')
        
        conn.commit()
        print("✅ urls 테이블 및 성능 인덱스가 성공적으로 생성되었습니다.")
    except Exception as e:
        print(f"❌ 테이블 생성 오류: {e}")
    finally:
        conn.close()

# 데이터베이스 초기화 함수
def init_database():
    """데이터베이스를 초기화하고 테이블을 생성하는 함수"""
    print("🔄 데이터베이스 초기화 중...")
    create_tables()
    
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
def add_url(original_url, short_code):
    """새로운 URL을 데이터베이스에 추가하는 함수"""
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO urls (original_url, short_code) 
            VALUES (?, ?)
        ''', (original_url, short_code))
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
            SELECT id, original_url, short_code, created_at, click_count 
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

def shorten_url_service(original_url):
    """URL을 단축하고 데이터베이스에 저장하는 서비스 함수 (1-6단계 개선)"""
    
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
    
    # 이미 같은 URL이 있는지 확인
    conn = get_db_connection()
    try:
        existing = conn.execute(
            'SELECT short_code FROM urls WHERE original_url = ? LIMIT 1',
            (original_url,)
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
    
    # 새로운 단축 코드 생성
    try:
        short_code = generate_unique_short_code(6)  # 6글자 코드 생성
        
        # 데이터베이스에 저장
        success = add_url(original_url, short_code)
        
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

# URL 단축 API/폼 엔드포인트 (1-3, 1-5단계)
@app.route('/shorten', methods=['POST'])
def shorten_url():
    """URL을 단축하는 API/폼 엔드포인트 (1-9단계 보안 강화)"""
    
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
        
        # URL 단축 서비스 호출
        result = shorten_url_service(original_url)
        
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
    # 🥩 이모지를 SVG로 변환한 파비콘
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
            # 캐시에서 찾은 경우에도 클릭 수는 업데이트
            update_click_count(short_code)
            return redirect(cached_url)
        
        # 캐시에 없으면 데이터베이스에서 URL 조회
        url_data = get_url_by_short_code(short_code)
        
        if url_data is None:
            logging.warning(f"Invalid short code requested: {short_code}")
            print(f"⚠️ 존재하지 않는 단축 코드: {short_code}")
            abort(404)
        
        # 조회된 URL을 캐시에 저장
        original_url = url_data['original_url']
        add_to_cache(short_code, original_url)
        
        # 클릭 수 업데이트
        update_success = update_click_count(short_code)
        if update_success:
            print(f"✅ 클릭 수 업데이트 성공: {short_code} -> 클릭 수: {url_data['click_count'] + 1}")
        else:
            print(f"⚠️ 클릭 수 업데이트 실패: {short_code}")
        
        # 원본 URL로 리다이렉트
        print(f"🔄 리다이렉트: {short_code} -> {original_url}")
        logging.info(f"Redirect: {short_code} -> {original_url}")
        
        return redirect(original_url)
        
    except Exception as e:
        print(f"❌ 리다이렉트 오류: {e}")
        abort(500)

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
    
    html_content = '''
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🥩 Cutlet - Cut your links, serve them fresh</title>
        <link rel="icon" href="/favicon.ico" type="image/svg+xml">
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="brand-emoji">🥩</div>
            <div class="logo">Cutlet</div>
            <div class="subtitle">Cut your links, serve them fresh</div>
            <div style="color: #888; font-size: 0.9rem; margin-bottom: 20px; font-style: italic;">빠르고 간편한 URL 단축 서비스</div>
            
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
                
                <button type="submit" class="submit-btn" id="submitBtn">
                    🚀 URL 단축하기
                </button>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <span class="loading-text">URL을 단축하는 중입니다...</span>
                </div>
            </form>
            
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
            </div>
            
            <div class="links">
                <a href="/test" class="link">🧪 테스트 페이지</a>
                <a href="/admin" class="link">🛠️ 관리자 페이지</a>
                <a href="#" class="link" onclick="showApiDocs()">📖 API 문서</a>
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
    
    # error_html을 body 시작 부분에 삽입
    if error_html:
        html_content = html_content.replace('<body>', f'<body>\n        {error_html}')
    
    return html_content

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
