"""
Gunicorn Configuration for Cutlet URL Shortener
🥩 Cut your links, serve them fresh

프로덕션 환경에서 사용할 WSGI 서버 설정
"""

import os
import multiprocessing

# 서버 설정
bind = f"0.0.0.0:{os.environ.get('PORT', 8080)}"
workers = int(os.environ.get('WEB_CONCURRENCY', multiprocessing.cpu_count() * 2 + 1))

# 워커 클래스
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# 타임아웃 설정
timeout = 30
keepalive = 2

# 로깅 설정
accesslog = "access.log"
errorlog = "error.log"
loglevel = os.environ.get('LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# 프로세스 이름
proc_name = "cutlet"

# 보안 설정
user = None  # 실제 배포시 적절한 사용자로 변경
group = None  # 실제 배포시 적절한 그룹으로 변경

# 성능 최적화
preload_app = True
enable_stdio_inheritance = True

# 재시작 설정
reload = os.environ.get('FLASK_ENV', 'production') == 'development'

# 임시 파일 디렉토리
tmp_upload_dir = None

# SSL 설정 (필요시)
# keyfile = "/path/to/keyfile"
# certfile = "/path/to/certfile"

def when_ready(server):
    """서버 시작 시 실행될 함수"""
    server.log.info("🥩 Cutlet URL Shortener is ready to serve!")
    server.log.info("Cut your links, serve them fresh!")

def worker_int(worker):
    """워커 중단 시 실행될 함수"""
    worker.log.info("Worker received INT or QUIT signal")

def pre_fork(server, worker):
    """포크 전 실행될 함수"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def post_fork(server, worker):
    """포크 후 실행될 함수"""
    server.log.info(f"Worker {worker.pid} started")
