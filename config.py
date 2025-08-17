"""
Cutlet URL Shortener Configuration
🥩 Cut your links, serve them fresh

환경 변수를 통한 설정 관리
"""

import os
from pathlib import Path

class Config:
    """기본 설정"""
    
    # Flask 설정
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cutlet-dev-secret-key-2024'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # 데이터베이스 설정
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or 'cutlet.db'
    
    # 로그 설정
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or 'cutlet.log'
    
    # 성능 & 보안 설정
    RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE') or 10)
    CACHE_MAX_SIZE = int(os.environ.get('CACHE_MAX_SIZE') or 1000)
    
    # 서버 설정
    HOST = os.environ.get('HOST') or '0.0.0.0'
    PORT = int(os.environ.get('PORT') or 8081)
    
    # 보안 설정
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH') or 1048576)  # 1MB
    
    # 이메일 설정 (비밀번호 찾기 기능)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or ''
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or ''
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or ''
    MAIL_MAX_EMAILS = int(os.environ.get('MAIL_MAX_EMAILS') or 10)
    
    @staticmethod
    def init_app(app):
        """Flask 앱 초기화"""
        pass


class DevelopmentConfig(Config):
    """개발 환경 설정"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    DATABASE_PATH = 'cutlet_dev.db'


class ProductionConfig(Config):
    """프로덕션 환경 설정"""
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'change-this-in-production'
    DATABASE_PATH = os.environ.get('DATABASE_URL') or 'cutlet_prod.db'
    
    # 프로덕션 보안 강화
    RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE') or 5)
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        
        # 프로덕션 로깅 설정
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug:
            file_handler = RotatingFileHandler(
                'cutlet_prod.log', 
                maxBytes=10240000, 
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.WARNING)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.WARNING)


class TestingConfig(Config):
    """테스트 환경 설정"""
    TESTING = True
    DEBUG = False
    DATABASE_PATH = ':memory:'  # 메모리 내 SQLite
    LOG_LEVEL = 'CRITICAL'


# 환경별 설정 매핑
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """현재 환경에 맞는 설정 반환"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
