#!/bin/bash
# Cutlet URL Shortener Startup Script
# 🥩 Cut your links, serve them fresh

echo "🥩 Starting Cutlet URL Shortener..."

# 환경 변수 설정 (필요시 수정)
export FLASK_ENV=${FLASK_ENV:-production}
export FLASK_DEBUG=${FLASK_DEBUG:-False}
export HOST=${HOST:-0.0.0.0}
export PORT=${PORT:-8080}

# 프로덕션 환경에서는 Gunicorn 사용
if [ "$FLASK_ENV" = "production" ]; then
    echo "🚀 Starting with Gunicorn (Production mode)"
    exec gunicorn --config gunicorn.conf.py app:app
else
    echo "🛠️ Starting with Flask dev server (Development mode)"
    exec python app.py
fi
