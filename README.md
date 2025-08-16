# 🥩 Cutlet URL Shortener

**Cut your links, serve them fresh!**

완전한 기능을 갖춘 엔터프라이즈급 URL 단축 서비스입니다.

## ✨ 주요 기능

### 🎯 핵심 기능
- **URL 단축**: 긴 URL을 짧고 기억하기 쉬운 코드로 변환
- **리다이렉트**: 단축 URL 클릭 시 원본 URL로 즉시 이동
- **클릭 추적**: 각 URL의 클릭 수 실시간 모니터링
- **중복 방지**: 동일 URL 재입력 시 기존 단축 코드 반환

### 🎨 사용자 인터페이스
- **반응형 디자인**: 모바일/데스크톱 완벽 지원
- **실시간 검증**: URL 입력 시 즉시 유효성 확인
- **복사 기능**: 원클릭으로 단축 URL 복사
- **로딩 상태**: 처리 과정 시각적 피드백

### 📊 관리 도구
- **관리자 대시보드**: 전체 통계 및 URL 관리
- **상세 분석**: 개별 URL 성능 지표
- **일괄 관리**: URL 삭제 및 수정 기능
- **실시간 모니터링**: 서비스 상태 추적

### 🛡️ 보안 & 성능
- **Rate Limiting**: IP별 요청 제한 (분당 10회)
- **악성 URL 차단**: 알려진 위험 패턴 자동 검출
- **메모리 캐싱**: 인기 URL 빠른 응답
- **데이터베이스 최적화**: 인덱스 기반 고속 조회

## 🚀 빠른 시작

### 1. 개발 환경 설정

```bash
# 저장소 클론
git clone <repository-url>
cd cutlet-project

# 의존성 설치
pip install -r requirements.txt

# 개발 서버 실행
python app.py
```

## 📱 PWA 설치 방법

### 모바일에서 앱으로 설치
1. **Chrome/Edge (Android)**
   - 브라우저에서 Cutlet 접속
   - 주소창 아래 "앱 설치" 버튼 클릭
   - "설치" 선택

2. **Safari (iOS)**
   - Safari에서 Cutlet 접속
   - 공유 버튼 → "홈 화면에 추가"
   - "추가" 선택

3. **데스크톱에서 설치**
   - Chrome/Edge에서 Cutlet 접속
   - 주소창 우측 "설치" 아이콘 클릭
   - "설치" 선택

### PWA 기능
- ✅ 오프라인 지원
- ✅ 홈 화면 추가
- ✅ 앱과 같은 경험
- ✅ 자동 업데이트
- ✅ 푸시 알림 준비

### 2. 환경 변수 설정

`config.py`에서 기본 설정을 확인하고 필요시 환경 변수로 오버라이드:

```bash
export FLASK_ENV=development
export FLASK_DEBUG=True
export DATABASE_PATH=cutlet_dev.db
export RATE_LIMIT_PER_MINUTE=10
export PORT=8080
```

### 3. 접속 확인

- **메인 페이지**: http://localhost:8080
- **관리자 페이지**: http://localhost:8080/admin
- **테스트 페이지**: http://localhost:8080/test

## 🏭 프로덕션 배포

### Gunicorn 사용

```bash
# 프로덕션 환경 변수 설정
export FLASK_ENV=production
export FLASK_DEBUG=False
export SECRET_KEY=your-super-secret-key

# Gunicorn으로 실행
gunicorn --config gunicorn.conf.py app:app
```

### 시작 스크립트 사용

```bash
# 실행 권한 부여
chmod +x start.sh

# 프로덕션 실행
FLASK_ENV=production ./start.sh
```

### Heroku 배포

```bash
# Heroku CLI 설치 후
heroku create cutlet-app
git push heroku main
```

### Docker 배포

```dockerfile
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["./start.sh"]
```

## 📁 프로젝트 구조

```
cutlet-project/
├── 🥩 app.py                # 메인 애플리케이션
├── ⚙️ config.py             # 환경별 설정
├── 📋 requirements.txt      # Python 의존성
├── 🚀 gunicorn.conf.py      # WSGI 서버 설정
├── 📦 Procfile             # Heroku 배포용
├── 🐍 runtime.txt          # Python 버전 지정
├── 🚀 start.sh             # 시작 스크립트
├── 📊 cutlet.db            # SQLite 데이터베이스
├── 📝 cutlet.log           # 애플리케이션 로그
├── 🔒 .gitignore           # Git 제외 파일
└── 📖 README.md            # 프로젝트 문서
```

## 🔧 환경 설정

### 개발 환경 (Development)
- DEBUG: True
- 로그 레벨: DEBUG
- 데이터베이스: cutlet_dev.db
- Rate Limit: 10/분

### 프로덕션 환경 (Production)
- DEBUG: False
- 로그 레벨: WARNING
- 로그 로테이션: 활성화
- Rate Limit: 5/분 (더 엄격)
- 캐싱: 최적화

### 테스트 환경 (Testing)
- 메모리 내 데이터베이스
- 로그 최소화
- 빠른 실행

## 📊 API 문서

### URL 단축
```bash
POST /shorten
Content-Type: application/json

{
  "original_url": "https://example.com/very/long/url"
}
```

### 응답
```json
{
  "success": true,
  "original_url": "https://example.com/very/long/url",
  "short_code": "abc123",
  "short_url": "http://your-domain.com/abc123",
  "message": "URL이 성공적으로 단축되었습니다!"
}
```

### URL 삭제
```bash
POST /delete/<short_code>
```

## 🛠️ 개발 가이드

### 로컬 개발
1. Python 3.13+ 설치
2. 가상환경 생성 권장
3. 의존성 설치: `pip install -r requirements.txt`
4. 개발 서버 실행: `python app.py`

### 코드 수정
- `app.py`: 메인 로직
- `config.py`: 설정 관리
- `requirements.txt`: 패키지 관리

### 디버깅
- 로그 파일: `cutlet.log`
- 개발자 도구: Flask Debug 모드
- 테스트 페이지: `/test`

## 🔍 모니터링

### 로그 파일
- `cutlet.log`: 애플리케이션 로그
- `access.log`: Gunicorn 접근 로그
- `error.log`: Gunicorn 에러 로그

### 주요 메트릭
- 총 단축 URL 수
- 일일 클릭 수
- 평균 응답 시간
- 캐시 히트율

## 🆘 문제 해결

### 일반적인 문제
1. **포트 충돌**: PORT 환경 변수로 다른 포트 사용
2. **데이터베이스 락**: SQLite 파일 권한 확인
3. **메모리 부족**: 캐시 크기 조정

### 성능 최적화
1. **데이터베이스 인덱스**: 자동 생성됨
2. **캐싱**: 인기 URL 메모리 저장
3. **Rate Limiting**: 과부하 방지

## 📄 라이센스

MIT License - 자유롭게 사용, 수정, 배포 가능

## 🤝 기여하기

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

**🥩 Cutlet - Cut your links, serve them fresh!**

Made with ❤️ for the web community.
