# 🥩 Cutlet URL Shortener

**Cut your links, serve them fresh!** 🚀

Cutlet은 현대적이고 사용자 친화적인 URL 단축 서비스입니다. 긴 URL을 짧고 기억하기 쉬운 링크로 변환하고, 상세한 분석과 관리 기능을 제공합니다.

## ✨ 주요 기능

### 🔗 핵심 기능
- **URL 단축**: 긴 URL을 짧고 기억하기 쉬운 링크로 변환
- **커스텀 코드**: 원하는 단축 코드 직접 설정 가능
- **만료일 설정**: URL의 유효 기간 설정
- **태그 관리**: URL을 카테고리별로 분류
- **즐겨찾기**: 자주 사용하는 URL 저장

### 📊 분석 및 통계
- **클릭 추적**: 단축된 URL의 클릭 수 실시간 모니터링
- **상세 분석**: 사용자 에이전트, IP, 접근 시간 등 상세 정보
- **QR 코드**: 모바일에서 쉽게 접근할 수 있는 QR 코드 생성
- **CSV 내보내기**: 데이터 백업 및 분석

### 🚀 고급 기능
- **벌크 단축**: 여러 URL을 한 번에 단축 (프리미엄)
- **프리미엄 플랜**: 무제한 URL, 상세 분석, 우선 지원
- **PWA 지원**: 모바일 앱처럼 사용 가능
- **오프라인 지원**: 서비스 워커를 통한 오프라인 기능

### 🛡️ 보안 및 안정성
- **사용자 인증**: 안전한 로그인 및 회원가입
- **URL 검증**: 악성 URL 및 보안 위험 패턴 차단
- **속도 제한**: API 남용 방지
- **에러 처리**: 사용자 친화적인 에러 페이지

## 🏗️ 기술 스택

- **Backend**: Python Flask
- **Database**: SQLite (개발) / PostgreSQL (프로덕션)
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **PWA**: Service Worker, Manifest
- **Deployment**: Gunicorn, Heroku 지원

## 🚀 설치 및 실행

### 1. 저장소 클론
```bash
git clone https://github.com/yourusername/cutlet-url-shortener.git
cd cutlet-url-shortener
```

### 2. 의존성 설치
```bash
pip install -r requirements.txt
```

### 3. 환경 설정
```bash
# 개발 환경
export FLASK_ENV=development
export FLASK_DEBUG=1

# 프로덕션 환경
export FLASK_ENV=production
export FLASK_DEBUG=0

# 이메일 설정 (비밀번호 찾기 기능)
export MAIL_USERNAME=your-email@gmail.com
export MAIL_PASSWORD=your-app-password
export MAIL_DEFAULT_SENDER=your-email@gmail.com
```

#### 📧 Gmail SMTP 설정 방법
1. **Google 계정 보안 설정**
   - [Google 계정 설정](https://myaccount.google.com/) → 보안
   - 2단계 인증 활성화

2. **앱 비밀번호 생성**
   - 보안 → 앱 비밀번호 → 메일 선택
   - 생성된 16자리 비밀번호를 `MAIL_PASSWORD`에 입력

3. **환경변수 설정 예시**
   ```bash
   export MAIL_SERVER=smtp.gmail.com
   export MAIL_PORT=587
   export MAIL_USE_TLS=True
   export MAIL_USERNAME=your-email@gmail.com
   export MAIL_PASSWORD=abcd-efgh-ijkl-mnop
   export MAIL_DEFAULT_SENDER=your-email@gmail.com
   ```

### 4. 데이터베이스 초기화
```bash
python app.py
```

### 5. 서버 실행
```bash
# 개발 환경
python app.py

# 프로덕션 환경
gunicorn -c gunicorn.conf.py app:app
```

## 📱 사용법

### 기본 URL 단축
1. 메인 페이지에 단축하고 싶은 URL 입력
2. (선택사항) 커스텀 코드, 만료일, 태그 설정
3. "🥩 URL 단축하기" 버튼 클릭
4. 단축된 URL 복사 및 공유

### 계정 관리
1. 회원가입 또는 로그인
2. 대시보드에서 URL 목록 확인
3. 통계 및 분석 데이터 확인
4. URL 편집, 삭제, 즐겨찾기 설정

### 고급 기능
- **벌크 단축**: 대시보드에서 "🚀 벌크 단축" 버튼 사용
- **QR 코드**: URL 상세 페이지에서 QR 코드 생성
- **CSV 내보내기**: 대시보드에서 데이터 백업

## 🔧 API 엔드포인트

### 인증 필요
- `POST /shorten` - URL 단축
- `POST /bulk-shorten` - 벌크 URL 단축 (프리미엄)
- `GET /dashboard` - 사용자 대시보드
- `GET /stats/<code>` - URL 통계
- `GET /analytics/<code>` - 상세 분석
- `GET /qr/<code>` - QR 코드 생성

### 공개
- `GET /<code>` - 단축된 URL 리다이렉트
- `GET /help` - 도움말 및 FAQ
- `GET /pricing` - 요금제 정보

## 💰 요금제

### 🆓 무료 플랜
- 월 100개 URL 단축
- 기본 통계 및 분석
- 기본 QR 코드 생성
- 커뮤니티 지원

### ⭐ 프리미엄 플랜 ($4.99/월)
- 무제한 URL 단축
- 벌크 URL 단축 (최대 50개)
- 상세 분석 및 인사이트
- 우선 고객 지원
- 고급 통계 및 리포트

## 🛠️ 개발 및 기여

### 개발 환경 설정
```bash
# 가상환경 생성
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 개발 의존성 설치
pip install -r requirements-dev.txt

# 코드 포맷팅
black app.py
flake8 app.py
```

### 테스트
```bash
# 단위 테스트
python -m pytest tests/

# 통합 테스트
python test_integration.py
```

### 기여 가이드라인
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📋 체크리스트

### ✅ 완료된 기능 (4-5단계)
- [x] 기본 URL 단축 및 리다이렉트
- [x] 사용자 인증 및 계정 관리
- [x] URL 통계 및 분석
- [x] QR 코드 생성
- [x] 태그 및 즐겨찾기
- [x] 벌크 URL 단축 (프리미엄)
- [x] PWA 및 오프라인 지원
- [x] 에러 처리 및 사용자 친화적 페이지
- [x] 도움말 및 FAQ 페이지
- [x] 성능 최적화 및 안정성 개선
- [x] 배포 준비 완료

### 🚀 향후 계획
- [ ] 다국어 지원 (영어, 일본어 등)
- [ ] API Rate Limiting 개선
- [ ] 실시간 알림 시스템
- [ ] 팀 협업 기능
- [ ] 고급 분석 대시보드

## 🐛 문제 해결

### 일반적인 문제
1. **데이터베이스 연결 오류**: `DATABASE_PATH` 환경변수 확인
2. **포트 충돌**: `PORT` 환경변수로 다른 포트 설정
3. **메모리 부족**: `CACHE_MAX_SIZE` 조정

### 로그 확인
```bash
# Flask 로그
tail -f logs/app.log

# Gunicorn 로그
tail -f logs/gunicorn.log
```

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 🤝 지원 및 문의

- **이슈 리포트**: [GitHub Issues](https://github.com/yourusername/cutlet-url-shortener/issues)
- **기능 요청**: [GitHub Discussions](https://github.com/yourusername/cutlet-url-shortener/discussions)
- **문서**: [Wiki](https://github.com/yourusername/cutlet-url-shortener/wiki)

## 🙏 감사의 말

- Flask 커뮤니티
- PWA 개발자들
- 모든 기여자들

---

**🥩 Cutlet URL Shortener** - *Cut your links, serve them fresh!* 🚀

*마지막 업데이트: 2025년 8월 16일*
