# 보안 규칙

- 시크릿 하드코딩 금지 → 환경변수 사용
- `.env` → 항상 `.gitignore` 포함
- SQL → 파라미터 바인딩만 사용
- 사용자 입력 → 반드시 sanitize
- CORS → 최소 권한
- `--dangerously-skip-permissions` 절대 금지
- 의존성 취약점 정기 검사 (`npm audit`, `pip audit`)
