# 테스트 규칙

## 원칙

- TDD → Red > Green > Refactor 순서 준수
- 3A 원칙 → Arrange / Act / Assert
- 가능한 행위 검증보다 상태 검증을 우선한다
- 단위 테스트는 Classist 기준을 따른다 (테스트 대상 클래스 1개를 협력 객체와 격리)
- 커버리지 목표 → 80% 이상
- CI → 모든 테스트 통과 필수

## 테스트 작성

- 테스트명 → `메서드명_조건_기대결과` 형식
- 새 기능 → 레이어 정책에 맞는 테스트 함께 작성
- 버그 수정 → 재현 테스트 먼저 작성
- 버그 수정 증명 → 수정을 되돌리면 재현 테스트가 실패하고, 수정을 넣으면 통과해야 한다. 고치기 전에도 통과하는 테스트는 증거가 아니다. `python3 -I tools/review-gate/review_gate.py revert-check`로 확인하고 결과 JSON을 증거로 남긴다
- 외부 의존성 → `@MockitoBean` / `Mockito.mock()` 처리

## 레이어별 테스트 전략

- Domain / Domain Service → 단위 테스트
- Application Service → 통합 테스트
- Controller → 통합 테스트
- 핵심 사용자 시나리오 → ego lite CLI 기반 브라우저 E2E 검증 필수

## 브라우저 개발·검증

- 로컬 UI 개발, DOM 상호작용, 반응형 검사, 콘솔/네트워크 확인, 시각적 QA, 스크린샷은 `ego-browser nodejs`를 기본으로 사용한다.
- 공유 `skills/ego-browser/SKILL.md`의 API를 따른다. 브라우저 실행 전 같은 셸에서 프로필을 로드하고 검증한다. Playwright를 가져오거나 새 브라우저를 직접 실행하지 않는다.
- 사용자 목표당 TaskSpace 하나를 만들고 spaceId로 이어서 사용한다. `page.snapshot()`으로 상태를 읽고 동작 결과를 확인한다. 시각적 증거에는 필요한 경우 `page.screenshot()`을 사용한다.
- 완료 시 `task.finish({ keep: [] })`를 기다린다. 사용자가 확인하거나 이어서 작업할 결과 페이지만 유지한다. Aside는 명시적으로 선택한 작업에서만 기존 감사 래퍼로 사용한다.
- 공개 자료 확인은 HTTP/Lightpanda, 인증 자동화는 PinchTab 경로를 유지한다. 프로젝트가 고정한 E2E 러너는 그대로 실행하며, 기존 Playwright 테스트를 ego lite로 임의 변환하지 않는다.

## 단위 테스트(Classist) 규칙

- 테스트 대상(SUT)은 1개 클래스만 둔다
- 협력 객체(Repository, 외부 API, 메시징, Clock 등)는 Mock/Stub으로만 격리한다 (Fake 사용 금지)
- 단위 테스트에서 DB/네트워크/파일 I/O를 직접 사용하지 않는다
- 상태 검증을 우선하되, 외부 협력 호출은 필요한 경우에만 최소한으로 검증한다
- private 메서드/구현 디테일을 직접 검증하지 않는다

## Spring 테스트 도구 가이드

- 단위 테스트 → `@ExtendWith(MockitoExtension.class)`
- 통합 테스트 → `@SpringBootTest` + Testcontainers
- 통합 테스트 DB는 개발/운영과 동일한 엔진/버전 이미지를 사용한다
- E2E 테스트 → 실제 API 경로 기준으로 시나리오 검증
- DB 격리 → `@Transactional` 또는 `@Sql` 로 초기화
- API 검증 → `MockMvc` 사용

## 금지

- 통합 테스트에서 H2 인메모리 DB 사용 금지
- 테스트 간 상태 공유 금지
- `println` 디버깅 코드 남기지 말 것
