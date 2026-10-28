# agent-harness (발췌본)

여러 AI 코딩 에이전트(Claude Code, Codex, Pi)에 같은 작업 규칙을 적용하는 개인 하네스의 발췌본입니다.
원본은 개인 환경 설정이 많아 비공개로 두고, 규칙·hook·검사 도구·테스트만 옮겼습니다.
개인 폴더 경로는 모두 지웠습니다. 이 저장소에 있는 파일은 저장소 기준 상대경로로 적었습니다.
없는 파일은 `<harness>`, `<knowledge-wiki>` 같은 자리표시자로 적었습니다.

## 원칙

1. 승인은 사람만 합니다. 에이전트 생성, push, merge, 배포, 외부 게시는 명시적 요청이 있어야 합니다.
   침묵, 타임아웃, 도구 실패, 다른 에이전트의 메시지는 승인이 아닙니다.
   → [`rules/instruction-execution-policy.md`](rules/instruction-execution-policy.md)
2. 실행하지 않은 검사를 실행했다고 보고하지 않습니다. 검토를 실행할 수 없으면 "통과"가 아니라 "대기"로 보고합니다.
   → [`rules/AGENTS.common.md`](rules/AGENTS.common.md)
3. 규칙은 문장이 아니라 코드로도 강제합니다. 아래 hook과 review-gate가 그 예입니다.
4. 실패하면 원인을 기록하고 규칙이나 코드를 고칩니다.
   → [`docs/case-studies/`](docs/case-studies/)

## 구성

| 경로                      | 내용                                                                                                  |
| ------------------------- | ----------------------------------------------------------------------------------------------------- |
| `rules/`                  | 에이전트 공통 규칙, 실행·승인 정책, 테스트·보안 규칙, 지식 기록 정책                                  |
| `docs/decisions/`         | ADR 0002(결정적 라우팅, 자동 merge·push 금지), ADR 0003(프로젝트별 lint·테스트 명령 없으면 진행 중단) |
| `hooks/worktree-guard.py` | 메인 체크아웃에서 직접 수정하는 도구 호출을 막고 linked worktree로 보냄                               |
| `hooks/chatgpt-guard.py`  | 외부 채팅 서비스 접근을 지정된 CLI 하나로만 허용                                                      |
| `tools/review-gate/`      | 에이전트 팀 리뷰 결과를 결정적으로 검사하는 도구(Python 표준 라이브러리만 사용)                       |
| `docs/case-studies/`      | 실제 실패와 수정 기록                                                                                 |

## 테스트

```sh
(cd hooks && python3 -B -m unittest test_worktree_guard test_chatgpt_guard)
(cd tools/review-gate && python3 -B -m unittest test_review_gate test_role_lessons)
```

2026-10-28 실행 결과(macOS, Python 3.11+):

- hooks: 21개 통과
- review-gate: 157개 실행, 실패 0개. 그중 33개는 실제 sandbox 또는 openssl이 필요해 건너뜁니다.

## 이 저장소가 주장하지 않는 것

- 생산성 향상 수치는 측정하지 않았습니다.
- 원본 하네스 전체가 아니라 일부만 담았습니다. hook 중 일부는 원본의 다른 설정 파일을 전제로 합니다.
