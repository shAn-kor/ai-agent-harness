# 사례: ctx-relay가 바쁜 입력창에 명령을 넣던 경쟁 상태

- 날짜: 2026-10-28
- 대상: 컨텍스트가 가득 찬 세션을 새 세션으로 넘기는 Stop hook(`ctx_relay.rs`, Rust)

## 증상

인계문은 만들어졌지만 새 세션이 빈 상태로 열렸습니다.

## 원인

다른 Stop hook(capture-nudge)이 종료를 막으면 턴이 계속 실행됩니다.
ctx-relay는 Stop을 턴 종료로 보고 `/clear`와 인계 프롬프트를 바로 입력했습니다.
에이전트는 두 입력을 대기열에 넣었습니다. 이전 세션이 인계 프롬프트를 먼저 소비했고,
나중에 실행된 `/clear`가 빈 세션을 열었습니다.

## 수정

입력하기 전에 pane의 `agent_status`를 1.5초 간격으로 읽습니다.
`working`이 아닌 값을 두 번 연속 읽은 뒤에만 입력합니다. 15분 안에 조건을 만족하지 못하면 아무것도 입력하지 않습니다.

## 변경 부분 (발췌)

```diff
@@ -229,16 +230,40 @@ fn run_herdr(args: &[&str], timeout: Duration) -> Option<String> {
     Some(String::from_utf8_lossy(&bytes).into_owned())
 }
 
-fn pane_agent(pane: &str) -> Option<String> {
+fn pane_field(pane: &str, field: &str) -> Option<String> {
     let out = run_herdr(&["pane", "get", pane], Duration::from_secs(5))?;
     let v: Value = serde_json::from_str(&out).ok()?;
     v.get("result")?
         .get("pane")?
-        .get("agent")?
+        .get(field)?
         .as_str()
         .map(String::from)
 }
 
+fn pane_agent(pane: &str) -> Option<String> {
+    pane_field(pane, "agent")
+}
+
+/// Wait until the agent has finished its turn. Another Stop hook (e.g.
+/// capture-nudge) can block the stop and keep the turn running; typing then
+/// queues `/clear` behind the MARKER prompt, so the old session swallows the
+/// handoff and the new session starts empty.
+fn wait_idle(pane: &str, timeout: Duration) -> bool {
+    let deadline = Instant::now() + timeout;
+    let mut idle_reads = 0;
+    while Instant::now() < deadline {
+        match pane_field(pane, "agent_status").as_deref() {
+            Some("working") | None => idle_reads = 0,
+            Some(_) => idle_reads += 1,
+        }
+        if idle_reads >= 2 {
+            return true;
+        }
+        thread::sleep(Duration::from_millis(1500));
+    }
+    false
+}
+
 /// Only the pane's own top-level agent may relay.
 fn owns_pane(runtime: &str, pane: &str) -> bool {
     pane_agent(pane).as_deref() == Some(runtime)
@@ -639,8 +664,14 @@ fn relay(runtime: &str, pane: &str) {
         "pi" => "/new",
         _ => return,
     };
+    if !wait_idle(pane, IDLE_TIMEOUT) {
+        return;
+    }
     if type_and_confirm(pane, command) == Some(true) {
         thread::sleep(Duration::from_secs(3));
+        if !wait_idle(pane, IDLE_TIMEOUT) {
+            return;
+        }
         type_and_confirm(pane, &format!("{} {MARKER}", relay_title(&state)));
     }
 }
```
