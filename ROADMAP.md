# VectorGuard Roadmap

## Feature 1: Incident 기록 관리

### 목표
Blocked/Alerted 이벤트를 영구 기록으로 남기고, TUI에서 조회 가능하게

### 구현 단계

**Step 1: NormalizedEvent에 rule_name 추가**
- `vectorguard/src/event.rs`: `rule_name: Option<String>` 필드 추가
- `vectorguard/src/fast_path/rules.rs`: `evaluate()` 리턴을 `Option<(Action, String)>`으로 변경해 rule name도 반환
- `vectorguard/src/fast_path/mod.rs`: rule_name을 event에 세팅

**Step 2: Incident 저장 모듈**
- `vectorguard/src/incident.rs` 신규 생성
- Blocked/Alerted 이벤트를 `/var/log/vectorguard/incidents.jsonl`에 append
- 포맷: `{"timestamp":..., "pid":..., "binary":"...", "event_type":..., "rule":"...", "action":"Blocked"}`
- `main.rs`의 `run_pipeline`에서 proc_tx 전에 incident 저장 호출

**Step 3: TUI Incidents 탭**
- `vectorguard/src/tui/app.rs`: incidents 목록 유지 (최근 500개)
- `vectorguard/src/tui/render.rs`: Incidents 탭 렌더링
- 필터: All / Blocked / Alerted
- 선택 시 상세 팝업 (기존 event detail popup 재사용)

---

## Feature 2: AI 자동 룰 업데이트

### 목표
패턴 감지 → Claude API로 룰 제안 → 자동 적용

### 구현 단계

**Step 1: 패턴 감지기**
- `vectorguard/src/ai_advisor/pattern.rs`
- 슬라이딩 윈도우로 최근 이벤트 집계
- 트리거 조건 예시:
  - 동일 binary가 sensitive path 3회 이상 접근 시도 (Blocked)
  - 신규 binary가 의심 포트 연결
  - uid=0이 비정상 exec 반복

**Step 2: Claude API 연동**
- `vectorguard/src/ai_advisor/mod.rs`
- 트리거 시 최근 20개 이벤트 컨텍스트 + 현재 rules.toml 내용 전달
- 프롬프트: "이 이벤트 패턴을 보고 추가할 보안 룰을 TOML 형식으로 제안해줘"
- API key: `config.toml`의 `[ai_advisor]` 섹션에서 읽기
- 응답 파싱 → `rules/ai-generated.toml` 업데이트

**Step 3: Hot-reload 연동**
- 기존 hot-reload 시스템이 rules 디렉토리 변경 감지하도록 확장
- `ai-generated.toml` 변경 시 자동 룰 재로드

### Config 추가 필요 (`config.toml`)
```toml
[ai_advisor]
enabled = true
api_key = "sk-ant-..."
trigger_threshold = 3     # 같은 패턴 N회 감지 시 AI 호출
cooldown_seconds = 300    # AI 호출 간 최소 간격
```

---

## 구현 우선순위
1. Incident 기록 (Step 1+2) - 백엔드
2. TUI Incidents 탭 (Step 3)
3. AI Rule Advisor (패턴 감지 → API 연동)
