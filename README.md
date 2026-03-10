# VectorGuard

eBPF 기반 Linux 런타임 보안 데몬.

시스템 콜을 실시간으로 모니터링하고, TOML 룰 엔진으로 즉시 판단하며, 벡터 DB 기반 행동 분석으로 알려지지 않은 공격 패턴까지 탐지합니다.
위협이 확인되면 **커널 레벨에서 직접 차단** — userspace 왕복 없이 `bpf_send_signal(SIGKILL)`로 프로세스를 즉시 종료합니다.

---

## 목차

- [주요 기능](#주요-기능)
- [아키텍처](#아키텍처)
- [요구 사항](#요구-사항)
- [빠른 시작](#빠른-시작)
- [설정](#설정)
- [Fast Path 룰](#fast-path-룰)
- [Slow Path 이상 탐지](#slow-path-이상-탐지)
- [어댑터](#어댑터)
- [Kubernetes 배포](#kubernetes-배포)
- [테스트](#테스트)
- [프로젝트 구조](#프로젝트-구조)
- [문제 해결](#문제-해결)
- [제거](#제거)
- [라이선스](#라이선스)

---

## 주요 기능

### 모니터링
- `execve`, `openat`, `connect` 시스템 콜 트레이스포인트
- LSM 훅 (`bprm_check_security`, `file_open`) — 커널이 지원하면 자동 연결

### 탐지 (Fast Path)
- TOML 기반 룰 엔진 — 프로세스명, 파일 경로, 포트, UID 조합으로 매칭
- `block` / `alert` / `log` / `allow` 4단계 액션
- 룰 파일 저장 시 **500ms 이내 자동 반영** (hot reload)

### 탐지 (Slow Path)
- 프로세스별 행동 벡터를 64차원으로 임베딩
- 시간 윈도우 기반 컨텍스트 블렌딩 (현재 70% + 히스토리 30%)
- Qdrant 벡터 DB에서 코사인 유사도 검색 → 유사 패턴 없으면 이상 탐지

### 차단 (Enforcement)
- eBPF HashMap에 차단 대상(프로세스명/포트/UID) 등록
- 트레이스포인트에서 매칭 시 `bpf_send_signal(9)` → **SIGKILL 즉시 전송**
- userspace 왕복 없는 커널 레벨 차단

### 어댑터
Native eBPF 외에도 다양한 이벤트 소스 지원:
- **Tetragon** — gRPC 스트리밍
- **Falco** — JSON 로그 파일 tail
- **auditd** — audit.log 파싱

### 기타
- **Kubernetes** — 네임스페이스/라벨 필터링, DaemonSet/Helm 배포
- **TUI** — ratatui 기반 실시간 대시보드 (이벤트 스트림, 통계, 설정 뷰어)
- **Headless 모드** — Docker/systemd에서 TTY 없이 로그 전용으로 동작

---

## 아키텍처

```
┌──────────────────────────────────────────────────────────────┐
│  이벤트 소스                                                   │
│  ┌─────────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐   │
│  │ Native eBPF │  │ Tetragon │  │ Falco  │  │  auditd   │   │
│  │ tracepoint  │  │  gRPC    │  │  JSON  │  │  textlog  │   │
│  │ + LSM hook  │  │ stream   │  │  tail  │  │  tail     │   │
│  └──────┬──────┘  └────┬─────┘  └───┬────┘  └─────┬─────┘   │
│         └──────────────┴────────────┴──────────────┘         │
│                        NormalizedEvent                        │
└────────────────────────────┬─────────────────────────────────┘
                             ▼
           ┌─────────────────────────────┐
           │  Scope Filter               │  프로세스 glob · 네임스페이스 · 라벨
           └──────────────┬──────────────┘
                          ▼
           ┌─────────────────────────────┐
           │  Fast Path  (동기, μs)      │  TOML 룰 → Block / Alert / Log
           └──────────────┬──────────────┘
                          ▼
           ┌─────────────────────────────┐
           │  Slow Path  (비동기, ms)    │  임베딩 → 컨텍스트 블렌딩 → Qdrant
           └──────────────┬──────────────┘
                          ▼
           ┌─────────────────────────────┐
           │  TUI / Headless Logger      │  ratatui 대시보드 or 로그 전용
           └─────────────────────────────┘

커널 레벨 차단 (Linux ≥5.7):
  eBPF HashMap ← Enforcer ← Fast Path block 룰
  트레이스포인트에서 bpf_send_signal(SIGKILL) 전송
```

---

## 요구 사항

| 항목 | 필수 | 선택 |
|------|------|------|
| **OS** | Linux (커널 ≥ 5.7) | Ubuntu 22.04 LTS 권장 |
| **권한** | root 또는 `CAP_SYS_ADMIN` | - |
| **Rust** | nightly 툴체인 | - |
| **bpf-linker** | `cargo install bpf-linker` | - |
| **CONFIG_BPF_LSM** | - | `=y` 이면 LSM 훅 활성화 |
| **Qdrant** | - | Slow Path 이상 탐지 사용 시 |

> macOS/Windows에서는 Docker Desktop을 통해 테스트할 수 있습니다. [테스트 섹션](#테스트) 참고.

---

## 빠른 시작

### 방법 1: Docker Compose (가장 간단)

```bash
git clone https://github.com/Cozymori/VectorGuard.git
cd VectorGuard
docker compose up -d
```

VectorGuard + Qdrant가 함께 시작됩니다. VectorGuard는 headless 모드(로그 전용)로 동작합니다.

```bash
# 로그 확인
docker compose logs -f vectorguard

# 중지
docker compose down -v
```

### 방법 2: 자동 설치 (Bare-Metal Linux)

```bash
git clone https://github.com/Cozymori/VectorGuard.git
cd VectorGuard
sudo bash install.sh
```

설치 스크립트가 자동으로 처리하는 것들:
- 시스템 패키지 설치 (clang, llvm, libelf-dev, protobuf-compiler 등)
- Rust nightly 툴체인 + bpf-linker 설치
- eBPF 프로그램 + 유저스페이스 데몬 빌드
- 설정 파일 (`/etc/vectorguard/config.toml`) 및 룰 파일 생성
- systemd 서비스 등록 및 시작
- Docker가 있으면 Qdrant 컨테이너 자동 시작

```bash
# 서비스 상태 확인
sudo systemctl status vectorguard

# 실시간 로그
sudo journalctl -u vectorguard -f

# 설정 수정 (hot reload 자동 적용)
sudo nano /etc/vectorguard/config.toml
```

### 방법 3: 수동 빌드

```bash
# 1. Rust nightly + bpf-linker 설치
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# 2. eBPF 커널 프로그램 빌드
cargo +nightly build -p vectorguard-ebpf \
  --target bpfel-unknown-none --release -Z build-std=core

# 3. 유저스페이스 데몬 빌드 (eBPF 바이너리를 include_bytes!로 임베드)
cargo build -p vectorguard --release

# 4. 실행 (root 필요)
sudo ./target/release/vectorguard --config vectorguard/config.toml
```

---

## 설정

설정 파일 위치:
- 개발: `vectorguard/config.toml`
- 프로덕션: `/etc/vectorguard/config.toml`

`hot_reload = true`이면 파일 저장 시 재시작 없이 500ms 이내 자동 반영됩니다.

```toml
[system]
log_level  = "info"     # debug | info | warn | error
hot_reload = true       # 설정 파일 변경 시 자동 리로드

[scope]
targets            = []   # 모니터링 대상 프로세스 glob (빈 배열 = 전체)
include_namespaces = []   # K8s 네임스페이스 필터 (빈 배열 = 전체)
exclude_namespaces = []   # 제외할 네임스페이스 (include보다 우선)
label_selectors    = []   # K8s 라벨 셀렉터 (예: ["env=production"])

[adapter]
backend = "native_ebpf"  # native_ebpf | tetragon | falco | auditd

[fast_path]
enabled        = true
rules_path     = "/etc/vectorguard/rules"   # 룰 파일 디렉토리
default_action = "log"                      # 매칭 룰 없을 때 기본 액션

[slow_path]
enabled              = true
time_window_secs     = 60     # PID별 행동 컨텍스트 윈도우 (초)
similarity_threshold = 0.85   # 코사인 유사도 임계값 (이하면 이상 탐지)

[slow_path.embedder]
backend     = "local"    # local | openai
model       = ""         # openai 사용 시: "text-embedding-ada-002"
api_key_env = ""         # API 키 환경변수 이름

[slow_path.vectordb]
backend    = "qdrant"
url        = "http://localhost:6333"
collection = "behaviors"

[tui]
refresh_rate_ms = 200
theme           = "dark"   # dark | light
```

### 어댑터별 추가 설정

```toml
# Tetragon gRPC 연동
[adapter.tetragon]
endpoint = "http://localhost:54321"

# Falco JSON 로그
[adapter.falco]
log_path = "/var/log/falco/events.json"

# auditd 로그
[adapter.auditd]
log_path = "/var/log/audit/audit.log"
```

---

## Fast Path 룰

`rules/` 디렉토리에 `.toml` 파일로 작성합니다. 파일 저장 시 hot reload로 즉시 반영됩니다.

### 룰 평가 방식
- 한 룰 안의 모든 조건은 **AND** 로직 (모두 매칭되어야 함)
- 룰 간 평가는 파일 순서대로 → **첫 번째 매칭 룰의 액션이 적용**
- `block` 룰은 eBPF HashMap에도 등록되어 커널에서 직접 차단

### 사용 가능한 조건

| 필드 | 타입 | 설명 | 예시 |
|------|------|------|------|
| `name` | string | 룰 이름 (로그에 표시) | `"block-shadow"` |
| `action` | string | `block` / `alert` / `log` / `allow` | `"block"` |
| `match_process` | [string] | 프로세스 이름 glob 매칭 | `["nginx", "py*"]` |
| `match_path_prefix` | [string] | 파일 접근 경로 prefix | `["/etc/shadow"]` |
| `match_exec_path` | [string] | 실행 파일 경로 prefix | `["/bin/sh"]` |
| `match_port` | [u16] | TCP 목적지 포트 | `[4444, 1337]` |
| `match_uid` | u32 | 프로세스 UID | `0` |

### 예시: 기본 제공 룰 (`rules/default.toml`)

```toml
# 민감 파일 접근 차단
[[rules]]
name              = "block-shadow-access"
action            = "block"
match_path_prefix = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"]

# 웹서버에서 쉘 실행 감지
[[rules]]
name            = "alert-webserver-shell"
action          = "alert"
match_process   = ["nginx", "apache2", "httpd", "php-fpm"]
match_exec_path = ["/bin/sh", "/bin/bash", "/bin/dash"]

# 리버스쉘 의심 포트 감지
[[rules]]
name       = "alert-suspicious-port"
action     = "alert"
match_port = [4444, 1337, 31337, 9001, 8888, 6666]

# root의 네트워크 도구 실행 감지
[[rules]]
name            = "alert-root-nettools"
action          = "alert"
match_uid       = 0
match_exec_path = ["/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc"]
```

### 커스텀 룰 추가 예시

```toml
# /etc/vectorguard/rules/my-rules.toml

# Python의 외부 연결 차단
[[rules]]
name          = "block-python-outbound"
action        = "block"
match_process = ["python3", "python"]
match_port    = [80, 443, 8080]

# 특정 UID의 SSH 키 접근 감시
[[rules]]
name              = "alert-ssh-key-access"
action            = "alert"
match_path_prefix = ["/root/.ssh/", "/home/"]
match_uid         = 1000
```

---

## Slow Path 이상 탐지

Fast Path에서 잡지 못하는 **알려지지 않은 공격 패턴**을 탐지합니다.

### 동작 원리

```
이벤트 발생
    │
    ▼
1. 임베딩 — 이벤트를 64차원 벡터로 변환
   (이벤트 타입, severity, UID, 바이너리명, 경로/포트 등)
    │
    ▼
2. 컨텍스트 블렌딩 — 해당 PID의 최근 행동 이력과 혼합
   (현재 이벤트 70% + 히스토리 30%)
    │
    ▼
3. 유사도 검색 — Qdrant에서 코사인 유사도 검색
   유사 패턴 있음 (≥ 0.85) → 정상
   유사 패턴 없음 (< 0.85) → 이상 탐지 → Alert 에스컬레이션
    │
    ▼
4. 저장 — 블렌딩된 벡터를 Qdrant에 upsert (향후 비교 기준)
```

### Qdrant 설정

```bash
# Docker로 Qdrant 실행
docker run -d --name qdrant -p 6333:6333 \
  -v qdrant_data:/qdrant/storage \
  qdrant/qdrant:v1.9.0

# 연결 확인
curl http://localhost:6333/healthz
```

Slow Path를 사용하지 않으려면 설정에서 비활성화:
```toml
[slow_path]
enabled = false
```

---

## 어댑터

VectorGuard는 다양한 이벤트 소스를 지원합니다. `[adapter]` 설정으로 선택합니다.

### Native eBPF (기본)

Linux에서 직접 트레이스포인트를 연결하고, eBPF 링 버퍼로 이벤트를 수신합니다.
커널이 `CONFIG_BPF_LSM=y`를 지원하면 LSM 훅도 자동 연결됩니다.

```toml
[adapter]
backend = "native_ebpf"
```

### Tetragon

[Tetragon](https://tetragon.io/) 에이전트에 gRPC로 연결합니다.
`ProcessExec`, `ProcessExit`, `ProcessKprobe` 이벤트를 스트리밍하며, 연결 끊김 시 5초 간격으로 자동 재연결합니다.

```toml
[adapter]
backend = "tetragon"

[adapter.tetragon]
endpoint = "http://localhost:54321"
```

### Falco

Falco의 JSON 출력 파일을 tail합니다.

```toml
[adapter]
backend = "falco"

[adapter.falco]
log_path = "/var/log/falco/events.json"
```

### auditd

auditd의 `SYSCALL` 레코드를 파싱합니다.

```toml
[adapter]
backend = "auditd"

[adapter.auditd]
log_path = "/var/log/audit/audit.log"
```

---

## Kubernetes 배포

DaemonSet으로 모든 노드에 배포합니다.

### 배포 방법

```bash
# Helm 차트
bash deploy-k8s.sh --adapter native_ebpf

# 네임스페이스 필터링
bash deploy-k8s.sh \
  --adapter native_ebpf \
  --include-ns production \
  --exclude-ns kube-system,monitoring

# raw 매니페스트
kubectl apply -f deploy/k8s/
```

### 필요 권한

DaemonSet은 eBPF 로드를 위해 다음 권한이 필요합니다:

```yaml
securityContext:
  capabilities:
    add: [SYS_ADMIN, BPF, PERFMON, NET_ADMIN, SYS_PTRACE]
```

init 컨테이너가 BPF 파일시스템을 자동 마운트하고, `/tmp/vectorguard.ready` 파일을 liveness probe로 사용합니다.

---

## 테스트

### Docker E2E 테스트 (macOS/Windows/Linux 모두 가능)

Docker Desktop만 있으면 됩니다. Linux 환경이 없어도 테스트할 수 있습니다.

```bash
# 테스트 이미지 빌드 (eBPF + 데몬을 컨테이너 안에서 빌드)
docker build -f Dockerfile.test -t vectorguard-test .

# E2E 테스트 실행
docker run --rm --privileged --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  vectorguard-test
```

#### 테스트 항목 (17개)

| 섹션 | 내용 |
|------|------|
| 0. Environment | BPF 파일시스템, tracepoint, BTF, LSM 확인 |
| 1. Binary | 바이너리, 설정 파일, 룰 파일 존재 확인 |
| 2. Startup | 데몬 기동, Ready 파일, 로그 메시지, LSM 훅, eBPF 에러 확인 |
| 3. Shadow | `/etc/shadow` 접근 이벤트 캡처 확인 |
| 4. Port | 의심 포트(4444, 1337) 연결 이벤트 감지 확인 |
| 5. Hot Reload | 설정 변경 시 자동 리로드 확인 |
| 6. Dynamic Rule | 룰 파일 추가 후 리로드 + nc 차단 확인 |
| 7. Liveness | 전체 테스트 후 데몬 생존 확인 |

#### 수동 테스트 (컨테이너 쉘 접속)

```bash
docker run --rm -it --privileged --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  --entrypoint bash vectorguard-test
```

### 유닛 테스트

```bash
# eBPF 없이 macOS/Linux 모두 가능
cargo test
```

### Ubuntu에서 전체 테스트

[TESTING.md](TESTING.md)에 Ubuntu 환경에서의 상세 테스트 가이드가 있습니다.

---

## 프로젝트 구조

```
VectorGuard/
│
├── vectorguard-common/          # 커널/유저스페이스 공유 타입 (no_std 호환)
│   └── src/lib.rs               #   RawEvent, EventKind, EventPayload
│
├── vectorguard-ebpf/            # eBPF 커널 프로그램 (nightly, bpfel-unknown-none)
│   ├── src/main.rs              #   트레이스포인트 핸들러 + LSM 훅
│   └── .cargo/config.toml       #   BPF 타겟/링커 설정
│
├── vectorguard/                 # 유저스페이스 데몬
│   ├── src/
│   │   ├── main.rs              #   진입점, 파이프라인 구성, hot reload
│   │   ├── collector.rs         #   eBPF 로더 + 링 버퍼 폴링 (Linux)
│   │   ├── enforcer.rs          #   eBPF 차단 맵 관리 (Linux)
│   │   ├── adapter/             #   Tetragon · Falco · auditd 어댑터
│   │   ├── fast_path/           #   TOML 룰 엔진
│   │   │   └── rules.rs         #     룰 파싱 · 매칭 · 평가
│   │   ├── slow_path/           #   벡터 임베딩 · 컨텍스트 윈도우 · Qdrant
│   │   ├── scope.rs             #   프로세스/네임스페이스 필터링
│   │   ├── hotreload.rs         #   설정 파일 감시
│   │   └── tui/                 #   ratatui 터미널 UI
│   ├── build.rs                 #   Proto codegen + eBPF 바이너리 임베딩
│   └── config.toml              #   개발용 기본 설정
│
├── rules/                       # Fast Path 룰 파일 (.toml)
│   └── default.toml             #   기본 제공 보안 룰 7개
│
├── deploy/
│   ├── k8s/                     #   Kubernetes raw 매니페스트
│   └── helm/vectorguard/        #   Helm 차트
│
├── Dockerfile                   # 프로덕션 Docker 이미지
├── Dockerfile.test              # E2E 테스트용 Docker 이미지
├── docker-compose.yml           # VectorGuard + Qdrant 구성
├── test_e2e_docker.sh           # Docker E2E 테스트 스크립트
├── install.sh                   # Bare-metal 자동 설치 스크립트
├── uninstall.sh                 # 제거 스크립트
├── deploy-k8s.sh                # K8s 배포 스크립트
└── TESTING.md                   # Ubuntu 테스트 가이드
```

### 이벤트 처리 흐름

```
커널 (eBPF)                         유저스페이스 (데몬)
─────────────                       ────────────────────
sys_enter_execve ──┐
sys_enter_openat ──┤── Ring Buffer ──→ collector.rs
sys_enter_connect ─┘                      │
                                          ▼
BLOCKED_COMMS ◄──── enforcer.rs ◄── fast_path/rules.rs
BLOCKED_PORTS                             │
BLOCKED_UIDS                              ▼
                                    slow_path/ (Qdrant)
                                          │
                                          ▼
                                    tui/ (대시보드 or 로그)
```

---

## 문제 해결

### eBPF 로드 실패

```
ERROR eBPF load failed: ...
```

- root로 실행했는지 확인: `sudo ./vectorguard ...`
- BPF 파일시스템 마운트 확인: `mount | grep bpf`
- 없으면: `sudo mount -t bpf bpf /sys/fs/bpf`

### LSM 훅 비활성화 경고

```
WARN LSM hook 'bprm_check_security' unavailable
```

- 정상 동작입니다. 트레이스포인트 기반 차단은 그대로 동작합니다.
- LSM까지 사용하려면: `cat /boot/config-$(uname -r) | grep BPF_LSM` 확인
- `CONFIG_BPF_LSM=y`이어야 LSM 훅이 활성화됩니다.

### Qdrant 연결 실패

```
WARN Slow Path: Qdrant connection failed
```

- Docker 확인: `docker ps | grep qdrant`
- 포트 확인: `curl http://localhost:6333/healthz`
- Slow Path 없이 쓰려면 설정에서 `enabled = false`

### 프로세스가 차단되지 않음

1. 룰의 `action`이 `"block"`인지 확인 (`alert`/`log`는 차단 안 함)
2. `match_process`의 이름이 실제 comm과 일치하는지 확인
   ```bash
   cat /proc/<pid>/comm   # 실제 커널이 보는 프로세스 이름
   ```
3. `log_level = "debug"`로 변경 후 로그에서 룰 매칭 여부 확인

### 로그가 없음

- `log_level = "debug"`로 변경 후 hot reload 대기
- systemd: `sudo journalctl -u vectorguard -n 50`
- Docker: `docker compose logs -f vectorguard`

### Docker E2E 테스트 실패

- Docker Desktop이 실행 중인지 확인
- `--privileged` 플래그가 있는지 확인
- Docker Desktop 설정에서 리소스(CPU/Memory)가 충분한지 확인

---

## 제거

```bash
# Bare-metal
sudo bash uninstall.sh

# Docker
docker compose down -v

# Kubernetes
bash deploy-k8s.sh --uninstall
# 또는
helm uninstall vectorguard
```

---

## 라이선스

MIT
