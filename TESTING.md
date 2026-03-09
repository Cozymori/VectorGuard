# VectorGuard 테스트 가이드 (Ubuntu)

## 권장 환경

| 항목 | 최소 | 권장 |
|---|---|---|
| OS | Ubuntu 20.04 | Ubuntu 22.04 LTS |
| 커널 | 5.7 | 5.15+ |
| RAM | 2 GB | 4 GB |
| 디스크 | 10 GB | 20 GB |
| 권한 | root / sudo | root |

> Ubuntu 22.04 기본 커널은 5.15로 모든 기능 지원.
> `uname -r` 로 버전 확인.

---

## 1단계: Ubuntu 준비

### 커널 및 BPF 지원 확인

```bash
uname -r
# 5.15.x 또는 그 이상이어야 함

# eBPF LSM 지원 여부 확인 (있으면 proactive 차단 가능)
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF"
# CONFIG_BPF_LSM=y          → LSM hook 사용 가능
# CONFIG_DEBUG_INFO_BTF=y   → BTF 타입 정보 사용 가능
```

> Ubuntu 22.04는 두 옵션 모두 기본 활성화되어 있음.
> 없다면 eBPF LSM이 비활성화 상태로 시작되고, 트레이스포인트 기반 차단만 동작함 (기능 제한은 없음).

### BPF 파일시스템 확인

```bash
mount | grep bpf
# bpf on /sys/fs/bpf type bpf ... 가 보여야 함

# 없으면 수동 마운트
sudo mount -t bpf bpf /sys/fs/bpf
```

---

## 2단계: 설치

### 자동 설치 (권장)

```bash
git clone https://github.com/Cozymori/VectorGuard.git
cd VectorGuard
sudo bash install.sh
```

설치 스크립트가 자동으로:
- 시스템 패키지 설치 (clang, llvm, libelf-dev, protobuf-compiler 등)
- rustup 설치 및 nightly 툴체인 설정
- bpf-linker 설치
- eBPF + 유저스페이스 데몬 빌드
- 설정 파일 `/etc/vectorguard/config.toml` 생성
- 룰 파일 `/etc/vectorguard/rules/` 설치
- systemd 서비스 등록 및 시작
- Docker가 있으면 Qdrant 컨테이너 자동 시작

### 수동 빌드 (소스 수정하면서 테스트할 때)

```bash
# 의존성
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev pkg-config protobuf-compiler \
  linux-headers-$(uname -r) curl git

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install nightly --component rust-src

# bpf-linker
cargo install --locked bpf-linker

# 빌드
cd VectorGuard
cargo +nightly build -p vectorguard-ebpf \
  --target bpfel-unknown-none --release -Z build-std=core

cargo build -p vectorguard --release

# 실행 (root 필요)
sudo ./target/release/vectorguard --config vectorguard/config.toml
```

---

## 3단계: 설정 확인

```bash
# 설치 후 설정 파일 위치
cat /etc/vectorguard/config.toml
```

테스트용 권장 설정 (`/etc/vectorguard/config.toml` 또는 `vectorguard/config.toml`):

```toml
[system]
log_level  = "debug"    # 테스트 중에는 debug로 설정
hot_reload = true

[scope]
targets            = []   # 모든 프로세스 모니터링
include_namespaces = []
exclude_namespaces = []
label_selectors    = []

[adapter]
backend = "native_ebpf"   # eBPF 직접 사용

[fast_path]
enabled        = true
rules_path     = "/etc/vectorguard/rules"
default_action = "log"

[slow_path]
enabled              = true
time_window_secs     = 60
similarity_threshold = 0.85

[slow_path.embedder]
backend = "local"

[slow_path.vectordb]
backend    = "qdrant"
url        = "http://localhost:6333"
collection = "behaviors"

[tui]
refresh_rate_ms = 200
theme           = "dark"
```

---

## 4단계: 서비스 시작 및 로그 확인

```bash
# systemd로 설치했을 때
sudo systemctl status vectorguard
sudo journalctl -u vectorguard -f

# 수동 실행 (TUI 모드)
sudo ./target/release/vectorguard --config vectorguard/config.toml
```

### 정상 시작 로그 (이것들이 보이면 OK)

```
INFO  VectorGuard starting | adapter=NativeEbpf
INFO  LSM hook 'bprm_check_security' attached (lsm_exec)     ← BPF LSM 활성화됨
INFO  LSM hook 'file_open' attached (lsm_file_open)
INFO  Fast Path rules loaded: 4 rule(s)
INFO  Slow Path initialized (Qdrant connected)               ← Qdrant 연결됨
INFO  Ready (/tmp/vectorguard.ready)
```

> `WARN LSM hook unavailable` 이 뜨면 BPF LSM이 커널에서 비활성화된 것.
> 트레이스포인트 기반 차단은 여전히 동작하므로 테스트는 계속 가능.

---

## 5단계: 기능별 테스트

### [테스트 1] Fast Path — 민감 파일 차단

**내용:** `/etc/shadow` 접근 시 block 룰이 동작하는지 확인.

```bash
# 터미널 A: 로그 모니터링
sudo journalctl -u vectorguard -f
# 또는 수동 실행 중이면 TUI에서 바로 확인 가능

# 터미널 B: 차단될 명령 실행
sudo cat /etc/shadow
```

**기대 결과:**
- `action = "block"` 룰이면: `cat` 프로세스가 즉시 종료됨 (SIGKILL)
- 로그: `WARN  block-shadow-access | pid=XXXX binary=cat path=/etc/shadow action=Blocked`

---

### [테스트 2] Fast Path — 웹서버 → 쉘 실행 감지

**내용:** 웹서버 프로세스(nginx 등)가 bash를 실행하면 alert 발생.

```bash
# nginx 설치 (없다면)
sudo apt-get install -y nginx

# nginx 권한으로 bash 실행 (공격 시뮬레이션)
sudo -u www-data /bin/bash -c "id"
```

**기대 결과:**
```
WARN  alert-webserver-shell | pid=XXXX binary=bash action=Alerted severity=High
```

---

### [테스트 3] Fast Path — 의심 포트 연결 감지

**내용:** 리버스쉘에서 자주 쓰는 포트(4444, 1337 등)로 연결 시도.

```bash
# 리스너 없어도 연결 시도만으로 이벤트 발생
nc -w 1 127.0.0.1 4444 2>/dev/null; true
nc -w 1 127.0.0.1 1337 2>/dev/null; true
```

**기대 결과:**
```
WARN  alert-suspicious-port | pid=XXXX binary=nc port=4444 action=Alerted
```

---

### [테스트 4] eBPF 커널 레벨 차단 (block 룰)

**내용:** eBPF 블로킹 맵에 등록된 프로세스를 실행하면 커널이 직접 SIGKILL.

먼저 테스트용 룰 파일 추가:

```bash
sudo tee /etc/vectorguard/rules/test.toml << 'EOF'
[[rules]]
name          = "test-block-netcat"
action        = "block"
match_process = ["nc", "ncat", "netcat"]
EOF
```

설정이 hot_reload = true 이면 자동 반영 (약 500ms). 아니면 재시작:

```bash
sudo systemctl reload-or-restart vectorguard
```

```bash
# 이제 실행하면 즉시 강제 종료됨
nc -l 9999
# Killed   ← 커널이 SIGKILL 전송
```

**기대 결과:**
- 프로세스가 즉시 `Killed` 메시지와 함께 종료
- 로그: `INFO  test-block-netcat | action=Blocked`

테스트 후 룰 삭제:

```bash
sudo rm /etc/vectorguard/rules/test.toml
```

---

### [테스트 5] Hot Reload

**내용:** 설정 파일 저장 시 재시작 없이 즉시 반영되는지 확인.

```bash
# 터미널 A: 로그 모니터링
sudo journalctl -u vectorguard -f

# 터미널 B: default_action을 alert으로 변경
sudo sed -i 's/default_action = "log"/default_action = "alert"/' \
  /etc/vectorguard/config.toml
```

**기대 결과 (500ms 이내):**
```
INFO  Hot reload detected: /etc/vectorguard/config.toml
INFO  Pipeline reloading with new config
INFO  Fast Path rules loaded: 4 rule(s)
```

되돌리기:

```bash
sudo sed -i 's/default_action = "alert"/default_action = "log"/' \
  /etc/vectorguard/config.toml
```

---

### [테스트 6] Slow Path — Qdrant 연동

**내용:** 처음 보는 이벤트는 anomaly로 분류, 반복되면 정상으로 분류.

```bash
# Qdrant 실행 (Docker 사용)
docker run -d --name qdrant -p 6333:6333 \
  -v qdrant_data:/qdrant/storage \
  qdrant/qdrant:v1.9.0

# 연결 확인
curl http://localhost:6333/collections/behaviors
# {"result":{"name":"behaviors",...}}  ← 컬렉션이 생성되어 있어야 함
```

```bash
# 터미널 B: 반복 이벤트 발생
for i in $(seq 1 5); do
  ls /tmp > /dev/null
  sleep 1
done
```

**기대 결과:**
- 처음 1~2번: `slow_path: no similar behavior → escalating` (새로운 패턴)
- 3번 이후: `slow_path: similar behavior (0.9X) → normal` (학습된 패턴)

---

### [테스트 7] TUI 대화형 모드

수동 실행 중일 때 터미널에서 확인:

```
키 조작:
  q       → 종료
  ↑ ↓     → 이벤트 목록 스크롤
  Tab     → 패널 전환 (Events / Stats / Config)
```

패널 설명:
- **Events**: 실시간 이벤트 스트림 (색상: 빨강=Blocked, 노랑=Alerted, 흰색=normal)
- **Stats**: 이벤트 타입별 카운트, 차단/경고/허용 합계
- **Config**: 현재 로드된 config.toml 내용

---

## 6단계: 룰 커스터마이징

`/etc/vectorguard/rules/` 에 `.toml` 파일 추가하면 hot reload로 즉시 반영.

### 예시: 특정 프로세스 전체 차단

```toml
# /etc/vectorguard/rules/my-rules.toml
[[rules]]
name          = "block-python-outbound"
action        = "block"
match_process = ["python3", "python"]
match_port    = [80, 443, 8080]
```

### 예시: UID 0 (root) 의 외부 연결 감시

```toml
[[rules]]
name       = "alert-root-outbound"
action     = "alert"
match_uid  = 0
match_port = [80, 443, 8080, 8443]
```

### 예시: 특정 경로 접근 감시

```toml
[[rules]]
name              = "alert-private-key-access"
action            = "alert"
match_path_prefix = ["/home/", "/root/"]
match_exec_path   = ["/bin/bash", "/usr/bin/scp", "/usr/bin/rsync"]
```

룰 저장 후 hot reload 확인:

```bash
sudo journalctl -u vectorguard -f | grep "rules loaded"
# Fast Path rules loaded: N rule(s)   ← N이 늘어나야 함
```

---

## 문제 해결

### eBPF 로드 실패
```
ERROR eBPF load failed: ...
```
→ root로 실행했는지 확인: `sudo ./vectorguard ...`
→ BPF 파일시스템 마운트 확인: `mount | grep bpf`

### LSM hook 비활성화 경고
```
WARN LSM hook 'bprm_check_security' unavailable (kernel may lack CONFIG_BPF_LSM)
```
→ 정상 동작 (트레이스포인트 기반 차단은 그대로 동작)
→ LSM까지 쓰려면: `cat /boot/config-$(uname -r) | grep BPF_LSM` 확인

### Qdrant 연결 실패
```
WARN Slow Path: Qdrant connection failed
```
→ Docker 확인: `docker ps | grep qdrant`
→ 포트 확인: `curl http://localhost:6333/healthz`
→ slow_path를 끄려면 config에서 `enabled = false`

### 프로세스가 차단되지 않음
→ 룰의 `action`이 `"block"` 인지 확인 (alert/log는 차단 안 함)
→ `match_process`에 프로세스 이름이 정확한지 확인 (`ps aux`로 comm 이름 확인)
→ `sudo cat /proc/<pid>/comm` 으로 실제 comm 이름 확인

### 로그가 없음
→ `log_level = "debug"` 로 변경 후 hot reload
→ `sudo journalctl -u vectorguard -n 50`

---

## 체크리스트 요약

```
[ ] uname -r → 5.15 이상
[ ] CONFIG_BPF_LSM=y 확인
[ ] sudo bash install.sh 성공
[ ] systemctl status vectorguard → active (running)
[ ] 로그에 "Ready (/tmp/vectorguard.ready)" 확인
[ ] 로그에 "Fast Path rules loaded: 4 rule(s)" 확인
[ ] cat /etc/shadow → Blocked 로그 확인
[ ] nc 4444 연결 시도 → alert-suspicious-port 로그 확인
[ ] config.toml 수정 → 500ms 내 "Pipeline reloading" 로그 확인
[ ] Qdrant 연결 → "Slow Path initialized" 확인
[ ] block 룰 추가 → 해당 프로세스 Killed 확인
```
