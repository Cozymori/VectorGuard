# VectorGuard 작업 인수인계 문서

## 1. 현재 상태

### 완료된 작업
- Ubuntu 24.04 LTS ARM64 (UTM VM, kernel 6.8.0-101-generic) 에서 설치 및 동작 확인
- install.sh 통해 전체 설치 완료 (systemd 서비스 등록)
- eBPF 프로그램 빌드 성공 (bpf-linker 0.10.2, nightly toolchain)
- TUI 대폭 개선 (아래 상세)

### TUI 개선 내용 (커밋 예정)
파일: `vectorguard/src/tui/app.rs`, `event.rs`, `render.rs`, `mod.rs`

추가된 기능:
1. **배경 투명 문제 수정** - `terminal.clear()` + 전체 배경 Black Block
2. **탭 4 - Process Tree** - 감지된 프로세스 목록, 부모-자식 트리 구조, 이벤트 수 표시
3. **이벤트 상세 팝업** - Events 탭에서 Enter → PID/PPID/UID/Process/Event/Severity/Action 상세 표시
4. **필터링** - `/` 키로 검색창 열기, process명·path·action으로 실시간 필터
5. **키 힌트 footer** - 현재 모드에 따라 동적으로 변경 (normal / filtering / popup)
6. **색상 구분** - Blocked=Red, Alert=Yellow, Allowed=Green

키 바인딩:
- `Tab` / `1-4`: 탭 전환
- `↑↓` / `jk`: 스크롤
- `Enter`: 이벤트 상세 팝업 열기
- `/`: 필터 입력 모드
- `Esc`: 팝업/필터 닫기
- `q`: 종료

## 2. 미해결 이슈: eBPF degraded mode

### 증상
새로 빌드한 바이너리에서 `error parsing ELF data` 발생:
```
ERROR vectorguard: eBPF load failed: Failed to load eBPF: error parsing BPF object: error parsing ELF data: error parsing ELF data
WARN vectorguard: Event source closed — running in degraded mode (no events)
```

### 현황
- install.sh로 설치된 원본 바이너리: **정상 작동** (이벤트 수집 확인)
- `/tmp/vectorguard-src`에서 새로 빌드한 바이너리: **degraded mode** (이벤트 없음)
- TUI 자체는 정상 (배경, 탭 4개, 필터, 상세 팝업 모두 동작)

### 조사 내용
- eBPF 바이너리 자체는 유효한 ELF (objdump으로 확인, sections 정상)
- BTF 섹션 없음 (bpf-linker --btf 플래그 적용 시도했으나 효과 없음)
- aya 0.13.1 + aya-ebpf 0.1.1 사용 (버전 미스매치 이슈는 이전에 수정됨)
- .cargo/config.toml 의 rustflags 원상복구 후에도 동일 오류

### 원인 추정
install.sh가 github clone해서 빌드한 것과 로컬 tarball 빌드 간 차이.
eBPF 섹션명이 `tracepoint` (단일 섹션) 으로 합쳐져 있고 개별 `tracepoint/handle_exec` 등으로 분리되지 않는 것이 aya 파싱 실패 원인일 수 있음.

### 임시 해결방법
1. VM에서 install.sh를 다시 실행하면 원본 빌드가 복원됨
2. 또는: install.sh로 빌드한 후, eBPF 바이너리는 그대로 두고 daemon만 재빌드

### 다음 시도할 것
1. install.sh 실행 후 eBPF 바이너리를 `/tmp/`에 백업
2. 백업한 eBPF 바이너리를 `target/bpfel-unknown-none/release/vectorguard-ebpf`에 복사
3. daemon만 재빌드: `cargo build -p vectorguard --release`
4. 빌드된 daemon 설치

## 3. VM 접속 정보
- IP: 192.168.65.2
- User: spring / Password: wjsansrk
- SSH: `sshpass -p "wjsansrk" ssh -o PreferredAuthentications=password spring@192.168.65.2`
- sudo로 접근 가능

## 4. VM 설치 경로
- 바이너리: `/usr/local/bin/vectorguard`
- 설정: `/etc/vectorguard/config.toml`
- 룰: `/etc/vectorguard/rules/default.toml`
- 서비스: `systemctl status vectorguard`
- 로그: `journalctl -u vectorguard -f`

## 5. 빌드 명령어 (VM에서)
```bash
source /root/.cargo/env
cd /tmp/vectorguard-src

# eBPF 빌드
cargo +nightly build -p vectorguard-ebpf --target bpfel-unknown-none --release -Z build-std=core

# daemon 빌드
cargo build -p vectorguard --release

# 설치
sudo cp target/release/vectorguard /usr/local/bin/vectorguard
sudo systemctl restart vectorguard
```

## 6. 커밋 필요한 변경사항
```
vectorguard/src/tui/app.rs    - ProcessNode, InputMode, filtered_events, process_tree_rows 추가
vectorguard/src/tui/event.rs  - 팝업/필터 모드 키 처리
vectorguard/src/tui/render.rs - Process Tree 탭, 이벤트 상세 팝업, 필터 검색창
vectorguard/src/tui/mod.rs    - terminal.clear() 추가
```
