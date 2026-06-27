# Honeypot · Intercept Console

> SSH·TCP로 접속한 공격자에게 진짜 같은 가짜 셸을 보여주고, 입력하는 모든 명령과 자격증명을 기록·분석하는 허니팟입니다.
> 공격자의 행동 흐름(정찰 → 파일 접근 → 다운로드 → 권한 상승)을 실시간 웹 콘솔로 관찰할 목적으로 만들었습니다.

**작성자** 이정원 · **분야** 네트워크 보안

> ⚠️ **격리된 환경 전용** — 이 프로그램은 의도적으로 공격자를 유인하고 가짜 셸을 노출합니다. 실제 서비스망이나 중요한 데이터가 있는 호스트가 아니라, 격리된 VM·실습용 네트워크에서만 실행하세요. 트랩 서버는 `0.0.0.0`(7777·2222)에 바인딩되어 같은 네트워크에서 접근 가능하며, 관리용 대시보드(5000)는 외부에 노출하지 마세요.

---

## 데모

![데모](docs/demo.gif)

> 왼쪽에서 공격자가 셸에 명령을 입력하면, 오른쪽 콘솔에 세션과 명령이 실시간으로 나타나고 위협 단계가 올라갑니다.

---

## 주요 기능

- **두 갈래의 트랩 서버** — 원시 TCP(7777)와 SSH(2222) 양쪽으로 접속을 받아, 어떤 아이디·비밀번호를 넣어도 로그인에 성공시켜 셸로 유도
- **가짜 셸** — `whoami`·`ls`·`cat`·`wget`·`su` 등 실제처럼 반응하는 명령 에뮬레이션. `su`로 root 승격 시 프롬프트가 `#`로 바뀌고 권한별 출력이 달라짐
- **전 키스트로크 기록** — 로그인 자격증명·실행 명령·접속 종료를 JSONL로 영구 저장
- **실시간 인터셉트 콘솔** — 활성 세션·명령 스트림·위협 단계를 2초 주기로 갱신하고, 명령은 카테고리(정찰/파일/다운로드/권한상승)별로 색상 구분
- **세션 리플레이** — 명령 행을 클릭하면 해당 세션의 자격증명과 전체 명령 타임라인을 패널로 재생
- **검색** — 라이브 버퍼 즉시 필터 + Enter로 전체 로그(세션 ID·IP·계정·명령) 검색
- **오프라인 분석 도구** — 위협 분류(analyzer), 통계(stats), 터미널 세션 리플레이(replay) CLI

---

## 실행 방법

```bash
# 1. 의존성 설치
pip install -r requirements.txt   # flask, paramiko

# 2. SSH 호스트 키 생성 (최초 1회)
python generate_key.py

# 3. 허니팟 실행 (대시보드 + TCP + SSH 동시 기동)
python main.py
```

대시보드: `http://127.0.0.1:5000`

공격자 입장에서 접속 테스트:

```bash
# TCP 트랩 — 아이디·비밀번호 입력 후 셸 진입
nc 127.0.0.1 7777

# SSH 트랩 — 아무 비밀번호나 통과
ssh anyuser@127.0.0.1 -p 2222
```

오프라인 분석 (누적된 로그 대상):

```bash
PYTHONPATH=. python analysis/analyzer.py        # 위협 분류 요약
PYTHONPATH=. python analysis/stats.py           # IP·계정·비밀번호·명령 통계
PYTHONPATH=. python analysis/replay.py          # 전체 세션 리플레이
PYTHONPATH=. python analysis/replay.py <세션ID>  # 특정 세션만
```

> 분석 스크립트는 루트의 `config.py` 경로 설정과 `analysis/util.py`를 함께 참조하므로, 프로젝트 루트에서 `PYTHONPATH=.`를 지정해 실행합니다.

---

## 동작 원리

### 1. 두 갈래의 트랩 서버

TCP 서버(`tcp_server.py`)는 7777 포트에서 접속을 받아 `username:`·`password:`를 평문으로 물어보고, SSH 서버(`ssh_server.py`)는 paramiko로 2222 포트에 가짜 SSH 데몬을 띄웁니다. SSH의 `check_auth_password`는 입력값을 그대로 기록한 뒤 **항상 인증 성공**을 반환해, 어떤 크리덴셜이든 통과시켜 셸로 넘깁니다. 각 접속은 `uuid`로 세션 ID를 부여받고 별도 스레드에서 처리됩니다.

### 2. 가짜 셸

두 서버 모두 접속이 확립되면 공통 `fake_shell()`로 넘어갑니다. 셸은 한 줄씩 입력을 받아 첫 토큰을 명령으로 해석하고 미리 정의된 응답을 돌려줍니다. SSH는 한 글자씩 받아 백스페이스·에코까지 처리하고, TCP는 줄 단위로 받습니다.

- `su`는 비밀번호를 받은 뒤 root 권한을 부여 → 프롬프트가 `$`에서 `#`로 바뀌고 `whoami`·`id` 출력이 root로 변경됨
- `sudo`는 항상 실패시켜 공격자가 다른 경로를 시도하도록 유도
- `wget`·`curl`은 `DELAY`초(기본 15초) 대기 후 연결 실패 메시지를 띄워, 외부 다운로드 시도를 시간만 끌며 차단
- `cat flag.txt` 같은 미끼 파일에는 가짜 플래그(`CTF{fake_flag}`)를 반환

### 3. 기록 계층

`attack_logger.py`가 세 종류의 이벤트를 JSON Lines로 추가 기록합니다.

- `credentials.jsonl` — 로그인 시도(세션 ID·IP·계정·비밀번호·시각·프로토콜)
- `commands.jsonl` — 실행된 모든 명령
- `session.jsonl` — 접속 종료

JSONL은 한 줄에 한 이벤트라 실시간 append와 후처리(스트리밍 파싱) 양쪽에 유리합니다.

### 4. 실시간 상태 공유

대시보드와 트랩 서버는 같은 프로세스 안의 스레드이므로, 공유 상태(`state.py`)로 데이터를 주고받습니다. `active_connection` 딕셔너리는 현재 살아 있는 세션을, `recent_commands`(maxlen 10 deque)는 최근 명령 버퍼를 담으며, 모든 접근은 `state_lock`으로 보호됩니다. 셸이 명령을 처리할 때마다 이 버퍼에 push 합니다.

### 5. 대시보드 API

Flask(`routes.py`)가 콘솔에 데이터를 공급합니다. `/connections`·`/recent_commands`는 공유 상태를 그대로 내보내고, `/session/<id>`는 디스크 로그에서 해당 세션의 자격증명과 명령 전체를 모아 리플레이용으로 반환하며, `/history`는 `q`(부분일치) 또는 `session`·`ip`·`username`(정확 일치)으로 전체 로그를 검색합니다.

### 6. 인터셉트 콘솔 (프론트엔드)

콘솔은 2초마다 `/connections`·`/recent_commands`를 폴링해 세션 레일과 명령 스트림을 갱신합니다. 각 명령은 백엔드 분석기와 동일한 분류 체계(정찰/파일/다운로드/권한상승)로 색을 입히고, 버퍼 내 최고 위험 카테고리로 위협 단계(Calm → Critical)를 산출합니다. 명령을 클릭하면 `/session/<id>`로 세션 리플레이 패널이 열리고, 검색창은 버퍼 즉시 필터와 `/history` 전체 검색을 함께 제공합니다. 공격자가 제어하는 값(계정·명령·IP)은 모두 `textContent`로만 삽입해 XSS를 차단합니다.

### 7. 오프라인 분석

`analyzer.py`는 누적된 명령 로그를 정찰·파일 접근·다운로드·권한 상승으로 분류해 위협 요약을 출력하고, `stats.py`는 가장 많이 등장한 IP·계정·비밀번호·명령을 집계하며, `replay.py`는 터미널에서 세션을 시간순으로 재생합니다.

---

## 프로젝트 구조

```
honeypot/
├── main.py               # 대시보드·TCP·SSH 스레드 기동
├── config.py             # 포트·경로·딜레이 설정
├── generate_key.py       # SSH 호스트 키 생성
├── server/
│   ├── app.py            # Flask 앱
│   ├── routes.py         # 대시보드 API
│   ├── state.py          # 스레드 공유 상태
│   ├── shell.py          # 가짜 셸 에뮬레이터
│   ├── tcp_server.py     # TCP 트랩 (7777)
│   ├── ssh_server.py     # SSH 트랩 (2222)
│   └── server.key        # SSH 호스트 키 (자동 생성)
├── logger/
│   ├── attack_logger.py  # JSONL 기록
│   └── *.jsonl           # 자격증명·명령·세션 로그 (자동 생성)
├── analysis/
│   ├── util.py           # 로그 로더·출력 헬퍼
│   ├── analyzer.py       # 위협 분류
│   ├── stats.py          # 통계
│   └── replay.py         # 세션 리플레이
├── templates/
│   └── index.html        # 인터셉트 콘솔
└── static/
    ├── style.css
    └── script.js
```

---

## 기술 스택

**Backend** Python · Flask · paramiko · socket · threading

**Frontend** HTML · CSS · JavaScript (Fetch API)

**기록·분석** JSON Lines · Counter 기반 집계

**핵심 개념** SSH/TCP 프로토콜 에뮬레이션 · 멀티스레드 소켓 서버 · 공유 상태 동기화 · 실시간 폴링 대시보드

---

## 개발 노트

트랩 서버(TCP·SSH 소켓 처리, 가짜 셸 로직, 세션 관리)와 기록·분석 계층, 대시보드 백엔드 API는 동작 원리를 학습하며 직접 구현했습니다. 프론트엔드(인터셉트 콘솔 UI)는 AI 도구의 도움을 받아 구성했습니다.
