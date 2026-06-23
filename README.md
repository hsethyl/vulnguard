# vulnguard

소스코드의 취약점을 **탐지**하고, 안전한 코드로 **자동 보완**하는 Python CLI입니다.
화이트해커 학습 및 방어적 보안(자기 코드 점검)을 목적으로 합니다.

> ⚠️ 본인이 소유하거나 명시적으로 허가받은 코드/시스템에만 사용하세요.

## 기능

### 1. 정적 탐지 (`scan`)
- **Python 정적 분석 (AST 기반)**: `eval`/`exec`(PY001/2), `os.system`(PY003),
  `subprocess(shell=True)`(PY004), `pickle.load(s)`(PY005), `yaml.load`(PY006),
  약한 해시 md5/sha1(PY007), SQL 인젝션(PY008), TLS 검증 비활성 `verify=False`(PY009),
  `debug=True` 운영 서버(PY010), `extractall` 경로 탐색(PY011), `tempfile.mktemp`(PY012),
  Jinja2 `autoescape=False`(PY013), `0.0.0.0` 전체 인터페이스 바인딩(PY014)
- **Django 설정 분석**: 하드코딩 `SECRET_KEY`(DJ001), `ALLOWED_HOSTS=['*']`(DJ002),
  `DEBUG=True`(DJ003)
- **JavaScript/TypeScript (정규식 기반)**: `innerHTML`(JS001), `document.write`(JS002),
  `eval`(JS003), `new Function`(JS004), `child_process.exec`(JS005),
  `dangerouslySetInnerHTML`(JS006), 문자열 `setTimeout/setInterval`(JS007)
- **Go (정규식 기반)**: 셸 명령 주입 `exec.Command("sh",...)`(GO001), SQL 인젝션(GO002),
  약한 해시 md5/sha1(GO003), TLS 검증 비활성 `InsecureSkipVerify: true`(GO004)
- **Java (정규식 기반)**: `Runtime.exec`(JAVA001), SQL 문자열 결합(JAVA002),
  약한 해시 MD5/SHA-1(JAVA003), 안전하지 않은 역직렬화 `readObject`(JAVA004)
- **하드코딩 시크릿**: private key, AWS 키, `sk-`/GitHub/Slack 토큰, Google API 키, JWT
  (SEC001~005, SEC007/008) + 엔트로피 분석 기반 범용 시크릿 탐지(SEC006)
- **프로젝트 점검**: `.env` 등 시크릿 파일이 `.gitignore`로 보호되는지(PRJ001),
  이미 git에 추적/커밋됐는지(PRJ002) 확인
- **의존성 취약점**: `requirements.txt` / `package.json`을 오프라인 CVE DB와 대조,
  `--osv`로 **OSV.dev** 온라인 DB까지 확장(GHSA/PYSEC/CVE 전체 커버리지)

각 항목에 심각도(CRITICAL/HIGH/MEDIUM/LOW), 파일:줄, CWE, 수정 가이드가 표시됩니다.

### 2. 자동 보완 (`fix`)
동작을 보존하는 안전한 수정만 자동 적용합니다(나머지는 수동 권고):
- `yaml.load(x)` → `yaml.safe_load(x)`
- `verify=False` → `verify=True` (TLS 검증 복원)
- `debug=True` → `debug=False` (운영 디버그 서버 비활성)
- `autoescape=False` → `autoescape=True` (템플릿 이스케이프 복원)
- Go `InsecureSkipVerify: true` → `false` (TLS 검증 복원)
- 하드코딩 시크릿 → `os.environ["NAME"]` (필요 시 `import os` 추가, `.env.example` 생성)
- 취약 의존성 → 안전 버전으로 핀 업그레이드

기본은 **dry-run**(diff만 표시), `--apply`로 실제 적용하며 원본은 `*.vulnguard.bak`로 백업됩니다.

### 3. 동적 점검 (`dast`) — 수동(passive) 전용
실행 중인 웹사이트에 **일반 GET 요청 1회**만 보내 응답을 분석합니다(공격 페이로드 없음):
보안 헤더(HSTS/CSP/X-Frame-Options/nosniff), 쿠키 플래그(Secure/HttpOnly),
TLS 사용 여부, 소프트웨어 버전 노출(DAST001~008).

> 비로컬 호스트는 `--i-am-authorized` 플래그로 **명시적 권한 확인**을 요구합니다.

## 사용법

```bash
# 정적 스캔
python -m vulnguard scan <경로>
python -m vulnguard scan <경로> --osv                          # OSV.dev 온라인 보강
python -m vulnguard scan <경로> --format sarif -o report.sarif # GitHub code scanning 호환
python -m vulnguard scan <경로> --fail-on HIGH                 # CI: HIGH 이상이면 exit 2

# 자동 수정
python -m vulnguard fix <경로>            # dry-run (diff 미리보기)
python -m vulnguard fix <경로> --apply    # 적용 + 백업

# 동적 점검 (passive)
python -m vulnguard dast http://localhost:8000              # 로컬은 플래그 불필요
python -m vulnguard dast https://my-site.com --i-am-authorized
```

## 설정 (`.vulnguard.toml`, 선택)

프로젝트 루트에 두면 규칙/경로를 끄거나 기본 임계값을 정할 수 있습니다.

```toml
[ignore]
rules = ["PY007", "DAST003"]      # 특정 규칙 끄기
paths = ["legacy/", "*.min.js"]   # 파일/폴더 제외 (glob)

[scan]
fail_on = "HIGH"                  # --fail-on 기본값 (CLI 플래그가 우선)
```

## CI / pre-commit 통합 (shift-left)

커밋·PR 단계에서 자동으로 막습니다.

**pre-commit** — 스테이징된 파일을 커밋 직전 검사 (HIGH 이상이면 커밋 차단):
```bash
pip install pre-commit
pre-commit install          # .pre-commit-config.yaml 사용 (이 저장소 자체 검사)
```

**GitHub Actions** — `.github/workflows/vulnguard.yml`가 push/PR마다 실행:
- `--osv`로 의존성까지 검사하고 **SARIF**를 GitHub code scanning 탭에 업로드
- HIGH 이상 발견 시 빌드 실패(`--fail-on HIGH`)

> `scan`은 여러 경로를 받습니다: `vulnguard scan a.py b.js src/` (pre-commit 호환)

## 데모

```bash
python -m vulnguard scan examples/vulnerable_app          # 오프라인
python -m vulnguard scan examples/vulnerable_app --osv    # OSV.dev 보강
python -m vulnguard fix  examples/vulnerable_app          # dry-run
```

## 개발 / 테스트

```bash
python -m pip install pytest
python -m pytest -q        # 104 tests
```

## 구조

```
vulnguard/
  cli.py                 # 진입점 (scan / fix / dast)
  engine.py              # 디렉터리 순회 + 스캐너 디스패치 + OSV 보강
  models.py              # Finding / ScanResult (immutable)
  scanner/               # python · js · go · java · secret · dependency · project · osv_client
  fixers/                # line_fixes · dependency_fixes · engine (백업/diff/.env)
  dast/                  # analyzer(순수 헤더 분석) · client(네트워크 + 권한 게이트)
  config.py              # .vulnguard.toml 로더 (규칙/경로 제외)
  report/                # console · json · sarif
  data/vuln_db.py        # 오프라인 CVE 샘플 DB
tests/                   # 규칙별 탐지/오탐/수정 테스트 (104개)
.github/workflows/       # GitHub Actions 보안 스캔 (SARIF 업로드 + fail-on)
.pre-commit-hooks.yaml   # 다른 저장소에서 pre-commit 훅으로 사용
.pre-commit-config.yaml  # 자체 저장소 dogfooding 훅
```

## 한계 / 설계 노트
- 정적 분석이므로 런타임 동작은 보지 않습니다(오탐/미탐 가능).
- 오프라인 의존성 DB는 큐레이션 샘플입니다. 전체 커버리지는 `--osv`(네트워크) 사용.
- DAST는 **수동 점검만** 수행하며 공격 페이로드를 보내지 않습니다. 능동 스캐닝은
  법적 책임이 크므로 의도적으로 제외했습니다.
```
