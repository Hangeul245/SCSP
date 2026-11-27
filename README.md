# SCSP - Source Code Security Parser

Taint Analysis 기반 실시간 취약점 탐지 VSCode Extension.  
기본은 웹 입력만 추적하고, 설정으로 명령줄 인자, 파일, HTTP 응답, LLM 응답까지 넓힐 수 있습니다.  
코드 수정 시 자동 분석 후 Problems 패널에 결과를 표시합니다.

---

## 탐지 취약점

취약점 종류는 입력이 도착한 위험 함수(sink)로 정해집니다.

| 코드 | 취약점 | JS/TS sink 예 | Python sink 예 |
|------|--------|---------------|----------------|
| `sqli` | SQL Injection | `db.query`, `pool.query` | `cursor.execute`, `raw` |
| `xss` | Cross-Site Scripting | `res.send`, `res.write`, `eval` | `render_template_string`, `Markup` |
| `cmdi` | Command Injection, 코드 실행 | `exec`, `execSync`, `spawn` | `os.system`, `subprocess.*`, `eval`, `exec`, `pickle.loads`, `yaml.load` |
| `path` | Path Traversal | `readFile`, `createReadStream` | `open`, `shutil.move/copy`, `os.remove`, `os.replace`, `extractall` |
| `ssrf` | Server-Side Request Forgery | `fetch`, `axios.get` | `requests.get`, `urlopen`, `httpx.get` |
| `redirect` | Open Redirect | `res.redirect` | `redirect` |

---

## 출처 프로필

어떤 입력을 오염으로 볼지는 프로필로 정합니다. 기본은 `web`만 켜져 있습니다.

| 프로필 | 출처 | 지원 언어 | 주로 잡히는 경우 |
|--------|------|-----------|------------------|
| `web` (기본) | Express `req.query/body/params`, Flask `request.args/form`, Tornado `get_argument` | JS/TS, Python | 웹 취약점 6종 전부 |
| `cli` | `sys.argv`, `argparse`, `input()` | Python | 인자로 받은 경로로 파일 이동, 삭제(`path`), 인자를 셸 명령에 넣기(`cmdi`) |
| `file` | 파일 내용, 압축 파일 안 이름, 폴더 안 파일 이름 | Python | 압축 파일 안 이름으로 경로 만들기(zip slip, `path`), 파일 내용 역직렬화(`cmdi`) |
| `network` | `requests`, `httpx`, `urlopen` 응답 | Python | 응답 내용을 명령이나 경로에 쓰기 |
| `llm` | Ollama, OpenAI, Anthropic 응답 | Python | LLM 응답을 `exec`하거나 명령에 넣기(`cmdi`) |

```json
{ "taintGuard.sourceProfiles": ["web", "cli", "file", "network", "llm"] }
```

`cli`를 켜면 명령줄 프로그램이 인자로 받은 경로를 쓰는 곳마다 경고가 납니다. 의도된 동작이면 무시해도 됩니다.

---

## 지원 언어
JavaScript / TypeScript / Python

---
## 요구 사항

- Node.js 18 이상
- Python 파일 검사: Python 3.8 이상이 PATH에 있어야 함 (`python`, `python3`, `py` 순서로 찾음)
  - 검사할 코드는 Python 내장 `ast`로 읽기만 하고 실행하지 않음

---

## 설치 및 실행

```bash
git clone https://github.com/Hangeul245/scsp.git
cd scsp
npm install
npm run compile
```
VSCode에서 `F5` → Extension Development Host 실행

---

## 사용 방법

1. JS/TS/Python 파일 열기
2. 코드 수정 후 600ms 뒤 자동 분석
3. `Ctrl+Shift+M` Problems 패널에서 결과 확인
4. 결과(오류·경고)를 클릭하면 취약한 줄(sink)로, 그 아래 "오염 source" 항목을 클릭하면 입력이 들어온 줄로 이동

---

## 테스트

```bash
npm test
```
---

## 설정

```json
{
  "taintGuard.enabledRules": ["sqli", "xss", "cmdi", "path", "ssrf", "redirect"],
  "taintGuard.severity": "error",
  "taintGuard.sourceProfiles": ["web"]
}
```

---

## 알려진 한계

- 함수 간 흐름(Interprocedural) 미추적
- async/await, Promise 체인 내 전파 불완전
- `req[key]` 같은 동적 속성 접근 미탐지
- 등록되지 않은 커스텀 Sanitizer 미인식
- Python 파일에 문법 오류가 있으면 그 버전은 분석하지 않고 이전 결과를 유지
- `cli`, `file`, `network`, `llm` 프로필은 Python만 지원 (JS/TS는 `web`만)
- TypeScript 파일에 `<string>x` 같은 꺾쇠 타입 단언이나 `<T>(x) =>` 제네릭 화살표 함수가 있으면 파일 전체가 분석되지 않음
> 보조 도구로 활용하고 중요한 코드는 수동 검토를 병행하세요.
