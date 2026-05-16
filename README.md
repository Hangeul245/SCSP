# SCSP - Source Code Security Parser

Taint Analysis 기반 웹 취약점 실시간 탐지 VSCode Extension.  
코드 수정 시 자동 분석 후 Problems 패널에 결과를 표시합니다.

---

## 탐지 취약점

| 코드 | 취약점 |
|------|--------|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `cmdi` | Command Injection |
| `path` | Path Traversal |
| `ssrf` | Server-Side Request Forgery |
| `redirect` | Open Redirect |

---

## 지원 언어
JavaScript / TypeScript / Python

---

## 설치 및 실행

```bash
git clone https://github.com/<유저명>/scsp.git
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
4. 경고 클릭 시 오염 source 위치로 이동

---

## 설정

```json
{
  "taintGuard.enabledRules": ["sqli", "xss", "cmdi", "path", "ssrf", "redirect"],
  "taintGuard.severity": "warning"
}
```

---

## 알려진 한계

- 함수 간 흐름(Interprocedural) 미추적
- async/await, Promise 체인 내 전파 불완전
- `req[key]` 같은 동적 속성 접근 미탐지
- 등록되지 않은 커스텀 Sanitizer 미인식

> 보조 도구로 활용하고 중요한 코드는 수동 검토를 병행하세요.
