import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { fixFor } from '../fixes';

const RULES = ['sqli', 'xss', 'cmdi', 'path', 'ssrf', 'redirect'] as const;

test('탐지 규칙 6종 모두 Python, JS 수정 방안이 있음', () => {
  for (const rule of RULES) {
    for (const lang of ['py', 'js', 'ts'] as const) {
      const fix = fixFor(rule, lang);
      assert.ok(fix && fix.length > 0, `${rule} / ${lang}`);
    }
  }
});

test('Python과 JS는 다른 예시를 보여 줌', () => {
  assert.match(fixFor('sqli', 'py')!, /cursor\.execute/);
  assert.match(fixFor('sqli', 'ts')!, /db\.query/);
});
