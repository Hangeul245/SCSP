import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { PythonTaintEngine } from '../pythonengine';
import { parsePython } from '../pythonparser';

const FLASK_CMDI = [
  'import os',
  'from flask import request',
  'def view():',
  "    name = request.args.get('f')",
  '    os.system(name)',
].join('\n');

test('Flask 입력이 os.system으로 가면 cmdi 1건', async () => {
  const flows = await new PythonTaintEngine().analyze(FLASK_CMDI);
  assert.equal(flows.length, 1);
  assert.equal(flows[0].vulnType, 'cmdi');
  assert.equal(flows[0].sourceLine, 4);
  assert.equal(flows[0].sinkLine, 5);
});

test('문법 오류 파일은 0건 대신 lastError에 이유를 남김', async () => {
  const engine = new PythonTaintEngine();
  const flows = await engine.analyze('x = (');
  assert.equal(flows.length, 0);
  assert.equal(engine.lastError?.reason, 'SyntaxError');
});

test('출처 설명에 파라미터 이름이 들어감', async () => {
  const flows = await new PythonTaintEngine().analyze(FLASK_CMDI);
  assert.equal(flows[0].sourceDesc, "request.args.get('f')");
});

test('같은 코드는 파이썬을 다시 부르지 않고 이전 결과를 씀', async () => {
  const code = 'x = 1\n';
  const first = await parsePython(code);
  const second = await parsePython(code);
  assert.equal(first.ok, true);
  assert.equal(second, first);
});