import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { PythonTaintEngine } from '../pythonengine';

const FLASK_CMDI = [
  'import os',
  'from flask import request',
  'def view():',
  "    name = request.args.get('f')",
  '    os.system(name)',
].join('\n');

test('Flask 입력이 os.system으로 가면 cmdi 1건', () => {
  const flows = new PythonTaintEngine().analyze(FLASK_CMDI);
  assert.equal(flows.length, 1);
  assert.equal(flows[0].vulnType, 'cmdi');
  assert.equal(flows[0].sourceLine, 4);
  assert.equal(flows[0].sinkLine, 5);
});

test('문법 오류 파일은 0건 대신 lastError에 이유를 남김', () => {
  const engine = new PythonTaintEngine();
  const flows = engine.analyze('x = (');
  assert.equal(flows.length, 0);
  assert.equal(engine.lastError?.reason, 'SyntaxError');
});

test('출처 설명에 파라미터 이름이 들어감', () => {
  const flows = new PythonTaintEngine().analyze(FLASK_CMDI);
  assert.equal(flows[0].sourceDesc, "request.args.get('f')");
});