import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { PythonTaintEngine } from '../pythonengine';

const HEADER = 'import os\nfrom flask import request\n';

function kinds(body: string[]): string[] {
  const engine = new PythonTaintEngine();
  const flows = engine.analyze(HEADER + body.join('\n'));
  assert.equal(engine.lastError, null);
  return flows.map(f => f.vulnType);
}

test('클래스 안 메서드', () => {
  assert.deepEqual(kinds([
    'class View:',
    '    def get(self):',
    `        name = request.args.get('f')`,
    '        os.system(name)',
  ]), ['cmdi']);
});

test('except 블록', () => {
  assert.deepEqual(kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    try:',
    '        pass',
    '    except Exception:',
    '        os.system(name)',
  ]), ['cmdi']);
});

test('for 문의 else 블록', () => {
  assert.deepEqual(kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    for i in range(3):',
    '        pass',
    '    else:',
    '        os.system(name)',
  ]), ['cmdi']);
});

test('with 문 머리의 open', () => {
  assert.deepEqual(kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    with open(name) as fh:',
    '        pass',
  ]), ['path']);
});