import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { PythonTaintEngine } from '../pythonengine';

const HEADER = 'import os\nfrom flask import request\n';

async function kinds(body: string[]): Promise<string[]> {
  const engine = new PythonTaintEngine();
  const flows = await engine.analyze(HEADER + body.join('\n'));
  assert.equal(engine.lastError, null);
  return flows.map(f => f.vulnType);
}

test('클래스 안 메서드', async () => {
  assert.deepEqual(await kinds([
    'class View:',
    '    def get(self):',
    `        name = request.args.get('f')`,
    '        os.system(name)',
  ]), ['cmdi']);
});

test('except 블록', async () => {
  assert.deepEqual(await kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    try:',
    '        pass',
    '    except Exception:',
    '        os.system(name)',
  ]), ['cmdi']);
});

test('for 문의 else 블록', async () => {
  assert.deepEqual(await kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    for i in range(3):',
    '        pass',
    '    else:',
    '        os.system(name)',
  ]), ['cmdi']);
});

test('with 문 머리의 open', async () => {
  assert.deepEqual(await kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    with open(name) as fh:',
    '        pass',
  ]), ['path']);
});

test('대괄호 출처', async () => {
  assert.deepEqual(await kinds([
    'def f():',
    `    name = request.args['f']`,
    '    os.system(name)',
  ]), ['cmdi']);
});

test('출처가 sink 인자로 바로 들어감', async () => {
  assert.deepEqual(await kinds([
    'def f():',
    `    os.system(request.args.get('c'))`,
  ]), ['cmdi']);
});

test('중첩 호출 안쪽의 sink', async () => {
  assert.deepEqual(await kinds([
    'def f():',
    `    name = request.args.get('f')`,
    '    return open(name).read()',
  ]), ['path']);
});