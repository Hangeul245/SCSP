import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { PythonTaintEngine, SourceProfile } from '../pythonengine';

const HEADER = 'import os, sys, argparse\nfrom flask import request\n';

async function kinds(profiles: SourceProfile[], body: string[]): Promise<string[]> {
  const engine = new PythonTaintEngine(profiles);
  const flows = await engine.analyze(HEADER + body.join('\n'));
  assert.equal(engine.lastError, null);
  return flows.map(f => f.vulnType);
}

test('기본(web)만 켜면 명령줄 인자는 출처가 아님', async () => {
  assert.deepEqual(await kinds(['web'], [
    'os.system(sys.argv[1])',
  ]), []);
});

test('cli: sys.argv', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'target = sys.argv[1]',
    'os.system("yara " + target)',
  ]), ['cmdi']);
});

test('cli: argparse 결과의 속성', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'ap = argparse.ArgumentParser()',
    'args = ap.parse_args()',
    'open(args.path)',
  ]), ['path']);
});

test('cli: input()', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'cmd = input()',
    'os.system(cmd)',
  ]), ['cmdi']);
});

test('web을 끄면 Flask 입력은 출처가 아님', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'def f():',
    `    os.system(request.args.get('c'))`,
  ]), []);
});

test('오염된 값의 메서드 결과도 오염', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'name = sys.argv[1]',
    'clean = name.strip()',
    'os.system(clean)',
  ]), ['cmdi']);
});
