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

test('file: 파일 내용이 명령으로', async () => {
  assert.deepEqual(await kinds(['file'], [
    'data = open("rule.txt").read()',
    'os.system(data)',
  ]), ['cmdi']);
});

test('file: 압축 파일 안 이름으로 경로 만들기 (zip slip)', async () => {
  assert.deepEqual(await kinds(['file'], [
    'import zipfile',
    'z = zipfile.ZipFile("sample.zip")',
    'for name in z.namelist():',
    '    open(os.path.join("out", name), "wb")',
  ]), ['path']);
});

test('file: 폴더 안 파일 이름을 지우기', async () => {
  assert.deepEqual(await kinds(['file'], [
    'for f in os.listdir("quarantine"):',
    '    os.remove(f)',
  ]), ['path']);
});

test('cli: 명령줄 인자로 파일 이동 (두 번째 인자도 검사)', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'import shutil',
    'dest = sys.argv[1]',
    'shutil.move("sample.exe", dest)',
  ]), ['path']);
});

test('cli: 압축 풀 위치를 명령줄 인자로', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'import zipfile',
    'zipfile.ZipFile("a.zip").extractall(sys.argv[1])',
  ]), ['path']);
});

test('튜플 대입도 전파', async () => {
  assert.deepEqual(await kinds(['cli'], [
    'a, b = sys.argv[1], "x"',
    'os.system(a)',
  ]), ['cmdi']);
});

test('file을 끄면 파일 내용은 출처가 아님', async () => {
  assert.deepEqual(await kinds(['web'], [
    'data = open("rule.txt").read()',
    'os.system(data)',
  ]), []);
});

test('network: HTTP 응답 내용이 명령으로', async () => {
  assert.deepEqual(await kinds(['network'], [
    'import requests',
    'resp = requests.get("https://feed.example/list")',
    'os.system(resp.json()["cmd"])',
  ]), ['cmdi']);
});

test('network를 끄면 HTTP 응답은 출처가 아님', async () => {
  assert.deepEqual(await kinds(['web'], [
    'import requests',
    'resp = requests.get("https://feed.example/list")',
    'os.system(resp.json()["cmd"])',
  ]), []);
});

test('llm: Ollama 응답을 exec', async () => {
  assert.deepEqual(await kinds(['llm'], [
    'import ollama',
    'r = ollama.chat(model="qwen", messages=[])',
    'exec(r["message"]["content"])',
  ]), ['cmdi']);
});

test('llm: OpenAI 형식 응답을 eval', async () => {
  assert.deepEqual(await kinds(['llm'], [
    'out = client.chat.completions.create(model="m", messages=[])',
    'eval(out.choices[0].message.content)',
  ]), ['cmdi']);
});

test('역직렬화: HTTP로 받은 데이터를 pickle.loads', async () => {
  assert.deepEqual(await kinds(['network'], [
    'import pickle, requests',
    'pickle.loads(requests.get("https://x.example/m").content)',
  ]), ['cmdi']);
});

test('역직렬화: yaml.load는 잡고 yaml.safe_load는 안 잡음', async () => {
  assert.deepEqual(await kinds(['file'], [
    'import yaml',
    'a = yaml.load(open("c.yml").read())',
    'b = yaml.safe_load(open("c.yml").read())',
  ]), ['cmdi']);
});
