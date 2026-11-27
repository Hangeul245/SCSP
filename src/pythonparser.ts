import { spawn } from 'child_process';
import { createHash } from 'crypto';
import * as path from 'path';

export type ParseResult =
  | { ok: true; ast: any }
  | { ok: false; reason: string; line?: number };

type RunResult =
  | { kind: 'notfound' }
  | { kind: 'failed'; reason: string }
  | { kind: 'output'; stdout: string };

const SCRIPT = path.join(__dirname, '..', 'python', 'ast_dump.py');
const CANDIDATES = ['python', 'python3', 'py'];
const TIMEOUT_MS = 5000;
const MAX_OUTPUT = 64 * 1024 * 1024;
const CACHE_SIZE = 20;

const cache = new Map<string, ParseResult>();

export async function parsePython(code: string): Promise<ParseResult> {
  const key = createHash('sha256').update(code, 'utf8').digest('hex');
  const hit = cache.get(key);
  if (hit) {
    cache.delete(key);
    cache.set(key, hit);
    return hit;
  }

  for (const cmd of CANDIDATES) {
    const r = await runOnce(cmd, code);
    if (r.kind === 'notfound') continue;
    if (r.kind === 'failed') return { ok: false, reason: r.reason };

    let data: any;
    try {
      data = JSON.parse(r.stdout);
    } catch {
      return { ok: false, reason: 'AST JSON 해석 실패' };
    }
    const result: ParseResult = data._error
      ? { ok: false, reason: data._error, line: data.lineno ?? undefined }
      : { ok: true, ast: data };

    cache.set(key, result);
    if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value!);
    return result;
  }
  return { ok: false, reason: 'Python을 찾을 수 없음 (python, python3, py)' };
}

function runOnce(cmd: string, code: string): Promise<RunResult> {
  return new Promise(resolve => {
    const child = spawn(cmd, [SCRIPT], { windowsHide: true });
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;

    const finish = (r: RunResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(r);
    };

    const timer = setTimeout(() => {
      child.kill();
      finish({ kind: 'failed', reason: `시간 초과 (${TIMEOUT_MS / 1000}초)` });
    }, TIMEOUT_MS);

    child.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ENOENT') finish({ kind: 'notfound' });
      else finish({ kind: 'failed', reason: `Python 실행 실패: ${err.message}` });
    });

    child.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_OUTPUT) {
        child.kill();
        finish({ kind: 'failed', reason: 'AST 출력이 너무 큼' });
        return;
      }
      chunks.push(chunk);
    });

    child.on('close', status => {
      if (status !== 0) finish({ kind: 'notfound' });
      else finish({ kind: 'output', stdout: Buffer.concat(chunks).toString('utf8') });
    });

    child.stdin.on('error', () => { /* 프로세스가 먼저 끝나면 무시 */ });
    child.stdin.end(Buffer.from(code, 'utf8'));
  });
}