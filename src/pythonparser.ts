import { spawnSync } from 'child_process';
import * as path from 'path';

export type ParseResult =
  | { ok: true; ast: any }
  | { ok: false; reason: string; line?: number };

const SCRIPT = path.join(__dirname, '..', 'python', 'ast_dump.py');
const CANDIDATES = ['python', 'python3', 'py'];

export function parsePython(code: string): ParseResult {
  for (const cmd of CANDIDATES) {
    const r = spawnSync(cmd, [SCRIPT], {
      input: Buffer.from(code, 'utf8'),
      timeout: 5000,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    });
    if (r.error) {
      if ((r.error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      return { ok: false, reason: `Python 실행 실패: ${r.error.message}` };
    }
    if (r.status !== 0) continue;

    let data: any;
    try {
      data = JSON.parse(r.stdout.toString('utf8'));
    } catch {
      return { ok: false, reason: 'AST JSON 해석 실패' };
    }
    if (data._error) {
      return { ok: false, reason: data._error, line: data.lineno ?? undefined };
    }
    return { ok: true, ast: data };
  }
  return { ok: false, reason: 'Python을 찾을 수 없음 (python, python3, py)' };
}