import type { VulnType } from './types';

type Lang = 'py' | 'js';

const FIXES: Record<Exclude<VulnType, 'xxe'>, Record<Lang, string>> = {
  sqli: {
    py: '문자열을 이어 붙이지 말고 파라미터 바인딩을 쓰세요. 예: cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
    js: "문자열을 이어 붙이지 말고 파라미터 바인딩을 쓰세요. 예: db.query('SELECT * FROM users WHERE name = ?', [name])",
  },
  xss: {
    py: '출력 전에 html.escape(값)으로 이스케이프하세요. render_template_string 대신 템플릿 파일(자동 이스케이프)을 쓰는 게 안전합니다.',
    js: 'innerHTML 대신 textContent를 쓰세요. HTML이 꼭 필요하면 DOMPurify.sanitize(값)를 거치세요.',
  },
  cmdi: {
    py: 'shell=True와 문자열 명령 대신 인자 목록을 쓰세요. 예: subprocess.run(["ping", "-c", "1", host]). 문자열이 꼭 필요하면 shlex.quote(값). eval에는 사용자 입력을 넣지 마세요.',
    js: "exec 대신 execFile에 인자 배열을 넘기세요. 예: execFile('ping', ['-c', '1', host])",
  },
  path: {
    py: 'os.path.basename(값)으로 파일 이름만 남기거나, os.path.realpath 결과가 허용 폴더 안인지 확인한 뒤 여세요.',
    js: 'path.basename(값)으로 파일 이름만 남기거나, path.resolve 결과가 허용 폴더로 시작하는지 확인한 뒤 여세요.',
  },
  ssrf: {
    py: '사용자가 URL 전체를 정하지 않게 하세요. 허용 도메인 목록과 비교한 뒤 요청하고, 경로 일부만 받는다면 urllib.parse.quote(값)를 거치세요.',
    js: '사용자가 URL 전체를 정하지 않게 하세요. 허용 도메인 목록과 비교한 뒤 요청하고, 경로 일부만 받는다면 encodeURIComponent(값)를 거치세요.',
  },
  redirect: {
    py: '상대 경로("/"로 시작, "//"는 제외)만 허용하거나, 허용 도메인 목록과 비교한 뒤 이동하세요.',
    js: '상대 경로("/"로 시작, "//"는 제외)만 허용하거나, 허용 도메인 목록과 비교한 뒤 이동하세요.',
  },
};

export function fixFor(vulnType: VulnType, lang: 'js' | 'ts' | 'py'): string | null {
  if (vulnType === 'xxe') return null;
  return FIXES[vulnType][lang === 'py' ? 'py' : 'js'];
}
