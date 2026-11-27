import { parsePython } from './pythonparser';
import type { TaintedVar, TaintFlow, SinkCategory } from './types';

export type SourceProfile = 'web' | 'cli' | 'file' | 'network' | 'llm';

export class PythonTaintEngine {
  private tainted = new Map<string, TaintedVar>();
  private flows: TaintFlow[] = [];
  private profiles: Set<SourceProfile>;

  constructor(profiles: SourceProfile[] = ['web']) {
    this.profiles = new Set(profiles);
  }

  lastError: { reason: string; line?: number } | null = null;

  async analyze(code: string): Promise<TaintFlow[]> {
    this.tainted.clear();
    this.flows = [];
    this.lastError = null;

    const parsed = await parsePython(code);
    if (!parsed.ok) {
      this.lastError = { reason: parsed.reason, line: parsed.line };
      return [];
    }

    this.visitBody(parsed.ast.body);
    return this.flows;
  }

  private visitBody(body: any[]) {
    if (!Array.isArray(body)) return;
    for (const node of body) this.visitStatement(node);
  }

  private visitStatement(node: any) {
    if (!node) return;
    switch (node._type) {
      case 'FunctionDef':
      case 'AsyncFunctionDef':
      case 'ClassDef':
        this.visitBody(node.body);
        break;
      case 'Assign':
        this.handleAssign(node);
        break;
      case 'AnnAssign':
        if (node.value) this.handleAnnAssign(node);
        break;
      case 'Expr':
        this.visitExpr(node.value);
        break;
      case 'For':
      case 'AsyncFor':
        this.visitExpr(node.iter);
        this.assignTarget(node.target, node.iter, node.lineno);
        this.visitBody(node.body);
        this.visitBody(node.orelse);
        break;
      case 'If':
      case 'While':
        this.visitBody(node.body);
        this.visitBody(node.orelse);
        break;
      case 'Try':
      case 'TryStar':
        this.visitBody(node.body);
        for (const h of (node.handlers ?? [])) this.visitBody(h.body);
        this.visitBody(node.orelse);
        this.visitBody(node.finalbody);
        break;
      case 'Return':
        if (node.value) this.visitExpr(node.value);
        break;
      case 'With':
      case 'AsyncWith':
        for (const item of (node.items ?? [])) this.visitExpr(item.context_expr);
        this.visitBody(node.body);
        break;
    }
  }

  private visitExpr(node: any) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const child of node) this.visitExpr(child);
      return;
    }
    if (node._type === 'Call') this.checkSinks(node);
    for (const [key, child] of Object.entries(node)) {
      if (key !== '_type') this.visitExpr(child);
    }
  }

  private handleAssign(node: any) {
    this.visitExpr(node.value);
    for (const target of (node.targets ?? [])) {
      this.assignTarget(target, node.value, node.lineno);
    }
  }

  private handleAnnAssign(node: any) {
    this.visitExpr(node.value);
    this.assignTarget(node.target, node.value, node.lineno);
  }

  private assignTarget(target: any, value: any, line: number) {
    if (target?._type === 'Tuple' || target?._type === 'List') {
      for (const elt of (target.elts ?? [])) this.assignTarget(elt, value, line);
      return;
    }
    const varName = this.extractName(target);
    if (varName) this.processAssignment(varName, value, line);
  }

  private processAssignment(varName: string, value: any, line: number) {
    if (!value) return;

    const sourceDesc = this.matchSource(value);
    if (sourceDesc) {
      this.tainted.set(varName, {
        name: varName, sourceDesc, sourceLine: line,
        sanitized: false, validForCategories: [],
      });
      return;
    }

    if (value._type === 'Call') {
      const san = this.matchSanitizer(value);
      if (san) {
        const inputName = this.findTaintedArgName(value);
        if (inputName && this.tainted.has(inputName)) {
          this.tainted.set(varName, {
            ...this.tainted.get(inputName)!,
            name: varName,
            sanitized: true,
            sanitizerName: san.name,
            validForCategories: san.categories,
          });
          return;
        }
      }
    }

    const propagated = this.findTaintedInExpr(value);
    if (propagated) {
      this.tainted.set(varName, {
        ...propagated,
        name: varName,
        sanitized: false,
        sanitizerName: undefined,
        validForCategories: [],
      });
    }
  }

  private isRequestObject(name: string): boolean {
    return [
      'request.args', 'request.form', 'request.GET', 'request.POST',
      'request.json', 'request.values', 'request.cookies',
    ].some(o => name.startsWith(o));
  }

  private matchSource(node: any): string | null {
    if (!node) return null;
    if (this.profiles.has('web')) {
      const web = this.matchWebSource(node);
      if (web) return web;
    }
    if (this.profiles.has('cli')) {
      const cli = this.matchCliSource(node);
      if (cli) return cli;
    }
    if (this.profiles.has('file')) {
      const file = this.matchFileSource(node);
      if (file) return file;
    }
    if (this.profiles.has('network')) {
      const net = this.matchNetworkSource(node);
      if (net) return net;
    }
    if (this.profiles.has('llm')) {
      const llm = this.matchLlmSource(node);
      if (llm) return llm;
    }
    return null;
  }

  private matchWebSource(node: any): string | null {
    if (node._type === 'Subscript') {
      const objName = this.extractAttrChain(node.value);
      if (!this.isRequestObject(objName)) return null;
      return `${objName}['${this.subscriptKey(node)}']`;
    }

    if (node._type !== 'Call') return null;
    const func = node.func;

    if (
      func._type === 'Attribute' && func.attr === 'get' &&
      func.value?._type === 'Attribute' &&
      this.isRequestObject(this.extractAttrChain(func.value))
    ) {
      return `${this.extractAttrChain(func.value)}.get('${this.strArg(node, 0)}')`;
    }

    if (func._type === 'Attribute' && func.attr === 'get_argument') {
      return `get_argument('${this.strArg(node, 0)}')`;
    }

    return null;
  }

  private matchCliSource(node: any): string | null {
    if (node._type === 'Subscript' && this.extractAttrChain(node.value) === 'sys.argv') {
      return 'sys.argv (명령줄 인자)';
    }
    if (node._type === 'Attribute' && this.extractAttrChain(node) === 'sys.argv') {
      return 'sys.argv (명령줄 인자)';
    }
    if (node._type !== 'Call') return null;
    const func = node.func;
    if (func._type === 'Name' && func.id === 'input') {
      return 'input() (사용자 입력)';
    }
    if (func._type === 'Attribute' && func.attr === 'parse_args') {
      return 'parse_args() (명령줄 인자)';
    }
    return null;
  }

  private matchFileSource(node: any): string | null {
    if (node._type !== 'Call') return null;
    const func = node.func;
    const name = func._type === 'Attribute' ? func.attr : func._type === 'Name' ? func.id : '';
    const chain = this.extractAttrChain(func);

    if (['read', 'readline', 'readlines', 'read_text', 'read_bytes'].includes(name)) {
      return `.${name}() (파일 내용)`;
    }
    if (chain === 'json.load' || chain === 'pickle.load') {
      return `${chain}() (파일 내용)`;
    }
    if (['namelist', 'infolist', 'getnames', 'getmembers'].includes(name)) {
      return `.${name}() (압축 파일 안 이름)`;
    }
    if (['os.listdir', 'os.scandir', 'os.walk', 'glob.glob'].includes(chain) ||
        ['iterdir', 'glob', 'rglob'].includes(name)) {
      return `${chain || name}() (폴더 안 파일 이름)`;
    }
    return null;
  }

  private matchNetworkSource(node: any): string | null {
    if (node._type !== 'Call') return null;
    const chain = this.extractAttrChain(node.func);
    const calls = [
      'requests.get', 'requests.post', 'requests.put', 'requests.request',
      'httpx.get', 'httpx.post', 'urllib.request.urlopen',
    ];
    return calls.includes(chain) ? `${chain}() (HTTP 응답)` : null;
  }

  private matchLlmSource(node: any): string | null {
    if (node._type !== 'Call') return null;
    const chain = this.extractAttrChain(node.func);
    const calls = ['ollama.chat', 'ollama.generate', 'chat.completions.create', 'messages.create'];
    const hit = calls.find(c => chain === c || chain.endsWith('.' + c));
    return hit ? `${chain}() (LLM 응답)` : null;
  }

  private subscriptKey(node: any): string {
    const s = node.slice?._type === 'Index' ? node.slice.value : node.slice;
    return s?._type === 'Constant' && typeof s.value === 'string' ? s.value : '?';
  }

  private matchSanitizer(node: any): { name: string; categories: SinkCategory[] } | null {
    const funcStr = this.extractAttrChain(node.func);

    const sanitizers: { pattern: string; categories: SinkCategory[] }[] = [
      { pattern: 'escape',                   categories: ['xss'] },
      { pattern: 'html.escape',              categories: ['xss'] },
      { pattern: 'bleach.clean',             categories: ['xss'] },
      { pattern: 'markupsafe.escape',        categories: ['xss'] },
      { pattern: 'sanitize_sql',             categories: ['sqli'] },
      { pattern: 'shlex.quote',              categories: ['cmdi'] },
      { pattern: 'pipes.quote',              categories: ['cmdi'] },
      { pattern: 'urllib.parse.quote',       categories: ['ssrf', 'redirect'] },
      { pattern: 'urllib.parse.urlencode',   categories: ['ssrf', 'redirect'] },
      { pattern: 'quote',                    categories: ['ssrf', 'redirect'] },
    ];

    for (const s of sanitizers) {
      if (funcStr === s.pattern || funcStr.endsWith('.' + s.pattern)) {
        return { name: funcStr, categories: s.categories };
      }
    }
    return null;
  }

  private checkSinks(node: any) {
    if (node._type !== 'Call') return;
    const funcStr = this.extractAttrChain(node.func);

    const sinks: { pattern: string; argIndex: number | 'any'; category: SinkCategory; description: string }[] = [
      { pattern: 'cursor.execute',         argIndex: 0, category: 'sqli',     description: 'SQL Injection' },
      { pattern: 'execute',                argIndex: 0, category: 'sqli',     description: 'SQL Injection' },
      { pattern: 'raw',                    argIndex: 0, category: 'sqli',     description: 'SQL Injection (Django raw)' },
      { pattern: 'render_template_string', argIndex: 0, category: 'xss',      description: 'XSS/SSTI' },
      { pattern: 'Markup',                 argIndex: 0, category: 'xss',      description: 'XSS' },
      { pattern: 'os.system',              argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
      { pattern: 'os.popen',               argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
      { pattern: 'subprocess.run',         argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
      { pattern: 'subprocess.call',        argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
      { pattern: 'subprocess.Popen',       argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
      { pattern: 'eval',                   argIndex: 0, category: 'cmdi',     description: 'RCE (eval)' },
      { pattern: 'exec',                   argIndex: 0, category: 'cmdi',     description: 'RCE (exec)' },
      { pattern: 'pickle.loads',           argIndex: 0, category: 'cmdi',     description: 'RCE (역직렬화)' },
      { pattern: 'pickle.load',            argIndex: 0, category: 'cmdi',     description: 'RCE (역직렬화)' },
      { pattern: 'marshal.loads',          argIndex: 0, category: 'cmdi',     description: 'RCE (역직렬화)' },
      { pattern: 'yaml.load',              argIndex: 0, category: 'cmdi',     description: 'RCE (역직렬화)' },
      { pattern: 'open',                   argIndex: 0, category: 'path',     description: 'Path Traversal' },
      { pattern: 'os.path.join',           argIndex: 0, category: 'path',     description: 'Path Traversal' },
      { pattern: 'shutil.move',            argIndex: 'any', category: 'path', description: 'Path Traversal (파일 이동)' },
      { pattern: 'shutil.copy',            argIndex: 'any', category: 'path', description: 'Path Traversal (파일 복사)' },
      { pattern: 'shutil.copy2',           argIndex: 'any', category: 'path', description: 'Path Traversal (파일 복사)' },
      { pattern: 'shutil.copyfile',        argIndex: 'any', category: 'path', description: 'Path Traversal (파일 복사)' },
      { pattern: 'shutil.rmtree',          argIndex: 0, category: 'path',     description: 'Path Traversal (폴더 삭제)' },
      { pattern: 'os.remove',              argIndex: 0, category: 'path',     description: 'Path Traversal (파일 삭제)' },
      { pattern: 'os.unlink',              argIndex: 0, category: 'path',     description: 'Path Traversal (파일 삭제)' },
      { pattern: 'os.rename',              argIndex: 'any', category: 'path', description: 'Path Traversal (이름 변경)' },
      { pattern: 'os.replace',             argIndex: 'any', category: 'path', description: 'Path Traversal (이름 변경)' },
      { pattern: 'extract',                argIndex: 'any', category: 'path', description: 'Path Traversal (압축 풀기)' },
      { pattern: 'extractall',             argIndex: 'any', category: 'path', description: 'Path Traversal (압축 풀기)' },
      { pattern: 'requests.get',           argIndex: 0, category: 'ssrf',     description: 'SSRF' },
      { pattern: 'requests.post',          argIndex: 0, category: 'ssrf',     description: 'SSRF' },
      { pattern: 'urllib.request.urlopen', argIndex: 0, category: 'ssrf',     description: 'SSRF' },
      { pattern: 'httpx.get',              argIndex: 0, category: 'ssrf',     description: 'SSRF' },
      { pattern: 'redirect',               argIndex: 0, category: 'redirect', description: 'Open Redirect' },
    ];

    for (const sink of sinks) {
      if (!this.nameMatches(funcStr, sink.pattern)) continue;

      const taintedVar = this.findTaintedArgAtIndex(node, sink.argIndex);
      if (taintedVar) {
        const sanitizerWrong =
          taintedVar.sanitized &&
          !taintedVar.validForCategories.includes(sink.category);

        if (!taintedVar.sanitized || sanitizerWrong) {
          this.flows.push({
            vulnType:      sink.category,
            sourceLine:    taintedVar.sourceLine,
            sourceDesc:    taintedVar.sourceDesc,
            sinkLine:      node.lineno ?? 0,
            sinkDesc:      sink.description,
            sinkArgSource: taintedVar.name,
            sanitized:     taintedVar.sanitized,
            sanitizerName: taintedVar.sanitizerName,
            sanitizerWrong,
            message: sanitizerWrong
              ? `[TaintGuard] ${sink.description} — '${taintedVar.sanitizerName}'은 이 sink에 적합한 sanitizer가 아닙니다.`
              : `[TaintGuard] ${sink.description} — '${taintedVar.name}'은 ${taintedVar.sourceDesc}에서 유래한 검증되지 않은 입력입니다.`,
          });
        }
      }
      break;
    }
  }

  private nameMatches(funcStr: string, pattern: string): boolean {
    return funcStr === pattern || funcStr.endsWith('.' + pattern);
  }

  private findTaintedInExpr(node: any): TaintedVar | null {
    if (!node) return null;
    const direct = this.matchSource(node);
    if (direct) {
      return {
        name: direct, sourceDesc: direct, sourceLine: node.lineno ?? 0,
        sanitized: false, validForCategories: [],
      };
    }
    if (node._type === 'Name' && this.tainted.has(node.id))
      return this.tainted.get(node.id)!;
    if (node._type === 'JoinedStr') {
      for (const val of (node.values ?? [])) {
        const found = this.findTaintedInExpr(val);
        if (found) return found;
      }
    }
    if (node._type === 'FormattedValue')
      return this.findTaintedInExpr(node.value);
    if (node._type === 'BinOp')
      return this.findTaintedInExpr(node.left) ?? this.findTaintedInExpr(node.right);
    if (node._type === 'Attribute' || node._type === 'Subscript')
      return this.findTaintedInExpr(node.value);
    if (node._type === 'Tuple' || node._type === 'List') {
      for (const elt of (node.elts ?? [])) {
        const found = this.findTaintedInExpr(elt);
        if (found) return found;
      }
    }
    if (node._type === 'Call') {
      if (node.func?._type === 'Attribute') {
        const owner = this.findTaintedInExpr(node.func.value);
        if (owner) return owner;
      }
      for (const arg of (node.args ?? [])) {
        const found = this.findTaintedInExpr(arg);
        if (found) return found;
      }
    }
    return null;
  }

  private findTaintedArgName(node: any): string | null {
    for (const arg of (node.args ?? [])) {
      if (arg._type === 'Name' && this.tainted.has(arg.id)) return arg.id;
    }
    return null;
  }

  private findTaintedArgAtIndex(node: any, argIndex: number | 'any'): TaintedVar | null {
    if (argIndex === 'any') {
      for (const a of (node.args ?? [])) {
        const found = this.findTaintedInExpr(a);
        if (found) return found;
      }
      for (const kw of (node.keywords ?? [])) {
        const found = this.findTaintedInExpr(kw.value);
        if (found) return found;
      }
      return null;
    }
    const arg = node.args?.[argIndex];
    if (!arg) return null;
    if (arg._type === 'Name' && this.tainted.has(arg.id))
      return this.tainted.get(arg.id)!;
    return this.findTaintedInExpr(arg);
  }

  private strArg(node: any, index: number): string {
    const arg = node.args?.[index];
    if (arg?._type === 'Constant' && typeof arg.value === 'string') return arg.value;
    return '?';
  }

  private extractName(node: any): string | null {
    if (node._type === 'Name') return node.id;
    return null;
  }

  private extractAttrChain(node: any): string {
    if (!node) return '';
    if (node._type === 'Name') return node.id;
    if (node._type === 'Attribute')
      return `${this.extractAttrChain(node.value)}.${node.attr}`;
    return '';
  }
}