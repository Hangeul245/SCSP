import { parsePython } from './pythonparser';
import type { TaintedVar, TaintFlow, SinkCategory } from './types';

export class PythonTaintEngine {
  private tainted = new Map<string, TaintedVar>();
  private flows: TaintFlow[] = [];

    lastError: { reason: string; line?: number } | null = null;

  analyze(code: string): TaintFlow[] {
    this.tainted.clear();
    this.flows = [];
    this.lastError = null;

    const parsed = parsePython(code);
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
      case 'If':
      case 'For':
      case 'AsyncFor':
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
        if (node.value) this.checkSinks(node.value);
        break;
      case 'With':
      case 'AsyncWith':
        for (const item of (node.items ?? [])) this.checkSinks(item.context_expr);
        this.visitBody(node.body);
        break;
    }
  }

  private visitExpr(node: any) {
    if (!node) return;
    if (node._type === 'Call') {
      this.checkSinks(node);
      for (const arg of (node.args ?? [])) {
        if (arg._type === 'Lambda') this.visitExpr(arg.body);
      }
    }
  }

  private handleAssign(node: any) {
    this.checkSinks(node.value);
    for (const target of (node.targets ?? [])) {
      const varName = this.extractName(target);
      if (varName) this.processAssignment(varName, node.value, node.lineno);
    }
  }

  private handleAnnAssign(node: any) {
    this.checkSinks(node.value);
    const varName = this.extractName(node.target);
    if (varName) this.processAssignment(varName, node.value, node.lineno);
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

  private matchSource(node: any): string | null {
    if (node._type !== 'Call') return null;
    const func = node.func;

    if (
      func._type === 'Attribute' && func.attr === 'get' &&
      func.value?._type === 'Attribute'
    ) {
      const objName = this.extractAttrChain(func.value);
      if (
        objName.startsWith('request.args')   ||
        objName.startsWith('request.form')   ||
        objName.startsWith('request.GET')    ||
        objName.startsWith('request.POST')   ||
        objName.startsWith('request.json')   ||
        objName.startsWith('request.values') ||
        objName.startsWith('request.cookies')
      ) {
        const key = this.strArg(node, 0);
        return `${objName}.get('${key}')`;
      }
    }

    if (func._type === 'Attribute' && func.attr === 'get_argument') {
      const key = this.strArg(node, 0);
      return `get_argument('${key}')`;
    }

    return null;
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

    const sinks: { pattern: string; argIndex: number; category: SinkCategory; description: string }[] = [
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
      { pattern: 'open',                   argIndex: 0, category: 'path',     description: 'Path Traversal' },
      { pattern: 'os.path.join',           argIndex: 0, category: 'path',     description: 'Path Traversal' },
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
    if (node._type === 'Call') {
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

  private findTaintedArgAtIndex(node: any, argIndex: number): TaintedVar | null {
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