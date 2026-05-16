import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';
import { SOURCE_PATTERNS, SINK_PATTERNS, SANITIZER_PATTERNS } from './rules';
import type { TaintedVar, TaintFlow, SinkCategory } from './types';

function isIdentifier(n: TSESTree.Node): n is TSESTree.Identifier {
  return n.type === 'Identifier';
}
function isMemberExpr(n: TSESTree.Node): n is TSESTree.MemberExpression {
  return n.type === 'MemberExpression';
}
function isCallExpr(n: TSESTree.Node): n is TSESTree.CallExpression {
  return n.type === 'CallExpression';
}
function isTemplateLiteral(n: TSESTree.Node): n is TSESTree.TemplateLiteral {
  return n.type === 'TemplateLiteral';
}
function isBinaryExpr(n: TSESTree.Node): n is TSESTree.BinaryExpression {
  return n.type === 'BinaryExpression';
}
function lineOf(n: TSESTree.Node): number {
  return n.loc?.start.line ?? 0;
}
function memberToStr(n: TSESTree.MemberExpression): string {
  const obj  = isIdentifier(n.object)   ? n.object.name   : '?';
  const prop = isIdentifier(n.property) ? n.property.name : '?';
  return `${obj}.${prop}`;
}

export class TaintEngine {
  // ⚠️ 파일 전체를 단일 스코프로 처리 — 동명 변수 섀도잉 미지원
  private tainted = new Map<string, TaintedVar>();
  private flows: TaintFlow[] = [];

  analyze(code: string, language: 'js' | 'ts' | 'py'): TaintFlow[] {
    this.tainted.clear();
    this.flows = [];

    if (language === 'py') return []; // Python 파서 미구현

    let ast: TSESTree.Program;
    try {
      ast = parse(code, { jsx: true, loc: true, range: true, tolerant: true });
    } catch {
      return [];
    }

    for (const stmt of ast.body) {
      this.visitStatement(stmt as TSESTree.Statement);
    }
    return this.flows;
  }

  // ─── 순회 ──────────────────────────────────────────────────────────────

  private visitStatement(node: TSESTree.Statement) {
    switch (node.type) {
      case 'VariableDeclaration':
        node.declarations.forEach(d => this.visitVarDeclarator(d));
        break;
      case 'ExpressionStatement':
        this.visitExpression(node.expression);
        break;
      case 'BlockStatement':
        node.body.forEach(s => this.visitStatement(s));
        break;
      case 'IfStatement':
        // ⚠️ 분기 병합 미구현 — 양쪽 단순 방문
        this.visitStatement(node.consequent);
        if (node.alternate) this.visitStatement(node.alternate);
        break;
      case 'FunctionDeclaration':
        if (node.body) this.visitStatement(node.body);
        break;
      case 'ReturnStatement':
        if (node.argument) this.checkSinks(node.argument);
        break;
      case 'TryStatement':
        this.visitStatement(node.block);
        break;
      case 'ForStatement':
      case 'WhileStatement':
      case 'DoWhileStatement':
        if (node.body) this.visitStatement(node.body);
        break;
      case 'SwitchStatement':
        for (const c of node.cases) {
          c.consequent.forEach(s => this.visitStatement(s));
        }
        break;
    }
  }

  private visitExpression(node: TSESTree.Expression) {
    if (isCallExpr(node)) {
      this.checkSinks(node);

      // ─── 핵심 추가: Arrow/Function 콜백 내부 재귀 방문 ───────────────
      // app.get('/path', (req, res) => { ... }) 패턴 처리
      // ⚠️ 콜백 파라미터(req, res)를 현재 스코프 tainted map과 공유하므로
      //    동명 변수 충돌 가능성 있음 — 중첩 라우터 등에서 주의
      for (const arg of node.arguments) {
        if (
          arg.type === 'ArrowFunctionExpression' ||
          arg.type === 'FunctionExpression'
        ) {
          if (arg.body.type === 'BlockStatement') {
            arg.body.body.forEach(s => this.visitStatement(s));
          } else {
            // Arrow function 단일 표현식: (req, res) => db.query(...)
            this.visitExpression(arg.body as TSESTree.Expression);
          }
        }
      }
    }

    if (node.type === 'AssignmentExpression' && isIdentifier(node.left)) {
      this.handleAssignment(node.left.name, node.right, lineOf(node));
    }
  }

  private visitVarDeclarator(node: TSESTree.VariableDeclarator) {
    if (!node.init || !isIdentifier(node.id)) return;
    this.handleAssignment(node.id.name, node.init, lineOf(node));
  }

  // ─── 오염 마킹 ─────────────────────────────────────────────────────────

  private handleAssignment(varName: string, init: TSESTree.Expression, line: number) {
    // 1. 직접 source?
    const sourceDesc = this.matchSource(init);
    if (sourceDesc) {
      this.tainted.set(varName, {
        name: varName, sourceDesc, sourceLine: line,
        sanitized: false, validForCategories: [],
      });
      return;
    }

    // 2. sanitizer 결과?
    if (isCallExpr(init)) {
      const san = this.matchSanitizer(init);
      if (san) {
        const inputName = this.findTaintedArgName(init);
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

    // 3. 오염 전파 (문자열 연결, 템플릿 리터럴 등)
    const propagated = this.findTaintedInExpr(init);
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

  // ─── Source 매칭 ───────────────────────────────────────────────────────

  private matchSource(node: TSESTree.Expression): string | null {
    for (const p of SOURCE_PATTERNS) {
      if (p.type === 'member' && isMemberExpr(node)) {
        // req.query
        if (
          isIdentifier(node.object)   && node.object.name   === p.object &&
          isIdentifier(node.property) && node.property.name === p.property
        ) return memberToStr(node);

        // req.query.id (depth 2)
        if (
          isMemberExpr(node.object) &&
          isIdentifier(node.object.object)   && node.object.object.name   === p.object &&
          isIdentifier(node.object.property) && node.object.property.name === p.property
        ) {
          const leaf = isIdentifier(node.property) ? node.property.name : '?';
          return `${p.object}.${p.property}.${leaf}`;
        }
      }
    }
    return null;
  }

  // ─── Sanitizer 매칭 ────────────────────────────────────────────────────

  private matchSanitizer(node: TSESTree.CallExpression): { name: string; categories: SinkCategory[] } | null {
    for (const p of SANITIZER_PATTERNS) {
      if (p.type === 'call' && p.callee) {
        if (isIdentifier(node.callee) && node.callee.name === p.callee)
          return { name: p.callee, categories: p.categories };
        // "he.encode" 같은 dotted 형태
        if (isMemberExpr(node.callee)) {
          const full = [
            isIdentifier(node.callee.object)   ? node.callee.object.name   : '',
            isIdentifier(node.callee.property) ? node.callee.property.name : '',
          ].join('.');
          if (full === p.callee) return { name: full, categories: p.categories };
        }
      }
      if (p.type === 'method_call' && isMemberExpr(node.callee)) {
        const obj  = isIdentifier(node.callee.object)   ? node.callee.object.name   : null;
        const meth = isIdentifier(node.callee.property) ? node.callee.property.name : null;
        if (obj === p.object && meth === p.method)
          return { name: `${obj}.${meth}`, categories: p.categories };
      }
    }
    return null;
  }

  // ─── 오염 탐색 ─────────────────────────────────────────────────────────

  private findTaintedInExpr(node: TSESTree.Expression): TaintedVar | null {
    if (isIdentifier(node) && this.tainted.has(node.name))
      return this.tainted.get(node.name)!;
    if (isBinaryExpr(node))
      return this.findTaintedInExpr(node.left  as TSESTree.Expression)
          ?? this.findTaintedInExpr(node.right as TSESTree.Expression);
    if (isTemplateLiteral(node)) {
      for (const expr of node.expressions) {
        const found = this.findTaintedInExpr(expr as TSESTree.Expression);
        if (found) return found;
      }
    }
    if (isCallExpr(node)) {
      for (const arg of node.arguments) {
        if (arg.type !== 'SpreadElement') {
          const found = this.findTaintedInExpr(arg as TSESTree.Expression);
          if (found) return found;
        }
      }
    }
    return null;
  }

  private findTaintedArgName(node: TSESTree.CallExpression): string | null {
    for (const arg of node.arguments) {
      if (arg.type !== 'SpreadElement' && isIdentifier(arg) && this.tainted.has(arg.name))
        return arg.name;
    }
    return null;
  }

  // ─── Sink 검사 ─────────────────────────────────────────────────────────

  private checkSinks(node: TSESTree.Expression) {
    if (!isCallExpr(node)) return;

    for (const sink of SINK_PATTERNS) {
      let matched = false;

      if (sink.type === 'call' && sink.callee)
        matched = isIdentifier(node.callee) && node.callee.name === sink.callee;

      if (sink.type === 'method_call' && isMemberExpr(node.callee)) {
        const obj  = isIdentifier(node.callee.object)   ? node.callee.object.name   : null;
        const meth = isIdentifier(node.callee.property) ? node.callee.property.name : null;
        matched = obj === sink.object && meth === sink.method;
      }
      if (!matched) continue;

      const taintedVar = this.findTaintedArgAtIndex(node, sink.argIndex);
      if (!taintedVar) continue;

      const sanitizerWrong =
        taintedVar.sanitized &&
        !taintedVar.validForCategories.includes(sink.category);

      if (taintedVar.sanitized && !sanitizerWrong) continue; // 안전

      this.flows.push({
        vulnType:       sink.category,
        sourceLine:     taintedVar.sourceLine,
        sourceDesc:     taintedVar.sourceDesc,
        sinkLine:       lineOf(node),
        sinkDesc:       sink.description,
        sinkArgSource:  taintedVar.name,
        sanitized:      taintedVar.sanitized,
        sanitizerName:  taintedVar.sanitizerName,
        sanitizerWrong,
        message: sanitizerWrong
          ? `[TaintGuard] ${sink.description} — '${taintedVar.sanitizerName}'은 이 sink에 적합한 sanitizer가 아닙니다.`
          : `[TaintGuard] ${sink.description} — '${taintedVar.name}'은 ${taintedVar.sourceDesc}에서 유래한 검증되지 않은 입력입니다.`,
      });
    }
  }

  private findTaintedArgAtIndex(node: TSESTree.CallExpression, argIndex: number): TaintedVar | null {
    const arg = node.arguments[argIndex];
    if (!arg || arg.type === 'SpreadElement') return null;

    if (isIdentifier(arg) && this.tainted.has(arg.name))
      return this.tainted.get(arg.name)!;
    if (isTemplateLiteral(arg) || isBinaryExpr(arg))
      return this.findTaintedInExpr(arg as TSESTree.Expression);
    return null;
  }
}