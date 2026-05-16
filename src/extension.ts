import * as vscode from 'vscode';
import { TaintEngine } from './taintEngine';
import { PythonTaintEngine } from './pythonengine';
import type { TaintFlow } from './types';

const outputChannel = vscode.window.createOutputChannel('TaintGuard 분석 로그');
const diagnosticCollection = vscode.languages.createDiagnosticCollection('taintGuard');
const lastAnalyzedVersion = new Map<string, number>();
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
const diagnosticsCache = new Map<string, vscode.Diagnostic[]>();
const engineCache = new Map<string, TaintEngine>();
const DEBOUNCE_MS = 400;

export function activate(context: vscode.ExtensionContext) {
  outputChannel.appendLine('🚀 TaintGuard 활성화됨');
  outputChannel.show(true);
  context.subscriptions.push(outputChannel);

  if (vscode.window.activeTextEditor) {
    scheduleFullAnalysis(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(e => {
      if (!isSupported(e.document.languageId)) return;
      if (e.contentChanges.length === 0) return;

      const changedLines = new Set<number>();
      for (const change of e.contentChanges) {
        const startLine = change.range.start.line + 1;
        const endLine   = change.range.end.line   + 1;
        const newLineCount = (change.text.match(/\n/g) ?? []).length;
        const actualEndLine = startLine + newLineCount;
        for (let l = startLine; l <= Math.max(endLine, actualEndLine); l++) {
          changedLines.add(l);
        }
      }
      scheduleIncrementalAnalysis(e.document, changedLines);
    }),

    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (!editor || !isSupported(editor.document.languageId)) return;
      if (lastAnalyzedVersion.get(editor.document.uri.toString()) !== editor.document.version) {
        scheduleFullAnalysis(editor.document);
      }
    }),

    vscode.workspace.onDidCloseTextDocument(doc => {
      const uri = doc.uri.toString();
      diagnosticCollection.delete(doc.uri);
      lastAnalyzedVersion.delete(uri);
      diagnosticsCache.delete(uri);
      engineCache.delete(uri);
      clearDebounce(uri);
    }),

    diagnosticCollection,
  );
}

export function deactivate() {
  diagnosticCollection.clear();
  debounceTimers.forEach(clearTimeout);
}

function scheduleFullAnalysis(doc: vscode.TextDocument) {
  const uri = doc.uri.toString();
  clearDebounce(uri);
  debounceTimers.set(uri, setTimeout(() => {
    debounceTimers.delete(uri);
    runFullAnalysis(doc);
  }, DEBOUNCE_MS));
}

function runFullAnalysis(doc: vscode.TextDocument) {
  const uri  = doc.uri.toString();
  const file = doc.uri.fsPath.split(/[\\/]/).pop();

  outputChannel.appendLine('');
  outputChannel.appendLine(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  outputChannel.appendLine(`📂 파일: ${file}`);
  outputChannel.appendLine(`🔍 전체 분석 시작...`);

  if (lastAnalyzedVersion.get(uri) === doc.version) {
    outputChannel.appendLine(`⏭️  이미 분석된 버전 — 건너뜀`);
    return;
  }
  lastAnalyzedVersion.set(uri, doc.version);

  const config       = vscode.workspace.getConfiguration('taintGuard');
  const enabledRules = config.get<string[]>('enabledRules') ?? [];
  outputChannel.appendLine(`⚙️  활성 규칙: ${enabledRules.join(', ')}`);

  let flows: TaintFlow[];
  try {
    const lang = langOf(doc.languageId);
    outputChannel.appendLine(`🌐 언어: ${lang}`);

    if (lang === 'py') {
      flows = new PythonTaintEngine().analyze(doc.getText());
    } else {
      const engine = new TaintEngine();
      engineCache.set(uri, engine);
      flows = engine.analyze(doc.getText(), lang);
    }
  } catch (err) {
    outputChannel.appendLine(`❌ 분석 오류: ${err}`);
    return;
  }

  const diagnostics = flows
    .filter(f => enabledRules.includes(f.vulnType))
    .map(f => buildDiagnostic(f, doc, config));

  outputChannel.appendLine(`✅ 분석 완료 — 탐지 흐름: ${flows.length}개 / 활성 규칙 적용 후: ${diagnostics.length}개`);

  if (flows.length > 0) {
    outputChannel.appendLine('');
    outputChannel.appendLine('📋 탐지 결과:');
    for (const f of flows) {
      const active = enabledRules.includes(f.vulnType) ? '🔴' : '⚪ (비활성 규칙)';
      outputChannel.appendLine(`  ${active} [${f.vulnType.toUpperCase()}] ${f.sinkDesc}`);
      outputChannel.appendLine(`      └ source : ${f.sourceDesc} (${f.sourceLine}번째 줄)`);
      outputChannel.appendLine(`      └ sink   : ${f.sinkLine}번째 줄 — 변수명: ${f.sinkArgSource}`);
      outputChannel.appendLine(`      💬 ${f.message}`);
      if (f.sanitizerWrong) {
        outputChannel.appendLine(`      ⚠️  잘못된 sanitizer: ${f.sanitizerName}`);
      }
    }
  } else {
    outputChannel.appendLine('  ✔️  취약점 없음');
  }

  diagnosticsCache.set(uri, diagnostics);
  diagnosticCollection.set(doc.uri, diagnostics);
  showStatusBar(diagnostics.length);
}

function scheduleIncrementalAnalysis(doc: vscode.TextDocument, changedLines: Set<number>) {
  const uri = doc.uri.toString();
  clearDebounce(uri);
  debounceTimers.set(uri, setTimeout(() => {
    debounceTimers.delete(uri);
    runIncrementalAnalysis(doc, changedLines);
  }, DEBOUNCE_MS));
}

function runIncrementalAnalysis(doc: vscode.TextDocument, changedLines: Set<number>) {
  const uri    = doc.uri.toString();
  const file   = doc.uri.fsPath.split(/[\\/]/).pop();
  const config = vscode.workspace.getConfiguration('taintGuard');
  const enabledRules = config.get<string[]>('enabledRules') ?? [];
  const lang   = langOf(doc.languageId);

  outputChannel.appendLine('');
  outputChannel.appendLine(`✏️  [증분 분석] ${file} — 변경 라인: ${[...changedLines].join(', ')}번째 줄`);

  if (lang === 'py') {
    runFullAnalysis(doc);
    return;
  }

  const engine = engineCache.get(uri);
  if (!engine) {
    outputChannel.appendLine(`⚠️  엔진 캐시 없음 — 전체 분석으로 전환`);
    runFullAnalysis(doc);
    return;
  }

  let newFlows: TaintFlow[];
  try {
    newFlows = engine.analyzeRange(doc.getText(), lang, changedLines);
  } catch (err) {
    outputChannel.appendLine(`❌ 증분 분석 오류: ${err}`);
    return;
  }

  const existing   = diagnosticsCache.get(uri) ?? [];
  const unaffected = existing.filter(d => {
    const diagLine = d.range.start.line + 1;
    return !changedLines.has(diagLine);
  });

  const incoming = newFlows
    .filter(f => enabledRules.includes(f.vulnType))
    .map(f => buildDiagnostic(f, doc, config));

  const merged = [...unaffected, ...incoming];
  diagnosticsCache.set(uri, merged);
  diagnosticCollection.set(doc.uri, merged);
  lastAnalyzedVersion.set(uri, doc.version);

  outputChannel.appendLine(`✅ 증분 분석 완료 — 신규: ${incoming.length}개 / 누적: ${merged.length}개`);

  if (newFlows.length > 0) {
    outputChannel.appendLine('');
    outputChannel.appendLine('📋 신규 탐지:');
    for (const f of newFlows.filter(nf => enabledRules.includes(nf.vulnType))) {
      outputChannel.appendLine(`  🔴 [${f.vulnType.toUpperCase()}] ${f.sinkDesc}`);
      outputChannel.appendLine(`      └ source : ${f.sourceDesc} (${f.sourceLine}번째 줄)`);
      outputChannel.appendLine(`      └ sink   : ${f.sinkLine}번째 줄 — 변수명: ${f.sinkArgSource}`);
      outputChannel.appendLine(`      💬 ${f.message}`);
      if (f.sanitizerWrong) {
        outputChannel.appendLine(`      ⚠️  잘못된 sanitizer: ${f.sanitizerName}`);
      }
    }
  } else {
    outputChannel.appendLine('  ✔️  변경 범위 내 취약점 없음');
  }

  showStatusBar(merged.length);
}

function buildDiagnostic(
  flow: TaintFlow,
  doc: vscode.TextDocument,
  config: vscode.WorkspaceConfiguration,
): vscode.Diagnostic {
  const sinkLine = Math.max(0, flow.sinkLine - 1);
  const range    = new vscode.Range(sinkLine, 0, sinkLine, doc.lineAt(sinkLine).text.length);

  const severity = flow.sanitizerWrong
    ? vscode.DiagnosticSeverity.Warning
    : severityFrom(config.get<string>('severity') ?? 'warning');

  const diag    = new vscode.Diagnostic(range, flow.message, severity);
  diag.source   = 'TaintGuard';
  diag.code     = flow.vulnType.toUpperCase();

  const srcLine = Math.max(0, flow.sourceLine - 1);
  diag.relatedInformation = [
    new vscode.DiagnosticRelatedInformation(
      new vscode.Location(
        doc.uri,
        new vscode.Range(srcLine, 0, srcLine, doc.lineAt(srcLine).text.length),
      ),
      `오염 source: ${flow.sourceDesc}`,
    ),
  ];

  return diag;
}

function showStatusBar(count: number) {
  if (count > 0) {
    vscode.window.setStatusBarMessage(`$(shield) TaintGuard: ${count}개 취약점 발견`, 5000);
  }
}

function clearDebounce(uri: string) {
  const t = debounceTimers.get(uri);
  if (t) { clearTimeout(t); debounceTimers.delete(uri); }
}

function isSupported(langId: string) {
  return ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'python'].includes(langId);
}

function langOf(langId: string): 'js' | 'ts' | 'py' {
  if (langId === 'python') return 'py';
  if (langId.startsWith('typescript')) return 'ts';
  return 'js';
}

function severityFrom(s: string): vscode.DiagnosticSeverity {
  if (s === 'error') return vscode.DiagnosticSeverity.Error;
  if (s === 'information') return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Warning;
}