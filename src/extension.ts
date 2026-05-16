
import * as vscode from 'vscode';
import { TaintEngine } from './taintEngine';
import type { TaintFlow } from './types';

const diagnosticCollection = vscode.languages.createDiagnosticCollection('taintGuard');
const lastAnalyzedVersion  = new Map<string, number>();
const debounceTimers       = new Map<string, ReturnType<typeof setTimeout>>();
const DEBOUNCE_MS = 600;

export function activate(context: vscode.ExtensionContext) {
  if (vscode.window.activeTextEditor) {
    scheduleAnalysis(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    // 수정 감지 — 실제 내용 변경만 (커서 이동 등 제외)
    vscode.workspace.onDidChangeTextDocument(e => {
      if (!isSupported(e.document.languageId)) return;
      if (e.contentChanges.length === 0) return;
      scheduleAnalysis(e.document);
    }),

    // 에디터 전환 — 미분석 문서만
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (!editor || !isSupported(editor.document.languageId)) return;
      if (lastAnalyzedVersion.get(editor.document.uri.toString()) !== editor.document.version) {
        scheduleAnalysis(editor.document);
      }
    }),

    // 문서 닫힘 — 진단 및 캐시 정리
    vscode.workspace.onDidCloseTextDocument(doc => {
      const uri = doc.uri.toString();
      diagnosticCollection.delete(doc.uri);
      lastAnalyzedVersion.delete(uri);
      clearDebounce(uri);
    }),

    diagnosticCollection,
  );
}

export function deactivate() {
  diagnosticCollection.clear();
  debounceTimers.forEach(clearTimeout);
}

// ─── 스케줄링 ─────────────────────────────────────────────────────────────

function scheduleAnalysis(doc: vscode.TextDocument) {
  const uri = doc.uri.toString();
  clearDebounce(uri);
  debounceTimers.set(uri, setTimeout(() => {
    debounceTimers.delete(uri);
    runAnalysis(doc);
  }, DEBOUNCE_MS));
}

function clearDebounce(uri: string) {
  const t = debounceTimers.get(uri);
  if (t) { clearTimeout(t); debounceTimers.delete(uri); }
}

// ─── 분석 ─────────────────────────────────────────────────────────────────

function runAnalysis(doc: vscode.TextDocument) {
  const uri = doc.uri.toString();
  if (lastAnalyzedVersion.get(uri) === doc.version) return;
  lastAnalyzedVersion.set(uri, doc.version);

  const config       = vscode.workspace.getConfiguration('taintGuard');
  const enabledRules = config.get<string[]>('enabledRules') ?? [];

  let flows: TaintFlow[];
  try {
    flows = new TaintEngine().analyze(doc.getText(), langOf(doc.languageId));
  } catch (err) {
    console.error('[TaintGuard]', err);
    return;
  }

  const diagnostics = flows
    .filter(f => enabledRules.includes(f.vulnType))
    .map(f => buildDiagnostic(f, doc, config));

  diagnosticCollection.set(doc.uri, diagnostics);

  if (diagnostics.length > 0) {
    vscode.window.setStatusBarMessage(
      `$(shield) TaintGuard: ${diagnostics.length}개 취약점 발견`, 5000
    );
  }
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

  // Problems 패널에서 클릭하면 source 라인으로 이동
  const srcLine = Math.max(0, flow.sourceLine - 1);
  diag.relatedInformation = [
    new vscode.DiagnosticRelatedInformation(
      new vscode.Location(doc.uri, new vscode.Range(srcLine, 0, srcLine, doc.lineAt(srcLine).text.length)),
      `오염 source: ${flow.sourceDesc}`,
    ),
  ];

  return diag;
}

// ─── 유틸 ─────────────────────────────────────────────────────────────────

function isSupported(langId: string) {
  return ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'].includes(langId);
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