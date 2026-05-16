import { SourcePattern, SinkPattern, SanitizerPattern } from './types';

export const SOURCE_PATTERNS: SourcePattern[] = [
  { type: 'member', object: 'req',     property: 'query'   },
  { type: 'member', object: 'req',     property: 'body'    },
  { type: 'member', object: 'req',     property: 'params'  },
  { type: 'member', object: 'req',     property: 'headers' },
  { type: 'member', object: 'req',     property: 'cookies' },
  { type: 'member', object: 'req',     property: 'url'     },
  { type: 'member', object: 'request', property: 'query'   },
  { type: 'member', object: 'request', property: 'body'    },
  { type: 'member', object: 'request', property: 'params'  },
];

export const SINK_PATTERNS: SinkPattern[] = [
  { type: 'method_call', object: 'db',         method: 'query',    argIndex: 0, category: 'sqli',     description: 'SQL Injection' },
  { type: 'method_call', object: 'connection', method: 'query',    argIndex: 0, category: 'sqli',     description: 'SQL Injection' },
  { type: 'method_call', object: 'pool',       method: 'query',    argIndex: 0, category: 'sqli',     description: 'SQL Injection' },
  { type: 'method_call', object: 'client',     method: 'query',    argIndex: 0, category: 'sqli',     description: 'SQL Injection' },
  { type: 'method_call', object: 'res',        method: 'send',     argIndex: 0, category: 'xss',      description: 'XSS' },
  { type: 'method_call', object: 'res',        method: 'write',    argIndex: 0, category: 'xss',      description: 'XSS' },
  { type: 'method_call', object: 'res',        method: 'end',      argIndex: 0, category: 'xss',      description: 'XSS' },
  { type: 'call',        callee: 'eval',                            argIndex: 0, category: 'xss',      description: 'XSS/RCE (eval)' },
  { type: 'call',        callee: 'exec',                            argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
  { type: 'call',        callee: 'execSync',                        argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
  { type: 'call',        callee: 'spawn',                           argIndex: 0, category: 'cmdi',     description: 'Command Injection' },
  { type: 'call',        callee: 'readFile',                        argIndex: 0, category: 'path',     description: 'Path Traversal' },
  { type: 'call',        callee: 'readFileSync',                    argIndex: 0, category: 'path',     description: 'Path Traversal' },
  { type: 'call',        callee: 'createReadStream',                argIndex: 0, category: 'path',     description: 'Path Traversal' },
  { type: 'call',        callee: 'fetch',                           argIndex: 0, category: 'ssrf',     description: 'SSRF' },
  { type: 'method_call', object: 'axios',      method: 'get',      argIndex: 0, category: 'ssrf',     description: 'SSRF' },
  { type: 'method_call', object: 'axios',      method: 'post',     argIndex: 0, category: 'ssrf',     description: 'SSRF' },
  { type: 'method_call', object: 'http',       method: 'request',  argIndex: 0, category: 'ssrf',     description: 'SSRF' },
  { type: 'method_call', object: 'res',        method: 'redirect', argIndex: 0, category: 'redirect', description: 'Open Redirect' },
];

export const SANITIZER_PATTERNS: SanitizerPattern[] = [
  { type: 'method_call', object: 'mysql',      method: 'escape',   categories: ['sqli'] },
  { type: 'method_call', object: 'connection', method: 'escape',   categories: ['sqli'] },
  { type: 'call',        callee: 'sanitizeSql',                     categories: ['sqli'] },
  { type: 'method_call', object: 'DOMPurify',  method: 'sanitize', categories: ['xss'] },
  { type: 'call',        callee: 'escapeHtml',                      categories: ['xss'] },
  { type: 'call',        callee: 'sanitizeHtml',                    categories: ['xss'] },
  { type: 'call',        callee: 'xss',                             categories: ['xss'] },
  { type: 'call',        callee: 'shellescape',                     categories: ['cmdi'] },
  { type: 'call',        callee: 'encodeURIComponent',              categories: ['ssrf', 'redirect'] },
  { type: 'call',        callee: 'validateUrl',                     categories: ['ssrf', 'redirect'] },
];