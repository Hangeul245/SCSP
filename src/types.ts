export type VulnType = 'sqli' | 'xss' | 'cmdi' | 'path' | 'ssrf' | 'xxe' | 'redirect';
export type SinkCategory = VulnType;

export interface SourcePattern {
  type: 'call' | 'member';
  object?: string;
  property?: string;
  callee?: string;
}

export interface SinkPattern {
  type: 'call' | 'method_call';
  callee?: string;
  object?: string;
  method?: string;
  argIndex: number;
  category: SinkCategory;
  description: string;
}

export interface SanitizerPattern {
  type: 'call' | 'method_call';
  callee?: string;
  object?: string;
  method?: string;
  categories: SinkCategory[];
}

export interface TaintedVar {
  name: string;
  sourceDesc: string;
  sourceLine: number;
  sanitized: boolean;
  sanitizerName?: string;
  validForCategories: SinkCategory[];
}

export interface TaintFlow {
  vulnType: VulnType;
  sourceLine: number;
  sourceDesc: string;
  sinkLine: number;
  sinkDesc: string;
  sinkArgSource: string;
  sanitized: boolean;
  sanitizerName?: string;
  sanitizerWrong: boolean;
  message: string;
}