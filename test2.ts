function renderUserProfile() {
  const username = location.search;           // SOURCE: location.search
  const bio      = location.hash;             // SOURCE: location.hash

  document.getElementById('name')!.innerHTML = username;   // SINK: XSS ← 감지 대상
  document.getElementById('bio')!.innerHTML  = bio;  }

// ── 더미 선언 (타입 오류 방지용) ────────────────────────────────
declare const db:        { query: (q: string) => void };
declare const fs:        { readFile: (p: string, enc: string, cb: () => void) => void };
declare const fetchData: (url: string, cb: (r: string) => void) => void;
declare function escapeHtml(s: string): string;