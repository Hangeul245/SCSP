import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { PythonTaintEngine } from '../pythonengine';

// 노션 SCSP > Test code > python test code 케이스 (cmdi-1 괄호, sqli-2 탭 수정)
const HEADER = [
  'from flask import request, render_template_string, redirect, Markup',
  'import os, subprocess, cursor, requests, urllib.request, httpx, html, shlex, urllib.parse',
  '',
].join('\n');

type Case = { id: string; expect: string | null; wrong?: boolean; body: string[] };

const CASES: Case[] = [
  {
    id: 'sqli-1', expect: 'sqli',
    body: [
      'def f():',
      `    name = request.args.get('name')`,
      `    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")`,
    ],
  },
  {
    id: 'sqli-2', expect: 'sqli',
    body: [
      'def f():',
      `    user_id = request.args.get('id')`,
      '    query = f"SELECT * FROM orders WHERE user_id = {user_id}"',
      '    cursor.execute(query)',
    ],
  },
  {
    id: 'sqli-3', expect: 'sqli',
    body: [
      'def f():',
      `    keyword = request.form.get('keyword')`,
      `    q = "SELECT * FROM p WHERE name LIKE '%" + keyword + "%'"`,
      '    execute(q)',
    ],
  },
  {
    id: 'sqli-4', expect: 'sqli',
    body: [
      'def f():',
      `    raw = request.args.get('sort')`,
      '    step1 = raw',
      '    step2 = "SELECT * FROM items ORDER BY " + step1',
      '    cursor.execute(step2)',
    ],
  },
  {
    id: 'sqli-5', expect: 'sqli',
    body: [
      'def f():',
      `    email = request.GET.get('email')`,
      `    result = raw("SELECT * FROM auth_user WHERE email = '" + email + "'")`,
    ],
  },
  {
    id: 'xss-1', expect: 'xss',
    body: [
      'def f():',
      `    username = request.args.get('username')`,
      '    return render_template_string("<h1>" + username + "</h1>")',
    ],
  },
  {
    id: 'xss-2', expect: 'xss',
    body: [
      'def f():',
      `    msg = request.form.get('message')`,
      '    template = f"<div>{msg}</div>"',
      '    return render_template_string(template)',
    ],
  },
  {
    id: 'xss-3', expect: 'xss',
    body: [
      'def f():',
      `    comment = request.args.get('comment')`,
      '    return Markup(comment)',
    ],
  },
  {
    id: 'xss-4', expect: 'xss',
    body: [
      'def f():',
      `    raw = request.args.get('title')`,
      '    html_content = "<title>" + raw + "</title>"',
      '    return render_template_string(html_content)',
    ],
  },
  {
    id: 'xss-5', expect: 'xss', wrong: true,
    body: [
      'def f():',
      `    data = request.args.get('data')`,
      '    safe = sanitize_sql(data)',
      '    return render_template_string(safe)',
    ],
  },
  {
    id: 'cmdi-1', expect: 'cmdi',
    body: [
      'def f():',
      `    filename = request.args.get('file')`,
      '    os.system("cat " + filename)',
    ],
  },
  {
    id: 'cmdi-2', expect: 'cmdi',
    body: [
      'def f():',
      `    host = request.form.get('host')`,
      '    subprocess.run(f"ping -c 1 {host}", shell=True)',
    ],
  },
  {
    id: 'cmdi-3', expect: 'cmdi',
    body: [
      'def f():',
      `    cmd = request.args.get('cmd')`,
      '    result = os.popen("ls " + cmd)',
    ],
  },
  {
    id: 'cmdi-4', expect: 'cmdi',
    body: [
      'def f():',
      `    raw = request.args.get('input')`,
      '    command = "convert " + raw + " output.png"',
      '    subprocess.Popen(command, shell=True)',
    ],
  },
  {
    id: 'cmdi-5', expect: 'cmdi',
    body: [
      'def f():',
      `    expr = request.args.get('expr')`,
      '    result = eval(expr)',
    ],
  },
  {
    id: 'path-1', expect: 'path',
    body: [
      'def f():',
      `    filename = request.args.get('file')`,
      '    f = open("./uploads/" + filename)',
    ],
  },
  {
    id: 'path-2', expect: 'path',
    body: [
      'def f():',
      `    name = request.form.get('name')`,
      '    f = open(f"./data/{name}.txt")',
    ],
  },
  {
    id: 'path-3', expect: 'path',
    body: [
      'def f():',
      `    subpath = request.args.get('path')`,
      '    full = os.path.join("/var/www/files", subpath)',
      '    open(full)',
    ],
  },
  {
    id: 'path-4', expect: 'path',
    body: [
      'def f():',
      `    raw = request.args.get('doc')`,
      '    step1 = raw',
      '    path = "./docs/" + step1',
      '    open(path)',
    ],
  },
  {
    id: 'path-5', expect: 'path', wrong: true,
    body: [
      'def f():',
      `    filename = request.args.get('file')`,
      '    safe = html.escape(filename)',
      '    open("./uploads/" + safe)',
    ],
  },
  {
    id: 'ssrf-1', expect: 'ssrf',
    body: [
      'def f():',
      `    url = request.args.get('url')`,
      '    requests.get(url)',
    ],
  },
  {
    id: 'ssrf-2', expect: 'ssrf',
    body: [
      'def f():',
      `    endpoint = request.form.get('endpoint')`,
      '    requests.post(endpoint, data={})',
    ],
  },
  {
    id: 'ssrf-3', expect: 'ssrf',
    body: [
      'def f():',
      `    target = request.args.get('target')`,
      '    urllib.request.urlopen(target)',
    ],
  },
  {
    id: 'ssrf-4', expect: 'ssrf',
    body: [
      'def f():',
      `    raw = request.args.get('api')`,
      '    full_url = "https://internal/" + raw',
      '    httpx.get(full_url)',
    ],
  },
  {
    id: 'ssrf-5', expect: 'ssrf',
    body: [
      'def f():',
      `    raw = request.args.get('host')`,
      '    step1 = "http://" + raw',
      '    step2 = step1 + "/api/data"',
      '    requests.get(step2)',
    ],
  },
  {
    id: 'redirect-1', expect: 'redirect',
    body: [
      'def f():',
      `    next_url = request.args.get('next')`,
      '    return redirect(next_url)',
    ],
  },
  {
    id: 'redirect-2', expect: 'redirect',
    body: [
      'def f():',
      `    path = request.form.get('path')`,
      '    return redirect(f"https://example.com/{path}")',
    ],
  },
  {
    id: 'redirect-3', expect: 'redirect',
    body: [
      'def f():',
      `    raw = request.args.get('to')`,
      '    url = raw',
      '    return redirect(url)',
    ],
  },
  {
    id: 'redirect-4', expect: 'redirect',
    body: [
      'def f():',
      `    raw = request.args.get('dest')`,
      '    target = "https://mysite.com/" + raw',
      '    return redirect(target)',
    ],
  },
  {
    id: 'redirect-5', expect: 'redirect', wrong: true,
    body: [
      'def f():',
      `    url = request.args.get('url')`,
      '    safe = shlex.quote(url)',
      '    return redirect(safe)',
    ],
  },
  {
    id: 'safe_xss', expect: null,
    body: [
      'def f():',
      `    data = request.args.get('data')`,
      '    safe = html.escape(data)',
      '    return render_template_string(safe)',
    ],
  },
  {
    id: 'safe_cmdi', expect: null,
    body: [
      'def f():',
      `    filename = request.args.get('file')`,
      '    safe = shlex.quote(filename)',
      '    os.system("cat " + safe)',
    ],
  },
  {
    id: 'safe_ssrf', expect: null,
    body: [
      'def f():',
      `    path = request.args.get('path')`,
      '    safe = urllib.parse.quote(path)',
      '    requests.get("https://api.example.com/" + safe)',
    ],
  },
];

for (const c of CASES) {
  test(c.id, async () => {
    const engine = new PythonTaintEngine();
    const flows = await engine.analyze(HEADER + c.body.join('\n'));
    assert.equal(engine.lastError, null);
    if (c.expect === null) {
      assert.equal(flows.length, 0);
      return;
    }
    assert.equal(flows.length, 1);
    assert.equal(flows[0].vulnType, c.expect);
    assert.equal(flows[0].sanitizerWrong, c.wrong ?? false);
  });
}
