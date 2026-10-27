'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { createUi } = require('../src/ui');
const { parse } = require('../src/cli');
const { fake, makeRepo, write, commit, cleanup } = require('./helpers');

function request(ui, method, url, { headers = {}, body } = {}) {
  const port = new URL(ui.url).port;
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: url, headers: { Host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode, text, headers: res.headers }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function post(ui, url, obj, headers = {}) {
  return request(ui, 'POST', url, {
    headers: { 'Content-Type': 'application/json', Origin: ui.url.replace(/\/$/, ''), ...headers },
    body: JSON.stringify(obj),
  });
}

// Leak history: aws key added then removed, github token still present.
function withUi(fn) {
  return async () => {
    const dir = makeRepo();
    const ui = createUi(dir);
    try {
      write(dir, 'a.txt', 'start\n');
      commit(dir, 'start');
      write(dir, 'aws.txt', `${fake.aws}\n`);
      commit(dir, 'add aws');
      write(dir, 'gh.txt', `${fake.github}\n`);
      commit(dir, 'add github');
      write(dir, 'aws.txt', 'gone\n');
      commit(dir, 'remove aws');
      await ui.start(0);
      await ui.scanDone;
      await fn(ui, dir);
    } finally {
      await ui.close();
      cleanup(dir);
    }
  };
}

test('state shows exposure spans and never carries a raw secret', withUi(async (ui) => {
  const r = await request(ui, 'GET', '/api/state');
  assert.strictEqual(r.status, 200);
  for (const s of Object.values(fake)) assert.ok(!r.text.includes(s));
  const s = JSON.parse(r.text);
  assert.strictEqual(s.status, 'done');
  assert.strictEqual(s.commits.length, 4);
  const aws = s.marks.find((m) => m.rule === 'aws-access-key-id');
  assert.strictEqual(aws.start, 1);
  assert.strictEqual(aws.end, 3);
  assert.match(aws.preview, /\*\*\*\*\*\*/);
  const gh = s.marks.find((m) => m.rule === 'github-token');
  assert.strictEqual(gh.start, 2);
  assert.strictEqual(gh.end, null);
  assert.ok(aws.hint.length > 10);
}));

test('static assets are served and carry a CSP', withUi(async (ui) => {
  const page = await request(ui, 'GET', '/');
  assert.strictEqual(page.status, 200);
  assert.match(page.headers['content-security-policy'], /default-src 'self'/);
  assert.ok(!/https?:\/\/(?!127\.0\.0\.1)/.test(page.text));
  assert.strictEqual((await request(ui, 'GET', '/app.js')).status, 200);
  assert.strictEqual((await request(ui, 'GET', '/style.css')).status, 200);
  assert.strictEqual((await request(ui, 'GET', '/nope')).status, 404);
}));

test('page is a plain table with the finished scan inlined and masked', withUi(async (ui) => {
  const page = await request(ui, 'GET', '/');
  assert.match(page.text, /<table id="findings"/);
  assert.match(page.text, /<progress /);
  assert.match(page.text, /"status":"done"/);
  assert.ok(!page.text.includes('<!--boot-->'));
  for (const s of Object.values(fake)) assert.ok(!page.text.includes(s));
  const css = await request(ui, 'GET', '/style.css');
  assert.ok(css.text.length < 1000);
  assert.ok(!/gradient|animation|@font-face/.test(css.text));
}));

test('foreign Host and Origin are rejected', withUi(async (ui) => {
  const port = new URL(ui.url).port;
  for (const host of ['evil.example', `evil.example:${port}`, `127.0.0.1:${Number(port) + 1}`]) {
    assert.strictEqual((await request(ui, 'GET', '/api/state', { headers: { Host: host } })).status, 403, host);
  }
  const bad = await request(ui, 'GET', '/api/state', { headers: { Origin: 'http://evil.example' } });
  assert.strictEqual(bad.status, 403);
  assert.ok(!bad.text.includes('commits'));
  const rebind = await post(ui, '/api/baseline', { fingerprints: ['x'] }, { Origin: 'http://evil.example' });
  assert.strictEqual(rebind.status, 403);
  assert.strictEqual((await request(ui, 'GET', '/api/state', { headers: { Host: `localhost:${port}` } })).status, 200);
}));

test('POST needs an Origin, a json body and known fingerprints', withUi(async (ui, dir) => {
  const noOrigin = await request(ui, 'POST', '/api/baseline', {
    headers: { 'Content-Type': 'application/json' }, body: '{"fingerprints":["x"]}',
  });
  assert.strictEqual(noOrigin.status, 403);
  const form = await request(ui, 'POST', '/api/baseline', {
    headers: { 'Content-Type': 'text/plain', Origin: ui.url.replace(/\/$/, '') }, body: '{}',
  });
  assert.strictEqual(form.status, 415);
  const junk = await request(ui, 'POST', '/api/baseline', {
    headers: { 'Content-Type': 'application/json', Origin: ui.url.replace(/\/$/, '') }, body: '{nope',
  });
  assert.strictEqual(junk.status, 400);
  assert.strictEqual((await post(ui, '/api/baseline', {})).status, 400);
  assert.strictEqual((await post(ui, '/api/baseline', { fingerprints: [] })).status, 400);
  assert.strictEqual((await post(ui, '/api/baseline', { fingerprints: ['../../etc'] })).status, 400);
  assert.strictEqual((await post(ui, '/api/baseline', { fingerprints: [42] })).status, 400);
  assert.ok(!fs.existsSync(path.join(dir, '.secretscan-baseline.json')));
}));

test('baseline endpoint writes the existing baseline format and hides the finding', withUi(async (ui, dir) => {
  const s = JSON.parse((await request(ui, 'GET', '/api/state')).text);
  const gh = s.marks.find((m) => m.rule === 'github-token');
  const r = await post(ui, '/api/baseline', { fingerprints: [gh.fingerprint] });
  assert.strictEqual(r.status, 200);
  const file = path.join(dir, '.secretscan-baseline.json');
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { fingerprints: [gh.fingerprint] });
  const after = JSON.parse((await request(ui, 'GET', '/api/state')).text);
  assert.ok(!after.marks.some((m) => m.fingerprint === gh.fingerprint));
  assert.strictEqual(after.ignoredCount, 1);
  const aws = after.marks.find((m) => m.rule === 'aws-access-key-id');
  await post(ui, '/api/baseline', { fingerprints: [aws.fingerprint] });
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).fingerprints.length, 2);
}));

test('events stream reports progress and completion on rescan', withUi(async (ui) => {
  const port = new URL(ui.url).port;
  const seen = [];
  await new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/api/events', headers: { Host: `127.0.0.1:${port}` } }, (res) => {
      assert.match(res.headers['content-type'], /text\/event-stream/);
      res.setEncoding('utf8');
      res.on('data', (c) => {
        seen.push(c);
        if (seen.length === 1) post(ui, '/api/scan', {}).catch(reject);
        if (c.includes('event: done')) { req.destroy(); resolve(); }
      });
    });
    req.on('error', (e) => { if (e.code !== 'ECONNRESET') reject(e); });
  });
  assert.ok(seen.join('').includes('event: progress'));
}));

test('uncommitted leaks sit in the working tree slot', async () => {
  const dir = makeRepo();
  const ui = createUi(dir);
  try {
    write(dir, 'a.txt', 'x\n');
    commit(dir, 'x');
    write(dir, 'new.txt', `${fake.stripe}\n`);
    await ui.start(0);
    await ui.scanDone;
    const s = JSON.parse((await request(ui, 'GET', '/api/state')).text);
    assert.strictEqual(s.marks.length, 1);
    assert.strictEqual(s.marks[0].commit, null);
    assert.strictEqual(s.marks[0].start, 1);
    assert.strictEqual(s.marks[0].end, null);
  } finally {
    await ui.close();
    cleanup(dir);
  }
});

test('a repo with no commits scans without error', async () => {
  const dir = makeRepo();
  const ui = createUi(dir);
  try {
    await ui.start(0);
    await ui.scanDone;
    const s = JSON.parse((await request(ui, 'GET', '/api/state')).text);
    assert.strictEqual(s.status, 'done');
    assert.deepStrictEqual(s.marks, []);
  } finally {
    await ui.close();
    cleanup(dir);
  }
});

test('ui options parse and reject bad ports', () => {
  assert.strictEqual(parse(['--port', '8123', '--no-open']).port, 8123);
  assert.strictEqual(parse(['--no-open']).open, false);
  assert.strictEqual(parse(['--browser', 'librewolf.exe']).browser, 'librewolf.exe');
  assert.throws(() => parse(['--browser']), /needs a value/);
  assert.throws(() => parse(['--port', '99999']), /bad --port/);
  assert.throws(() => parse(['--port', 'x']), /bad --port/);
  assert.throws(() => parse(['--port']), /needs a value/);
});
