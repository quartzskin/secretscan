'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const git = require('./git');
const { scan, scanLine, fileLevel } = require('./scan');
const { defaultIgnores } = require('./rules');
const { makeIgnore, loadIgnoreFile } = require('./ignore');

const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
};

const HINTS = {
  'aws-access-key-id': 'Deactivate the key in IAM, create a new one and update whatever used it. Check CloudTrail for use of the old key.',
  'aws-secret-access-key': 'Rotate the access key pair in IAM and review CloudTrail for activity since the date above.',
  'github-token': 'Revoke it under Settings > Developer settings, then issue a new token with the narrowest scopes.',
  'github-fine-grained-pat': 'Delete the token under Settings > Developer settings and create a replacement with fewer permissions.',
  'slack-token': 'Revoke the token in the Slack app admin page and reinstall the app to get a fresh one.',
  'slack-webhook': 'Remove the webhook in the Slack app settings and create a new one.',
  'stripe-key': 'Roll the key in the Stripe dashboard (Developers > API keys). Rolling expires the old one.',
  'google-api-key': 'Regenerate the key in Google Cloud console and add application and API restrictions.',
  jwt: 'Invalidate the session or rotate the signing secret if the token is long lived.',
  'private-key': 'Generate a new key pair, replace the public half wherever it is installed and retire the old one.',
  'private-key-file': 'Generate a new key pair and remove the old public key from every host that trusted it.',
  'credentials-in-url': 'Change the password of the account in the URL and move the credentials out of the code.',
  'generic-secret-assignment': 'Change the value at its source (service or database) and load it from the environment instead.',
  'high-entropy-string': 'Check whether this is a real credential. If it is, rotate it at its source.',
  'env-file': 'Treat every value in the file as exposed and rotate them. Keep .env out of git.',
};

function hintFor(rule) {
  return HINTS[rule] || 'Rotate the credential at its source and load it from the environment.';
}

function listCommits(repo) {
  const out = git.run(repo, ['log', '--all', '--date-order', '--reverse', '--format=%H%x09%ct%x09%s']).toString('utf8');
  return out.split('\n').filter(Boolean).map((l) => {
    const [hash, t, ...s] = l.split('\t');
    return { hash, t: Number(t), s: s.join('\t').slice(0, 100) };
  });
}

// Finds the commits whose diff removes a line (or a whole file) carrying a finding.
async function scanRemovals(repo, ignored, maxFileSize, onProgress) {
  const removed = new Map();
  let commit = null;
  let file = null;
  let state = 'none';
  let deleted = false;
  let bytes = 0;
  let commits = 0;
  const note = (fp) => {
    if (!removed.has(fp)) removed.set(fp, new Set());
    removed.get(fp).add(commit);
  };
  for await (const l of git.logPatch(repo, ['--all'])) {
    if (l.startsWith('@@COMMIT@@ ')) {
      commit = l.slice(11); file = null; state = 'none';
      if (++commits % 25 === 0) onProgress({ stage: 'removals', done: commits });
    } else if (l.startsWith('diff --git ')) {
      file = null; state = 'header'; deleted = false; bytes = 0;
    } else if (state === 'header') {
      if (l.startsWith('deleted file mode')) deleted = true;
      else if (l.startsWith('--- ')) {
        const p = l.slice(4).replace(/\t.*$/, '');
        file = p === '/dev/null' ? null : p.replace(/^a\//, '');
        if (file && ignored(file)) file = null;
        if (file && deleted) for (const f of fileLevel(file)) note(f.fingerprint);
      } else if (l.startsWith('@@')) state = 'hunk';
    } else if (state === 'hunk' && file && l.startsWith('-')) {
      bytes += l.length;
      if (bytes > maxFileSize) continue;
      for (const f of scanLine(l.slice(1), file)) note(f.fingerprint);
    }
  }
  return removed;
}

function buildMarks(findings, commits, removed) {
  const index = new Map(commits.map((c, i) => [c.hash, i]));
  const marks = [];
  const liveFps = new Set();
  const make = (f, i, removedIdx) => ({
    id: `${f.fingerprint}:${i}:${f.line}`,
    fingerprint: f.fingerprint,
    rule: f.rule,
    confidence: f.confidence,
    file: f.file,
    line: f.line,
    preview: f.preview,
    commit: f.commit ? f.commit.slice(0, 10) : null,
    start: i,
    end: removedIdx,
    hint: hintFor(f.rule),
  });
  for (const f of findings) {
    if (!f.commit || !index.has(f.commit)) continue;
    const i = index.get(f.commit);
    const gone = [...(removed.get(f.fingerprint) || [])].map((h) => index.get(h)).filter((j) => j > i);
    const end = gone.length ? Math.min(...gone) : null;
    if (end === null) liveFps.add(f.fingerprint);
    marks.push(make(f, i, end));
  }
  for (const f of findings) {
    if (!f.commit && !liveFps.has(f.fingerprint)) marks.push(make(f, commits.length, null));
  }
  return marks;
}

function readBaseline(file) {
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    return new Set(Array.isArray(data.fingerprints) ? data.fingerprints : []);
  } catch (e) {
    if (e.code === 'ENOENT') return new Set();
    throw new Error(`cannot read baseline ${file}: ${e.message}`);
  }
}

// An explicit browser is spawned directly; otherwise the OS default handler decides.
function openBrowser(url, browser) {
  const [cmd, args] = browser ? [browser, [url]]
    : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
      : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
  const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
  child.on('error', () => {});
  child.unref();
}

function createUi(repoDir, opts = {}) {
  const repo = git.repoRoot(repoDir);
  const baselineFile = opts.baseline || path.join(repo, '.secretscan-baseline.json');
  const ignoreFile = opts.ignoreFile || path.join(repo, '.secretscanignore');
  const maxFileSize = opts.maxFileSize || 1048576;
  const state = {
    status: 'idle', progress: { stage: 'starting', done: 0, total: 0 }, error: null,
    commits: [], marks: [], ignored: readBaseline(baselineFile),
  };
  const clients = new Set();
  let host = null;
  let lastSent = 0;

  const send = (event, data) => {
    for (const res of clients) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  const progress = (p) => {
    state.progress = { ...state.progress, ...p };
    const now = Date.now();
    if (now - lastSent < 80) return;
    lastSent = now;
    send('progress', state.progress);
  };

  async function runScan() {
    if (state.status === 'scanning') return;
    state.status = 'scanning';
    state.error = null;
    state.progress = { stage: 'starting', done: 0, total: 0 };
    send('progress', state.progress);
    try {
      const commits = listCommits(repo);
      const patterns = loadIgnoreFile(ignoreFile);
      const ignored = makeIgnore([...defaultIgnores, ...patterns]);
      const onProgress = (p) => progress(p.stage === 'tree' ? p : { ...p, total: commits.length });
      const result = await scan(repo, {
        tree: true, history: true, revArgs: ['--all'], maxFileSize, minConfidence: 'low',
        ignorePatterns: patterns, onProgress,
      });
      const removed = await scanRemovals(repo, ignored, maxFileSize, onProgress);
      state.commits = commits;
      state.marks = buildMarks(result.findings, commits, removed);
      state.status = 'done';
    } catch (e) {
      state.status = 'error';
      state.error = e.message;
    }
    send('done', { status: state.status });
  }

  function snapshot() {
    return {
      status: state.status,
      progress: state.progress,
      error: state.error,
      repo: path.basename(repo),
      baseline: path.basename(baselineFile),
      commits: state.commits.map((c) => ({ h: c.hash.slice(0, 10), t: c.t, s: c.s })),
      marks: state.marks.filter((m) => !state.ignored.has(m.fingerprint)),
      ignoredCount: new Set(state.marks.filter((m) => state.ignored.has(m.fingerprint)).map((m) => m.fingerprint)).size,
    };
  }

  function addToBaseline(fingerprints) {
    const known = new Set(state.marks.map((m) => m.fingerprint));
    const bad = fingerprints.filter((f) => typeof f !== 'string' || !known.has(f));
    if (!fingerprints.length || bad.length) return { error: 'fingerprints must be ids of current findings' };
    const merged = new Set([...readBaseline(baselineFile), ...fingerprints]);
    fs.writeFileSync(baselineFile, `${JSON.stringify({ fingerprints: [...merged].sort() }, null, 2)}\n`);
    for (const f of fingerprints) state.ignored.add(f);
    return { added: new Set(fingerprints).size, total: merged.size, file: path.basename(baselineFile) };
  }

  const allowedHost = (h) => host !== null && (h === `127.0.0.1:${host}` || h === `localhost:${host}`);
  const allowedOrigin = (o) => host !== null && (o === `http://127.0.0.1:${host}` || o === `http://localhost:${host}`);

  function reply(res, code, body, type = 'application/json') {
    res.writeHead(code, {
      'Content-Type': type,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    });
    res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > 65536) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c);
      });
      req.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('invalid json')); }
      });
      req.on('error', reject);
    });
  }

  async function handle(req, res) {
    if (!allowedHost(req.headers.host)) return reply(res, 403, { error: 'bad host' });
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigin(origin)) return reply(res, 403, { error: 'bad origin' });
    const url = new URL(req.url, 'http://localhost').pathname;

    if (req.method === 'GET' && STATIC[url]) {
      const [name, type] = STATIC[url];
      let body = fs.readFileSync(path.join(__dirname, 'ui', name));
      // finished scans are inlined so the first paint needs no fetch
      if (name === 'index.html') {
        const boot = state.status === 'done' ? JSON.stringify(snapshot()).replace(/</g, '\\u003c') : '';
        body = body.toString('utf8').replace('<!--boot-->', () => boot);
      }
      return reply(res, 200, body, type);
    }
    if (req.method === 'GET' && url === '/api/state') return reply(res, 200, snapshot());
    if (req.method === 'GET' && url === '/api/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
      res.write(`event: progress\ndata: ${JSON.stringify(state.progress)}\n\n`);
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return undefined;
    }
    if (req.method === 'POST' && (url === '/api/scan' || url === '/api/baseline')) {
      if (origin === undefined) return reply(res, 403, { error: 'origin required' });
      if (!/^application\/json\b/.test(req.headers['content-type'] || '')) return reply(res, 415, { error: 'json only' });
      let body;
      try { body = await readJson(req); } catch (e) { return reply(res, 400, { error: e.message }); }
      if (url === '/api/scan') {
        runScan();
        return reply(res, 202, { status: 'scanning' });
      }
      if (!body || !Array.isArray(body.fingerprints)) return reply(res, 400, { error: 'fingerprints array required' });
      const r = addToBaseline(body.fingerprints);
      return reply(res, r.error ? 400 : 200, r);
    }
    return reply(res, 404, { error: 'not found' });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => reply(res, 500, { error: e.message }));
  });

  return {
    server,
    scanDone: null,
    async start(port = 0) {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
      });
      host = server.address().port;
      this.url = `http://127.0.0.1:${host}/`;
      this.scanDone = runScan();
      return this.url;
    },
    close() {
      for (const res of clients) res.end();
      return new Promise((resolve) => { server.close(resolve); server.closeAllConnections?.(); });
    },
  };
}

module.exports = { createUi, openBrowser, buildMarks };
