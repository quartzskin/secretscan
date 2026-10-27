'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const git = require('./git');
const { rules, fileRules, defaultIgnores } = require('./rules');
const { makeIgnore } = require('./ignore');

const MAX_LINE = 20000;
const CONF = { low: 0, medium: 1, high: 2 };

function mask(secret) {
  if (secret.length <= 8) return secret.slice(0, 1) + '*'.repeat(6);
  const keep = secret.length >= 20 ? 4 : 2;
  return secret.slice(0, keep) + '*'.repeat(6) + secret.slice(-2);
}

function fingerprint(rule, file, secret) {
  return crypto.createHash('sha256').update([rule, file, secret].join('\0')).digest('hex').slice(0, 16);
}

function previewOf(line, secret) {
  let t = line.trim().split(secret).join(mask(secret));
  if (t.length > 120) {
    const i = Math.max(0, t.indexOf(mask(secret)) - 40);
    t = (i ? '...' : '') + t.slice(i, i + 110) + '...';
  }
  return t;
}

function scanLine(line, file) {
  if (line.length > MAX_LINE || line.includes('secretscan:ignore')) return [];
  const found = [];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(line))) {
      const secret = m[1] ?? m[0];
      if (m[0] === '') rule.re.lastIndex++;
      if (rule.accept && !rule.accept(secret)) continue;
      if (found.some((f) => f.secret.includes(secret) || secret.includes(f.secret))) continue;
      found.push({ rule: rule.id, confidence: rule.confidence, secret });
    }
  }
  return found.map((f) => ({
    rule: f.rule,
    confidence: f.confidence,
    file,
    preview: previewOf(line, f.secret),
    fingerprint: fingerprint(f.rule, file, f.secret),
  }));
}

function fileLevel(file) {
  return fileRules.filter((r) => r.test(file)).map((r) => ({
    rule: r.id, confidence: r.confidence, file, line: 0,
    preview: `(file name matches ${r.id})`,
    fingerprint: fingerprint(r.id, file, ''),
  }));
}

function looksBinary(buf) {
  return buf.subarray(0, 8000).includes(0);
}

function scanWorkingTree(repo, opts, ignored) {
  const out = [];
  const files = git.listFiles(repo);
  for (const [i, rel] of files.entries()) {
    if (i % 50 === 0) opts.onProgress?.({ stage: 'tree', done: i, total: files.length });
    if (ignored(rel)) continue;
    const full = path.join(repo, rel);
    let st;
    try { st = fs.statSync(full); } catch { continue; }
    if (!st.isFile() || st.size > opts.maxFileSize) continue;
    const buf = fs.readFileSync(full);
    if (looksBinary(buf)) continue;
    for (const f of fileLevel(rel)) out.push({ ...f, commit: null });
    buf.toString('utf8').split(/\r?\n/).forEach((text, i) => {
      for (const f of scanLine(text, rel)) out.push({ ...f, commit: null, line: i + 1 });
    });
  }
  return out;
}

function hunkStart(l) {
  const m = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(l);
  return m ? Number(m[1]) : 0;
}

// Only added lines are scanned: a secret is born in the commit that adds it.
async function scanHistory(repo, revArgs, opts, ignored) {
  const out = [];
  let commit = null;
  let file = null;
  let state = 'none';
  let line = 0;
  let pending = [];
  let bytes = 0;
  let skip = false;
  let commits = 0;

  const flush = () => {
    if (file && !skip) for (const f of pending) out.push(f);
    pending = [];
    bytes = 0;
    skip = false;
  };

  for await (const l of git.logPatch(repo, revArgs)) {
    if (l.startsWith('@@COMMIT@@ ')) {
      flush(); file = null; commit = l.slice(11); state = 'none';
      if (++commits % 25 === 0) opts.onProgress?.({ stage: 'history', done: commits });
    } else if (l.startsWith('diff --git ')) {
      flush(); file = null; state = 'header';
    } else if (state === 'header') {
      if (l.startsWith('+++ ')) {
        const p = l.slice(4).replace(/\t.*$/, '');
        file = p === '/dev/null' ? null : p.replace(/^b\//, '');
        if (file && ignored(file)) file = null;
        if (file) for (const f of fileLevel(file)) pending.push({ ...f, commit });
      } else if (l.startsWith('@@')) {
        state = 'hunk';
        line = hunkStart(l);
      }
    } else if (state === 'hunk') {
      if (l.startsWith('@@')) line = hunkStart(l);
      else if (l.startsWith('+') && file) {
        bytes += l.length;
        if (bytes > opts.maxFileSize) skip = true;
        if (!skip) for (const f of scanLine(l.slice(1), file)) pending.push({ ...f, commit, line });
        line++;
      }
    }
  }
  flush();
  return out;
}

function applyFilters(findings, opts) {
  const min = CONF[opts.minConfidence];
  const seen = new Set();
  return findings.filter((f) => {
    if (CONF[f.confidence] < min) return false;
    if (opts.baseline && opts.baseline.has(f.fingerprint)) return false;
    const key = [f.fingerprint, f.commit, f.line].join(':');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function scan(repoDir, opts) {
  const repo = git.repoRoot(repoDir);
  const ignored = makeIgnore([...defaultIgnores, ...(opts.ignorePatterns || [])]);
  let findings = [];
  if (opts.tree) findings.push(...scanWorkingTree(repo, opts, ignored));
  if (opts.history) {
    findings.push(...await scanHistory(repo, opts.revArgs || ['--all'], opts, ignored));
  }
  return { repo, findings: applyFilters(findings, opts) };
}

module.exports = { scan, scanLine, fileLevel, mask, CONF };
