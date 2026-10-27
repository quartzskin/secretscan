'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { scan, scanLine, mask } = require('../src/scan');
const { makeIgnore } = require('../src/ignore');
const { fake, git, makeRepo, write, commit, cleanup } = require('./helpers');

const base = { tree: true, history: true, maxFileSize: 1048576, minConfidence: 'low' };

function withRepo(fn) {
  return async () => {
    const dir = makeRepo();
    try { await fn(dir); } finally { cleanup(dir); }
  };
}

test('finds a secret in the working tree with file and line', withRepo(async (dir) => {
  write(dir, 'src/cfg.js', `// config\nconst k = "${fake.aws}";\n`);
  commit(dir, 'add cfg');
  const { findings } = await scan(dir, { ...base, history: false });
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].rule, 'aws-access-key-id');
  assert.strictEqual(findings[0].file, 'src/cfg.js');
  assert.strictEqual(findings[0].line, 2);
  assert.strictEqual(findings[0].commit, null);
  assert.strictEqual(findings[0].confidence, 'high');
}));

test('finds a secret that was deleted in a later commit', withRepo(async (dir) => {
  write(dir, 'a.txt', 'hello\n');
  commit(dir, 'first');
  write(dir, 'deploy.sh', `#!/bin/sh\nexport GH=${fake.github}\n`);
  const bad = commit(dir, 'oops');
  write(dir, 'deploy.sh', '#!/bin/sh\n');
  commit(dir, 'remove it');

  const tree = await scan(dir, { ...base, history: false });
  assert.strictEqual(tree.findings.length, 0);

  const { findings } = await scan(dir, base);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].commit, bad);
  assert.strictEqual(findings[0].rule, 'github-token');
  assert.strictEqual(findings[0].line, 2);
}));

test('history line numbers follow the hunk, not the diff position', withRepo(async (dir) => {
  write(dir, 'f.txt', 'a\nb\nc\nd\ne\n');
  commit(dir, 'base');
  write(dir, 'f.txt', `a\nb\nc\nd\ne\nstripe=${fake.stripe}\n`);
  commit(dir, 'add');
  const { findings } = await scan(dir, { ...base, tree: false });
  assert.strictEqual(findings[0].rule, 'stripe-key');
  assert.strictEqual(findings[0].line, 6);
}));

test('skips binary files', withRepo(async (dir) => {
  const buf = Buffer.concat([Buffer.from([0, 1, 2, 0]), Buffer.from(`key ${fake.aws}\n`)]);
  write(dir, 'blob.bin', buf);
  commit(dir, 'binary');
  const { findings } = await scan(dir, base);
  assert.deepStrictEqual(findings, []);
}));

test('skips huge files in tree and history', withRepo(async (dir) => {
  write(dir, 'big.txt', `${fake.aws}\n${'x'.repeat(5000)}\n`);
  commit(dir, 'big');
  const small = await scan(dir, { ...base, maxFileSize: 1000 });
  assert.deepStrictEqual(small.findings, []);
  const normal = await scan(dir, base);
  assert.ok(normal.findings.length >= 2);
}));

test('never exposes the full secret', withRepo(async (dir) => {
  write(dir, 'x.env.js', `a="${fake.github}"\nb="${fake.stripe}"\nc="${fake.slack}"\npassword = "${fake.password}"\n`);
  commit(dir, 'x');
  const { findings } = await scan(dir, base);
  assert.ok(findings.length >= 4);
  const dump = JSON.stringify(findings);
  for (const s of Object.values(fake)) assert.ok(!dump.includes(s), `leaked ${s.slice(0, 6)}`);
  assert.ok(findings.every((f) => f.preview.includes('******')));
}));

test('mask keeps short secrets short on both ends', () => {
  assert.strictEqual(mask('abcdefgh'), 'a******');
  assert.strictEqual(mask('abcdefghijkl'), 'ab******kl');
  assert.strictEqual(mask('a'.repeat(30)).length, 12);
});

test('.secretscanignore patterns and default ignores', withRepo(async (dir) => {
  write(dir, 'vendor/a.js', `k="${fake.aws}"\n`);
  write(dir, 'keep/b.js', `k="${fake.aws}"\n`);
  write(dir, 'package-lock.json', `"integrity": "sha512-${'aB3dE6gH9jK2'.repeat(6)}"\n`);
  commit(dir, 'files');
  const { findings } = await scan(dir, { ...base, ignorePatterns: ['# c', 'vendor/'] });
  assert.deepStrictEqual(findings.map((f) => f.file), ['keep/b.js', 'keep/b.js']);
}));

test('ignore matcher semantics', () => {
  const ig = makeIgnore(['*.log', '/root.txt', 'docs/**/*.md', 'build/']);
  assert.ok(ig('a/b/c.log'));
  assert.ok(ig('root.txt'));
  assert.ok(!ig('sub/root.txt'));
  assert.ok(ig('docs/x/y/z.md'));
  assert.ok(ig('build/out.js'));
  assert.ok(!ig('src/rebuild/out.js'));
});

test('inline secretscan:ignore and placeholders', () => {
  assert.deepStrictEqual(scanLine(`k=${fake.aws} # secretscan:ignore`, 'f'), []);
  assert.deepStrictEqual(scanLine('password = "changeme123"', 'f'), []);
  assert.deepStrictEqual(scanLine('password = process.env.DB_PASSWORD', 'f'), []);
  assert.deepStrictEqual(scanLine('token: ${{ secrets.NPM_TOKEN }}', 'f'), []);
  assert.strictEqual(scanLine(`password = "${fake.password}"`, 'f')[0].rule, 'generic-secret-assignment');
});

test('rule coverage: pem, url credentials, jwt, high entropy', () => {
  assert.strictEqual(scanLine(fake.pem, 'k.pem')[0].rule, 'private-key');
  assert.strictEqual(scanLine('db = "postgres://admin:s3cr3tPw9xQ@db.internal/app"', 'f')[0].rule, 'credentials-in-url');
  const jwt = ['eyJ' + 'hbGciOiJIUzI1NiJ9', 'eyJ' + 'zdWIiOiIxMjM0NTY3ODkwIn0', 'abcDEF123_-xyzABC987'].join('.');
  assert.strictEqual(scanLine(`auth ${jwt}`, 'f')[0].rule, 'jwt');
  const r = scanLine('x = "Zm9vQmFyOjEyMzRhYkNkRWZHaElqS2xNbk9wUXI"', 'f');
  assert.strictEqual(r[0].rule, 'high-entropy-string');
  assert.strictEqual(r[0].confidence, 'low');
  assert.deepStrictEqual(scanLine('sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709"', 'f'), []);
});

test('env files are flagged by name, examples are not', withRepo(async (dir) => {
  write(dir, '.env', 'MODE=dev\n');
  write(dir, '.env.example', 'MODE=dev\n');
  commit(dir, 'env');
  const { findings } = await scan(dir, { ...base, history: false });
  assert.deepStrictEqual(findings.map((f) => f.rule), ['env-file']);
}));

test('baseline drops known fingerprints and keeps new ones', withRepo(async (dir) => {
  write(dir, 'a.js', `k="${fake.aws}"\n`);
  commit(dir, 'a');
  const first = await scan(dir, base);
  const baseline = new Set(first.findings.map((f) => f.fingerprint));
  assert.ok(baseline.size > 0);
  assert.deepStrictEqual((await scan(dir, { ...base, baseline })).findings, []);
  write(dir, 'b.js', `k="${fake.stripe}"\n`);
  commit(dir, 'b');
  const next = await scan(dir, { ...base, baseline });
  assert.ok(next.findings.length > 0);
  assert.ok(next.findings.every((f) => f.rule === 'stripe-key'));
}));

test('min-confidence filters low findings', withRepo(async (dir) => {
  write(dir, 'a.txt', 'x = "Zm9vQmFyOjEyMzRhYkNkRWZHaElqS2xNbk9wUXI"\n');
  commit(dir, 'a');
  assert.strictEqual((await scan(dir, base)).findings.length > 0, true);
  assert.strictEqual((await scan(dir, { ...base, minConfidence: 'medium' })).findings.length, 0);
}));

test('a repo with no commits scans untracked files and empty history', withRepo(async (dir) => {
  write(dir, 'a.js', `k="${fake.aws}"\n`);
  const { findings } = await scan(dir, base);
  assert.deepStrictEqual(findings.map((f) => f.commit), [null]);
}));
