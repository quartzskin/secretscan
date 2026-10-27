'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { prePushRevs } = require('../src/cli');
const { fake, git, makeRepo, write, commit, cleanup, cli } = require('./helpers');

function withRepo(fn) {
  return async () => {
    const dir = makeRepo();
    try { await fn(dir); } finally { cleanup(dir); }
  };
}

test('exit code 1 on findings, 0 when clean', withRepo((dir) => {
  write(dir, 'ok.txt', 'nothing here\n');
  commit(dir, 'ok');
  assert.strictEqual(cli([dir]).status, 0);
  write(dir, 'bad.txt', `${fake.aws}\n`);
  commit(dir, 'bad');
  const r = cli([dir]);
  assert.strictEqual(r.status, 1);
  assert.ok(r.stdout.includes('aws-access-key-id'));
  assert.ok(!r.stdout.includes(fake.aws));
}));

test('json and sarif output parse and carry no raw secret', withRepo((dir) => {
  write(dir, 'bad.txt', `${fake.github}\n`);
  commit(dir, 'bad');
  const j = cli([dir, '--format', 'json']);
  assert.strictEqual(JSON.parse(j.stdout).count, 2);
  const s = cli([dir, '--format', 'sarif']);
  const doc = JSON.parse(s.stdout);
  assert.strictEqual(doc.version, '2.1.0');
  assert.strictEqual(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'bad.txt');
  assert.ok(!j.stdout.includes(fake.github) && !s.stdout.includes(fake.github));
}));

test('--write-baseline then --baseline gives a clean run', withRepo((dir) => {
  write(dir, 'bad.txt', `${fake.aws}\n`);
  commit(dir, 'bad');
  const bl = path.join(dir, '..', `bl-${path.basename(dir)}.json`);
  try {
    const w = cli([dir, '--write-baseline', bl]);
    assert.strictEqual(w.status, 0);
    assert.strictEqual(cli([dir, '--baseline', bl]).status, 0);
  } finally { fs.rmSync(bl, { force: true }); }
}));

test('.secretscanignore is honoured', withRepo((dir) => {
  write(dir, 'gen/bad.txt', `${fake.aws}\n`);
  write(dir, '.secretscanignore', '# generated\ngen/\n');
  commit(dir, 'bad');
  assert.strictEqual(cli([dir]).status, 0);
}));

test('bad input gives exit 2 with a message', withRepo((dir) => {
  const nongit = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'plain-'));
  try {
    assert.strictEqual(cli([nongit]).status, 2);
  } finally { cleanup(nongit); }
  assert.strictEqual(cli([dir, '--bogus']).status, 2);
  assert.strictEqual(cli([dir, '--format']).status, 2);
  assert.strictEqual(cli([dir, '--format', 'xml']).status, 2);
  assert.strictEqual(cli([dir, '--max-file-size', 'abc']).status, 2);
  const missing = cli([dir, '--baseline', path.join(dir, 'nope.json')]);
  assert.strictEqual(missing.status, 2);
  assert.match(missing.stderr, /cannot read baseline/);
  write(dir, 'bl.json', '{not json');
  assert.strictEqual(cli([dir, '--baseline', path.join(dir, 'bl.json')]).status, 2);
  write(dir, 'bl2.json', '{"x":1}');
  assert.strictEqual(cli([dir, '--baseline', path.join(dir, 'bl2.json')]).status, 2);
}));

test('install-hook does nothing unless asked, never overwrites silently', withRepo((dir) => {
  const hook = path.join(dir, '.git', 'hooks', 'pre-push');
  assert.ok(!fs.existsSync(hook));
  const dry = cli(['install-hook', dir, '--dry-run']);
  assert.strictEqual(dry.status, 0);
  assert.ok(!fs.existsSync(hook));
  assert.strictEqual(cli(['install-hook', dir]).status, 0);
  assert.match(fs.readFileSync(hook, 'utf8'), /^#!\/bin\/sh\n/);
  assert.strictEqual(cli(['install-hook', dir]).status, 2);
  assert.strictEqual(cli(['install-hook', dir, '--force']).status, 0);
}));

test('prePushRevs handles new branches, updates and deletes', () => {
  const z = '0'.repeat(40);
  const a = 'a'.repeat(40);
  const b = 'b'.repeat(40);
  const input = `refs/heads/new ${a} refs/heads/new ${z}\nrefs/heads/m ${b} refs/heads/m ${a}\n(delete) ${z} refs/heads/old ${a}\n`;
  assert.deepStrictEqual(prePushRevs(input), [a, `${a}..${b}`]);
  assert.deepStrictEqual(prePushRevs(''), []);
});

test('pre-push scans only commits being pushed', withRepo((dir) => {
  write(dir, 'old.txt', `${fake.aws}\n`);
  const old = commit(dir, 'old leak');
  write(dir, 'new.txt', `${fake.stripe}\n`);
  const head = commit(dir, 'new leak');
  const input = `refs/heads/main ${head} refs/heads/main ${old}\n`;
  const r = cli(['pre-push', dir, '--format', 'json'], { input });
  assert.strictEqual(r.status, 1);
  const rules = JSON.parse(r.stdout).findings.map((f) => f.rule);
  assert.deepStrictEqual(rules, ['stripe-key']);
  assert.match(r.stderr, /push blocked/);
  assert.strictEqual(cli(['pre-push', dir], { input: '' }).status, 0);
}));

test('installed hook blocks a real push of a leaked secret', withRepo((dir) => {
  const remote = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'remote-'));
  try {
    git(remote, 'init', '-q', '--bare');
    write(dir, 'bad.txt', `${fake.github}\n`);
    commit(dir, 'leak');
    git(dir, 'remote', 'add', 'origin', remote);
    assert.strictEqual(cli(['install-hook', dir]).status, 0);
    assert.throws(() => git(dir, 'push', 'origin', 'main'), /pre-push|failed to push|secretscan/);
    git(dir, 'push', '--no-verify', 'origin', 'main');
  } finally { cleanup(remote); }
}));
