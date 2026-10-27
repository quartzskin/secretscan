'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// Fake credentials, assembled so this file itself matches no rule.
const fake = {
  aws: 'AKIA' + 'IOSFODNN7' + 'EXAMPLE',
  github: 'gh' + 'p_' + 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6',
  stripe: 'sk' + '_live_' + '4eC39HqLyjWDarjtT1zdp7dc',
  slack: 'xox' + 'b-' + '123456789012-abcdefghijklmnop',
  pem: '-----BEGIN ' + 'RSA PRIVATE KEY-----',
  password: 'Tr0ub4dor&3' + 'xyzQ',
};

function git(dir, ...args) {
  const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretscan-'));
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'user.name', 'test');
  git(dir, 'config', 'user.email', 'test@example.invalid');
  git(dir, 'config', 'core.autocrlf', 'false');
  return dir;
}

function write(dir, rel, data) {
  const full = path.join(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, data);
}

function commit(dir, msg) {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', msg);
  return git(dir, 'rev-parse', 'HEAD');
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

const bin = path.resolve(__dirname, '..', 'bin', 'secretscan.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', ...opts });
}

module.exports = { fake, git, makeRepo, write, commit, cleanup, cli };
