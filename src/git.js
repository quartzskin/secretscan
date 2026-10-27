'use strict';

const { spawn, spawnSync } = require('node:child_process');

function run(repo, args) {
  const r = spawnSync('git', ['-C', repo, '-c', 'core.quotepath=off', ...args], {
    encoding: 'buffer', maxBuffer: 256 * 1024 * 1024,
  });
  if (r.error) throw new Error(`cannot run git: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${r.stderr.toString().trim()}`);
  return r.stdout;
}

function repoRoot(dir) {
  return run(dir, ['rev-parse', '--show-toplevel']).toString().trim();
}

function listFiles(repo) {
  const out = run(repo, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']).toString('utf8');
  return [...new Set(out.split('\0').filter(Boolean))];
}

function hooksDir(repo) {
  return run(repo, ['rev-parse', '--path-format=absolute', '--git-path', 'hooks']).toString().trim();
}

// Streams `git log -p` line by line so a big history is never held in memory.
async function* logPatch(repo, revArgs) {
  const args = ['-C', repo, '-c', 'core.quotepath=off', 'log', '-p', '-U0', '--no-color', '--no-ext-diff',
    '--no-textconv', '--no-renames', '--format=@@COMMIT@@ %H', ...revArgs, '--'];
  const child = spawn('git', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let err = '';
  child.stderr.on('data', (d) => { err += d; });
  const exited = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  child.stdout.setEncoding('utf8');
  let rest = '';
  for await (const chunk of child.stdout) {
    const parts = (rest + chunk).split('\n');
    rest = parts.pop();
    for (const l of parts) yield l.endsWith('\r') ? l.slice(0, -1) : l;
  }
  if (rest) yield rest;
  const code = await exited;
  if (code !== 0) throw new Error(`git log failed: ${err.trim()}`);
}

module.exports = { run, repoRoot, listFiles, hooksDir, logPatch };
