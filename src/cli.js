'use strict';

const fs = require('node:fs');
const path = require('node:path');
const git = require('./git');
const { scan } = require('./scan');
const { loadIgnoreFile } = require('./ignore');
const { rules, fileRules } = require('./rules');
const output = require('./output');
const { createUi, openBrowser } = require('./ui');
const pkg = require('../package.json');

const HELP = `usage: secretscan [path] [options]
       secretscan install-hook [path] [--force] [--dry-run]
       secretscan ui [path] [--port <n>] [--no-open] [--browser <exe>]

Scans the working tree and git history of a repo for leaked secrets.
Exit code: 0 clean, 1 findings, 2 usage or runtime error.

options:
  --no-history            skip git history
  --no-tree               skip the working tree
  --rev <rev>             history revisions to scan (repeatable, default --all)
  --max-file-size <bytes> skip files / per-commit diffs bigger than this (default 1048576)
  --min-confidence <lvl>  low, medium or high (default low)
  --format <fmt>          text, json or sarif (default text)
  --baseline <file>       ignore findings whose id is listed in this file
  --write-baseline <file> write the current findings' ids to a file and exit 0
  --ignore-file <file>    ignore patterns (default <repo>/.secretscanignore)
  -h, --help, --version

ui serves a page listing the findings on 127.0.0.1 and prints the url. It opens
the OS default browser unless --no-open; --browser <exe> (or $BROWSER) launches that instead.
Its baseline button adds the selected ids to --baseline (default <repo>/.secretscan-baseline.json).

Add "secretscan:ignore" to a line to skip it.
`;

class UsageError extends Error {}

function parse(argv) {
  const o = {
    path: null, tree: true, history: true, revs: [], maxFileSize: 1048576, minConfidence: 'low',
    format: 'text', baseline: null, writeBaseline: null, ignoreFile: null, force: false, dryRun: false,
    port: 0, open: true, browser: process.env.BROWSER || null,
  };
  const val = (i, name) => {
    if (i + 1 >= argv.length) throw new UsageError(`${name} needs a value`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--no-history': o.history = false; break;
      case '--no-tree': o.tree = false; break;
      case '--rev': o.revs.push(val(i++, a)); break;
      case '--max-file-size': {
        o.maxFileSize = Number(val(i++, a));
        if (!Number.isInteger(o.maxFileSize) || o.maxFileSize < 1) throw new UsageError('bad --max-file-size');
        break;
      }
      case '--min-confidence': o.minConfidence = val(i++, a); break;
      case '--format': o.format = val(i++, a); break;
      case '--baseline': o.baseline = val(i++, a); break;
      case '--write-baseline': o.writeBaseline = val(i++, a); break;
      case '--ignore-file': o.ignoreFile = val(i++, a); break;
      case '--port': {
        o.port = Number(val(i++, a));
        if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new UsageError('bad --port');
        break;
      }
      case '--browser': o.browser = val(i++, a); break;
      case '--no-open': o.open = false; break;
      case '--force': o.force = true; break;
      case '--dry-run': o.dryRun = true; break;
      case '-h': case '--help': o.help = true; break;
      case '--version': o.version = true; break;
      default:
        if (a.startsWith('-')) throw new UsageError(`unknown option ${a}`);
        if (o.path) throw new UsageError(`unexpected argument ${a}`);
        o.path = a;
    }
  }
  if (!['low', 'medium', 'high'].includes(o.minConfidence)) throw new UsageError('bad --min-confidence');
  if (!['text', 'json', 'sarif'].includes(o.format)) throw new UsageError('bad --format');
  return o;
}

function loadBaseline(file) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    throw new UsageError(`cannot read baseline ${file}: ${e.message}`);
  }
  if (!data || !Array.isArray(data.fingerprints)) throw new UsageError(`baseline ${file} has no fingerprints array`);
  return new Set(data.fingerprints);
}

function installHook(o, out) {
  const repo = git.repoRoot(o.path || '.');
  const dir = git.hooksDir(repo);
  const file = path.join(dir, 'pre-push');
  const bin = path.resolve(__dirname, '..', 'bin', 'secretscan.js').replace(/\\/g, '/');
  const script = `#!/bin/sh\n# installed by secretscan\nexec node "${bin}" pre-push "$@"\n`;
  if (fs.existsSync(file) && !o.force) {
    throw new UsageError(`${file} already exists (use --force to overwrite)`);
  }
  if (o.dryRun) {
    out(`would write ${file}:\n${script}`);
    return 0;
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, script, { mode: 0o755 });
  out(`wrote ${file}\n`);
  return 0;
}

async function startUi(o, out) {
  const ui = createUi(o.path || '.', {
    baseline: o.baseline, ignoreFile: o.ignoreFile, maxFileSize: o.maxFileSize,
  });
  const url = await ui.start(o.port);
  out(`\nsecretscan ui:  ${url}\n(ctrl-c to stop)\n\n`);
  if (o.open) openBrowser(url, o.browser);
  return 0;
}

// Pushes only the commits the remote lacks; stdin is git's "<lref> <lsha> <rref> <rsha>" list.
function prePushRevs(stdin) {
  const zero = /^0+$/;
  const revs = [];
  for (const l of stdin.split('\n')) {
    const [, lsha, , rsha] = l.trim().split(/\s+/);
    if (!lsha || zero.test(lsha)) continue;
    if (zero.test(rsha || '0')) revs.push(lsha);
    else revs.push(`${rsha}..${lsha}`);
  }
  return revs;
}

async function main(argv, io) {
  const out = io.out;
  const err = io.err;
  try {
    const cmd = ['install-hook', 'pre-push', 'ui'].includes(argv[0]) ? argv[0] : null;
    const o = parse(cmd ? argv.slice(1) : argv);
    if (o.help) { out(HELP); return 0; }
    if (o.version) { out(`${pkg.version}\n`); return 0; }
    if (cmd === 'install-hook') return installHook(o, out);
    if (cmd === 'ui') return startUi(o, out);

    let revArgs = o.revs.length ? o.revs : ['--all'];
    if (cmd === 'pre-push') {
      const revs = prePushRevs(io.stdin ? io.stdin() : '');
      if (!revs.length) return 0;
      // a new branch is checked against what the remote already has
      const fresh = revs.filter((r) => !r.includes('..'));
      revArgs = [...revs.filter((r) => r.includes('..')), ...fresh];
      if (fresh.length) revArgs.push('--not', '--remotes');
      o.tree = false;
    }

    const repo = git.repoRoot(o.path || '.');
    const ignoreFile = o.ignoreFile || path.join(repo, '.secretscanignore');
    const result = await scan(repo, {
      tree: o.tree,
      history: o.history,
      revArgs,
      maxFileSize: o.maxFileSize,
      minConfidence: o.minConfidence,
      baseline: o.baseline && !o.writeBaseline ? loadBaseline(o.baseline) : null,
      ignorePatterns: loadIgnoreFile(ignoreFile),
    });

    if (o.writeBaseline) {
      const ids = [...new Set(result.findings.map((f) => f.fingerprint))].sort();
      fs.writeFileSync(o.writeBaseline, `${JSON.stringify({ fingerprints: ids }, null, 2)}\n`);
      out(`wrote ${ids.length} fingerprint${ids.length === 1 ? '' : 's'} to ${o.writeBaseline}\n`);
      return 0;
    }

    const ids = [...rules.map((r) => r.id), ...fileRules.map((r) => r.id)];
    if (o.format === 'json') out(output.json(result.findings));
    else if (o.format === 'sarif') out(output.sarif(result.findings, ids, pkg.version));
    else out(output.text(result.findings));
    if (cmd === 'pre-push' && result.findings.length) {
      err('secretscan: push blocked. Fix, baseline the finding, or push with --no-verify.\n');
    }
    return result.findings.length ? 1 : 0;
  } catch (e) {
    err(`secretscan: ${e.message}\n`);
    if (e instanceof UsageError) err('try secretscan --help\n');
    return 2;
  }
}

module.exports = { main, parse, prePushRevs };
