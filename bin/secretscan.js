#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const { main } = require('../src/cli');

main(process.argv.slice(2), {
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
  stdin: () => { try { return fs.readFileSync(0, 'utf8'); } catch { return ''; } },
}).then((code) => { process.exitCode = code; });
