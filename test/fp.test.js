'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { scanLine } = require('../src/scan');

// Lines taken from false positives seen on real repos (synthetic equivalents).
test('path values and hyphenated marker strings are not secrets', () => {
  assert.deepStrictEqual(scanLine('deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root', 'a.log'), []);
  assert.deepStrictEqual(scanLine('$m = "SOMEPROJ-TEST-MARKER-7f3a9c1e-NOT-MALWARE"', 'a.yar'), []);
});
