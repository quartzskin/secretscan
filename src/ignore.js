'use strict';

const fs = require('node:fs');

function globToRegex(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return re;
}

function compile(line) {
  let p = line.trim();
  if (!p || p.startsWith('#')) return null;
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith('/') || p.includes('/');
  p = p.replace(/^\//, '');
  const body = globToRegex(p);
  const prefix = anchored ? '^' : '(?:^|/)';
  // a match on a directory also covers everything below it
  return new RegExp(prefix + body + (dirOnly ? '/' : '(?:/|$)'));
}

function makeIgnore(patterns) {
  const res = patterns.map(compile).filter(Boolean);
  return (path) => {
    const p = path.replace(/\\/g, '/');
    return res.some((re) => re.test(p));
  };
}

function loadIgnoreFile(file) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

module.exports = { makeIgnore, loadIgnoreFile };
