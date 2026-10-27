'use strict';

function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const PLACEHOLDER = /(example|changeme|change_me|placeholder|your[_-]?|dummy|sample|redacted|xxxx|\*\*\*\*|todo|fixme|password|secret|token|none|null|undefined|true|false)/i;

function looksLikeCode(v) {
  return /^[$<{%/~.]/.test(v) || /[()]/.test(v) || /^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+$/.test(v) || /^\w+\[/.test(v);
}

// Specific rules trust the pattern; generic ones need entropy and a placeholder check.
const rules = [
  { id: 'aws-access-key-id', confidence: 'high', re: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b/g },
  {
    id: 'aws-secret-access-key', confidence: 'high',
    re: /aws.{0,20}?secret.{0,20}?[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi,
  },
  { id: 'github-token', confidence: 'high', re: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g },
  { id: 'github-fine-grained-pat', confidence: 'high', re: /\b(github_pat_[A-Za-z0-9_]{50,255})\b/g },
  { id: 'slack-token', confidence: 'high', re: /\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g },
  {
    id: 'slack-webhook', confidence: 'high',
    re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/g,
  },
  { id: 'stripe-key', confidence: 'high', re: /\b([sr]k_live_[0-9a-zA-Z]{20,99})\b/g },
  { id: 'google-api-key', confidence: 'high', re: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  {
    id: 'jwt', confidence: 'medium',
    re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g,
  },
  {
    id: 'private-key', confidence: 'high',
    re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/g,
  },
  {
    id: 'credentials-in-url', confidence: 'medium',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/"']+:([^\s:@/"']{6,})@[^\s/"']+/gi,
    accept: (v) => !PLACEHOLDER.test(v) && !looksLikeCode(v) && entropy(v) >= 2.5,
  },
  {
    id: 'generic-secret-assignment', confidence: 'medium',
    re: /[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?key|credential)[\w.-]*["']?\s*[:=]>?\s*["']?([^\s"',;]{8,})/gi,
    accept: (v) => !PLACEHOLDER.test(v) && !looksLikeCode(v) && entropy(v) >= 3.0,
  },
  {
    id: 'high-entropy-string', confidence: 'low',
    re: /(?<![A-Za-z0-9+/_=-])([A-Za-z0-9+/_=-]{24,})(?![A-Za-z0-9+/_=-])/g,
    accept: (v) => /[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v) && !/^[\w./-]+\.(js|ts|py|json|md)$/.test(v) && (v.match(/[-_]/g) || []).length < 4 && entropy(v) >= 4.2,
  },
];

// Whole-file rules, matched on the path (line 0).
const fileRules = [
  {
    id: 'env-file', confidence: 'medium',
    test: (p) => /(^|\/)\.env(\.[\w-]+)?$/.test(p) && !/\.(example|sample|template|dist)$/.test(p),
  },
  { id: 'private-key-file', confidence: 'medium', test: (p) => /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/.test(p) },
];

const defaultIgnores = [
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '*.lock', '*.min.js', '*.min.css', '*.map', '.git/',
];

module.exports = { rules, fileRules, defaultIgnores, entropy };
