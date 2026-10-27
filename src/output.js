'use strict';

const LEVEL = { high: 'error', medium: 'warning', low: 'note' };

function where(f) {
  const c = f.commit ? f.commit.slice(0, 10) : 'worktree';
  return `${f.file}:${f.line} [${c}]`;
}

function text(findings) {
  if (!findings.length) return 'no findings\n';
  const lines = findings.map((f) =>
    `${f.confidence.padEnd(6)} ${f.rule}  ${where(f)}\n       ${f.preview}\n       id ${f.fingerprint}`);
  return `${lines.join('\n')}\n\n${findings.length} finding${findings.length === 1 ? '' : 's'}\n`;
}

function json(findings) {
  return `${JSON.stringify({ count: findings.length, findings }, null, 2)}\n`;
}

function sarif(findings, ruleIds, version) {
  const doc = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'secretscan', version, rules: ruleIds.map((id) => ({ id })) } },
      results: findings.map((f) => ({
        ruleId: f.rule,
        level: LEVEL[f.confidence],
        message: { text: `${f.rule} (${f.confidence}): ${f.preview}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: Math.max(f.line, 1) },
          },
        }],
        partialFingerprints: { secretscan: f.fingerprint },
        properties: { commit: f.commit },
      })),
    }],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

module.exports = { text, json, sarif };
