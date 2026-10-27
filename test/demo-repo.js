'use strict';

// Builds a synthetic repo with backdated commits and fake credentials, for screenshots and manual poking.
// usage: node test/demo-repo.js <dir>   (dir must not exist or be empty)
const fs = require('node:fs');
const path = require('node:path');
const { fake, git, write, commit } = require('./helpers');

function build(dir) {
  fs.mkdirSync(dir, { recursive: true });
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'config', 'user.name', 'demo');
  git(dir, 'config', 'user.email', 'demo@example.invalid');
  git(dir, 'config', 'core.autocrlf', 'false');

  const start = Date.UTC(2025, 8, 1, 10, 0, 0);
  const files = {};
  const plan = {
    4: () => { files['deploy/aws.py'] = `ACCESS_KEY = "${fake.aws}"\n`; },
    11: () => { files['scripts/release.sh'] = `#!/bin/sh\nexport GH_TOKEN=${fake.github}\n`; },
    16: () => { files['.env'] = `STRIPE=${fake.stripe}\n`; },
    18: () => { delete files['.env']; },
    23: () => { files['deploy/aws.py'] = 'ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]\n'; },
    29: () => { files['infra/id.pem'] = `${fake.pem}\nMIIEfake\n`; },
    31: () => { delete files['infra/id.pem']; },
    37: () => { files['docker-compose.yml'] = `db:\n  environment:\n    password: "${fake.password}"\n`; },
    44: () => { files['scripts/release.sh'] = '#!/bin/sh\nexport GH_TOKEN="$GH_TOKEN"\n'; },
    52: () => { files['billing/notify.py'] = `HOOK = "${fake.slack}"\n`; },
  };
  const total = 64;
  const existing = new Set();
  for (let i = 0; i < total; i++) {
    const when = new Date(start + i * 4.1 * 86400000).toISOString();
    process.env.GIT_AUTHOR_DATE = when;
    process.env.GIT_COMMITTER_DATE = when;
    write(dir, `src/mod${i % 9}.py`, `# change ${i}\nVALUE = ${i}\n`);
    plan[i]?.();
    for (const f of existing) if (!(f in files)) fs.rmSync(path.join(dir, f), { force: true });
    for (const [f, body] of Object.entries(files)) write(dir, f, body);
    existing.clear();
    for (const f of Object.keys(files)) existing.add(f);
    commit(dir, `change ${i}`);
  }
}

if (require.main === module) {
  if (!process.argv[2]) {
    console.error('usage: node test/demo-repo.js <dir>');
    process.exit(2);
  }
  build(path.resolve(process.argv[2]));
}

module.exports = { build };
