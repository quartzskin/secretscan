'use strict';

const $ = (id) => document.getElementById(id);
const data = { marks: [], status: 'idle' };
const checked = new Set();
let current = null;

const STAGES = { tree: 'reading files', history: 'reading history', removals: 'tracing removals' };

function cell(text, cls) {
  const td = document.createElement('td');
  td.textContent = text;
  if (cls) td.className = cls;
  return td;
}

function showProgress(p) {
  $('progress-line').hidden = false;
  $('bar').max = p.total || 100;
  if (p.total) $('bar').value = Math.min(p.done, p.total);
  else $('bar').removeAttribute('value');
  const unit = p.stage === 'tree' ? 'files' : 'commits';
  const label = STAGES[p.stage] || 'starting';
  $('progress-label').textContent = p.total ? `${label}: ${p.done} / ${p.total} ${unit}` : label;
}

function shown() {
  const q = $('filter').value.trim().toLowerCase();
  const liveOnly = $('live-only').checked;
  return data.marks.filter((m) => {
    if (liveOnly && m.end !== null) return false;
    if (!q) return true;
    return [m.file, m.rule, m.commit || 'worktree', m.confidence, m.preview].some((s) => s.toLowerCase().includes(q));
  });
}

function render() {
  const marks = shown().sort((a, b) => a.start - b.start || a.file.localeCompare(b.file) || a.line - b.line);
  const rows = $('rows');
  rows.replaceChildren();
  for (const m of marks) {
    const tr = document.createElement('tr');
    if (m.id === current) tr.className = 'picked';
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = checked.has(m.fingerprint);
    box.setAttribute('aria-label', `select ${m.file}`);
    box.addEventListener('change', () => {
      if (box.checked) checked.add(m.fingerprint); else checked.delete(m.fingerprint);
      syncButtons();
    });
    box.addEventListener('click', (e) => e.stopPropagation());
    const pick = document.createElement('td');
    pick.append(box);
    tr.append(pick, cell(m.commit || 'worktree', 'mono'), cell(m.line ? `${m.file}:${m.line}` : m.file, 'mono'),
      cell(m.rule), cell(m.confidence), cell(m.preview, 'mono'), cell(m.end === null ? 'present' : 'removed'));
    tr.addEventListener('click', () => { current = current === m.id ? null : m.id; render(); });
    rows.append(tr);
  }
  $('findings').hidden = data.status !== 'done' || !marks.length;
  const m = data.marks.find((x) => x.id === current);
  $('detail').textContent = m ? `${m.rule}: ${m.hint}` : '';
  syncButtons();
  if (data.status === 'done') {
    $('status').textContent = !data.marks.length ? 'No findings.'
      : `${marks.length} of ${data.marks.length} shown, ${data.ignoredCount} hidden by ${data.baseline}.`;
  }
}

function syncButtons() {
  $('ignore').disabled = !checked.size;
  const marks = shown();
  $('all').checked = marks.length > 0 && marks.every((m) => checked.has(m.fingerprint));
}

async function load(boot) {
  const s = boot || await (await fetch('/api/state')).json();
  Object.assign(data, s);
  document.title = `secretscan: ${s.repo}`;
  $('repo').textContent = s.repo;
  $('controls').hidden = s.status !== 'done';
  $('progress-line').hidden = s.status !== 'scanning';
  if (s.status === 'scanning') {
    showProgress(s.progress);
    $('status').textContent = 'Scanning...';
  } else if (s.status === 'error') {
    $('status').textContent = `Scan failed: ${s.error}`;
  } else if (s.status === 'done' && !s.commits.length && !s.marks.length) {
    $('status').textContent = 'No commits and no findings.';
  }
  const known = new Set(data.marks.map((m) => m.fingerprint));
  for (const f of checked) if (!known.has(f)) checked.delete(f);
  render();
}

async function post(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return { ok: res.ok, body: await res.json() };
}

$('filter').addEventListener('input', render);
$('live-only').addEventListener('change', render);
$('controls').addEventListener('submit', (e) => e.preventDefault());
$('all').addEventListener('change', (e) => {
  for (const m of shown()) {
    if (e.target.checked) checked.add(m.fingerprint); else checked.delete(m.fingerprint);
  }
  render();
});
$('ignore').addEventListener('click', async () => {
  const r = await post('/api/baseline', { fingerprints: [...checked] });
  if (!r.ok) {
    $('status').textContent = r.body.error || 'could not write baseline';
    return;
  }
  checked.clear();
  current = null;
  await load();
  $('status').textContent = `Added ${r.body.added} to ${r.body.file} (${r.body.total} in file). The credentials still need rotating.`;
});
$('rescan').addEventListener('click', async () => {
  await post('/api/scan', {});
  data.status = 'scanning';
  current = null;
  $('controls').hidden = true;
  $('findings').hidden = true;
  $('status').textContent = 'Scanning...';
  showProgress({ stage: 'starting', done: 0, total: 0 });
});

const events = new EventSource('/api/events');
events.addEventListener('progress', (e) => { if (data.status === 'scanning') showProgress(JSON.parse(e.data)); });
events.addEventListener('done', () => load());
const boot = $('boot').textContent.trim();
load(boot ? JSON.parse(boot) : null);
