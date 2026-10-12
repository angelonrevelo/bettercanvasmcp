import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8');
const engagement = readFileSync(new URL('../src/engagement.ts', import.meta.url), 'utf8');
const example = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
const check = [];

function expect(name, ok) {
  check.push({ name, ok });
}

expect('no hardcoded school host', !/ateneo\.instructure\.com|fhict\.instructure\.com/.test(src + engagement));
expect('base url is required', src.includes('Missing CANVAS_BASE_URL') && engagement.includes('Missing CANVAS_BASE_URL'));
expect('identifies itself to Canvas', src.includes('User-Agent') && engagement.includes('User-Agent'));
expect('read-only tool annotations', src.includes('readOnlyHint: true'));
expect(
  'watch diff is the local write',
  engagement.includes("readOnlyHint: item.name !== 'get_watch_diff'"),
);

for (const name of [
  'list_course',
  'get_assignment_context',
  'get_course_due_date_context',
  'get_course_quiz_lti_context',
  'get_course_group_context',
  'get_submission_feedback_context',
  'extract_file_text',
  'resolve_canvas_link',
  'request_canvas_api',
  'get_canvas_api_capability',
]) {
  expect(`tool ${name}`, src.includes(`name: '${name}'`));
}

for (const name of [
  'list_reply_need',
  'list_peer_response_requirement',
  'get_my_engagement_state',
  'get_watch_diff',
]) {
  expect(`engagement ${name}`, engagement.includes(`name: '${name}'`));
}

expect('env example names the host', /^CANVAS_BASE_URL=https:\/\/canvas\.example\.edu$/m.test(example));
expect('env example has an empty token', /^CANVAS_API_TOKEN=$/m.test(example));

const env = { PATH: process.env.PATH, HOME: process.env.HOME };
const tsx = new URL('../node_modules/.bin/tsx', import.meta.url).pathname;
const missingHost = spawnSync(tsx, ['src/index.ts'], { env, encoding: 'utf8' });
expect(
  'refuses to start without a Canvas host',
  missingHost.status === 1 && (missingHost.stderr || '').includes('Missing CANVAS_BASE_URL'),
);

const missingToken = spawnSync(tsx, ['src/engagement.ts'], {
  env: { ...env, CANVAS_BASE_URL: 'https://canvas.example.edu' },
  encoding: 'utf8',
});
expect(
  'refuses to start without a token',
  missingToken.status === 1 && (missingToken.stderr || '').includes('Missing CANVAS_API_TOKEN'),
);

const failed = check.filter((item) => !item.ok);
for (const item of check) process.stdout.write(`${item.ok ? 'ok' : 'FAIL'}  ${item.name}\n`);
if (failed.length) {
  process.stderr.write(missingHost.stderr || '');
  process.stderr.write(missingToken.stderr || '');
  process.exit(1);
}
