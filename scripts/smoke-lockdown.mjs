import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';

const envPath = '/Users/angelonrevelo/Code/college/mcp-servers/canvas/.env';
const env = {};
for (const line of readFileSync(envPath, 'utf8').split('\n')) {
  const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
  if (!match) continue;
  env[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, '');
}
if (!env.CANVAS_BASE_URL || !env.CANVAS_API_TOKEN) {
  console.error('missing host or token');
  process.exit(1);
}

const child = spawn('node_modules/.bin/tsx', ['src/index.ts'], {
  cwd: '/Users/angelonrevelo/Code/bettercanvasmcp',
  env: { ...process.env, CANVAS_BASE_URL: env.CANVAS_BASE_URL, CANVAS_API_TOKEN: env.CANVAS_API_TOKEN, CANVAS_COURSE_ID: process.argv[2] ?? '' },
  stdio: ['pipe', 'pipe', 'inherit'],
});

const pending = new Map();
let nextId = 0;
const rl = createInterface({ input: child.stdout });
let started = false;

function call(name, args = {}) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n');
    setTimeout(() => reject(new Error(`timeout calling ${name}`)), 60000);
  });
}

const toolName = process.argv[3] ?? 'get_lockdown_quiz_access';
const toolArgs = process.argv[4] ? JSON.parse(process.argv[4]) : {};

rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  } else if (!started && msg.id === 1) {
    started = true;
    (async () => {
      const result = await call(toolName, toolArgs);
      const text = result?.result?.content?.[0]?.text ?? JSON.stringify(result);
      const parsed = (() => { try { return JSON.parse(text); } catch { return text; } })();
      console.log(JSON.stringify(parsed, null, 2).slice(0, 200000));
      child.kill();
      process.exit(0);
    })().catch((err) => { console.error('FAIL', err.message); child.kill(); process.exit(1); });
  }
});

child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '1.0', capabilities: {}, clientInfo: { name: 't', version: '0' } } }) + '\n');
child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
