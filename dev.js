/**
 * Starts the three processes in dependency order with prefixed, colourised logs.
 * Each can also be started on its own (npm run dev:sim | dev:api | dev:ui).
 */
import { spawn } from 'node:child_process';

const COLORS = { sim: '[35m', api: '[36m', ui: '[32m', reset: '[0m' };

const services = [
  { name: 'sim', script: 'sim/server.js' },
  { name: 'api', script: 'api/server.js' },
  { name: 'ui', script: 'ui/server.js' },
];

const children = [];

function start({ name, script }) {
  const child = spawn(process.execPath, [script], { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
  const prefix = `${COLORS[name]}${name.padEnd(3)}${COLORS.reset} │ `;
  const pipe = (stream, target) => {
    let buffer = '';
    stream.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) target.write(`${prefix}${line.replace(/^\[\w+\]\s*/, '')}\n`);
    });
  };
  pipe(child.stdout, process.stdout);
  pipe(child.stderr, process.stderr);
  child.on('exit', (code) => {
    process.stdout.write(`${prefix}exited with code ${code}\n`);
    shutdown(code ?? 0);
  });
  children.push(child);
}

function shutdown(code = 0) {
  for (const child of children) if (!child.killed) child.kill('SIGTERM');
  process.exit(code);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

for (const service of services) start(service);

setTimeout(() => {
  process.stdout.write(`\n  defense-validation prototype\n  UI   http://localhost:${process.env.UI_PORT ?? 5173}\n  API  http://localhost:${process.env.API_PORT ?? 8088}\n  SIM  http://localhost:${process.env.SIM_PORT ?? 8099}\n\n`);
}, 400);
