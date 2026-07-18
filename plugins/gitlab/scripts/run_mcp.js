'use strict';

const path = require('path');
const { spawn } = require('child_process');

const script = path.resolve(__dirname, '..', 'src', 'gitlab_mcp.py');
const candidates = process.platform === 'win32'
  ? [['py', ['-3']], ['python', []], ['python3', []]]
  : [['python3', []], ['python', []]];

let index = 0;

function launchNext() {
  if (index >= candidates.length) {
    process.stderr.write('No usable Python 3 interpreter was found for the GitLab MCP server.\n');
    process.exit(127);
    return;
  }
  const [command, prefix] = candidates[index++];
  const child = spawn(command, [...prefix, script], {
    stdio: 'inherit',
    windowsHide: true,
  });
  let spawnFailed = false;
  child.once('error', (error) => {
    spawnFailed = true;
    if (error && error.code === 'ENOENT') {
      launchNext();
      return;
    }
    process.stderr.write(`Failed to start ${command}: ${error.message}\n`);
    process.exit(127);
  });
  child.once('exit', (code, signal) => {
    if (spawnFailed) return;
    if (signal) {
      process.stderr.write(`GitLab MCP Python process ended with signal ${signal}.\n`);
      process.exit(1);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

launchNext();
