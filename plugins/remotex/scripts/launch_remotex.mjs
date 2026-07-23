import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";


const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(scriptDir, "..");
const server = path.join(pluginRoot, "src", "remotex_mcp.py");

const candidates = process.platform === "win32"
  ? [
      { command: "py", prefix: ["-3", "-B"] },
      { command: "python3", prefix: ["-B"] },
      { command: "python", prefix: ["-B"] },
    ]
  : [
      { command: "python3", prefix: ["-B"] },
      { command: "python", prefix: ["-B"] },
    ];

const candidate = candidates.find(({ command, prefix }) => {
  const probe = spawnSync(command, [...prefix, "--version"], {
    cwd: pluginRoot,
    stdio: "ignore",
    windowsHide: true,
  });
  return !probe.error && probe.status === 0;
});

if (!candidate) {
  process.stderr.write("RemoteX could not find a usable Python 3 interpreter.\n");
  process.exit(127);
}

const child = spawn(candidate.command, [...candidate.prefix, server], {
  cwd: pluginRoot,
  stdio: "inherit",
  windowsHide: true,
});

child.once("error", (error) => {
  process.stderr.write(`RemoteX Python launcher failed: ${error.message}\n`);
  process.exitCode = 1;
});
child.once("exit", (code) => {
  process.exitCode = code ?? 1;
});
