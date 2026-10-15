import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "orca-codex-smoke-"));
const codexHome = path.join(temporary, "codex-home");
fs.mkdirSync(codexHome);

function codex(...args) {
  const result = spawnSync("codex", args, {
    cwd: temporary,
    env: { ...process.env, CODEX_HOME: codexHome },
    encoding: "utf8",
    timeout: 60_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `codex ${args.join(" ")} failed:\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}

function compareFiles(relativeDirectory, installedRoot) {
  let count = 0;
  for (const entry of fs.readdirSync(path.join(root, relativeDirectory), { withFileTypes: true })) {
    const relative = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      count += compareFiles(relative, installedRoot);
    } else if (entry.isFile()) {
      assert.deepEqual(fs.readFileSync(path.join(installedRoot, relative)), fs.readFileSync(path.join(root, relative)), `Installed ${relative} must match the source`);
      count++;
    }
  }
  return count;
}

try {
  console.log(codex("--version").trim());
  codex("plugin", "marketplace", "add", root, "--json");
  const installation = JSON.parse(codex("plugin", "add", "orca-skills", "--marketplace", "orcasecurity", "--json"));
  const installedRoot = fs.realpathSync(installation.installedPath);
  const cacheRoot = fs.realpathSync(path.join(codexHome, "plugins/cache"));
  assert(installedRoot.startsWith(cacheRoot + path.sep), "Plugin must install into the temporary cache");
  const listing = JSON.parse(codex("plugin", "list", "--marketplace", "orcasecurity", "--json"));
  assert(listing.installed.some((plugin) => plugin.pluginId === "orca-skills@orcasecurity" && plugin.enabled), "Installed plugin must be enabled");

  const skillFiles = compareFiles("skills", installedRoot);
  const prompt = codex("debug", "prompt-input", "triage Orca alert orca-1234567");
  const skillNames = fs.readdirSync(path.join(root, "skills"), { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  // Prompt paths may use an alias from the skill roots table. Both the cache
  // root and each namespaced skill must appear in this fresh, isolated prompt.
  assert(prompt.includes(path.join(installedRoot, "skills")), "Codex must discover skills from the temporary installed cache");
  for (const skillName of skillNames) {
    assert(prompt.includes(`orca-skills:${skillName}:`), `Codex must discover installed ${skillName}`);
  }
  console.log(`Codex root-plugin smoke test passed: ${skillNames.length} skills discovered; ${skillFiles} skill and reference files match.`);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
