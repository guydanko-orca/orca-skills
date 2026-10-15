import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "orca-packaging-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const name of [".agents", ".claude-plugin", ".codex-plugin", ".cursor-plugin", "skills", "scripts", "package.json", "README.md", "CONTRIBUTING.md"]) {
    fs.cpSync(path.join(root, name), path.join(directory, name), { recursive: true });
  }
  updateJson(directory, ".agents/plugins/marketplace.json", (catalog) => {
    catalog.plugins.find((entry) => entry.name === "orca-skills").source.path = "./";
  });
  return directory;
}

function updateJson(directory, file, update) {
  const target = path.join(directory, file);
  const value = JSON.parse(fs.readFileSync(target, "utf8"));
  update(value);
  fs.writeFileSync(target, JSON.stringify(value, null, 2) + "\n");
}

function validate(directory) {
  return spawnSync(process.execPath, [path.join(directory, "scripts/validate-packaging.mjs")], { encoding: "utf8" });
}

function expectFailure(directory, message) {
  const result = validate(directory);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, message);
  assert.doesNotMatch(result.stderr, /\n\s+at /, "report validation errors without a stack trace");
}

test("accepts a root plugin with every current skill and no duplicate tree", (t) => {
  const result = validate(fixture(t));
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("discovers new skills without a hardcoded count", (t) => {
  const directory = fixture(t);
  fs.mkdirSync(path.join(directory, "skills/orca-new-skill"));
  fs.writeFileSync(path.join(directory, "skills/orca-new-skill/SKILL.md"), "---\nname: orca-new-skill\ndescription: Test a new workflow.\n---\n\nTest workflow.\n");
  const result = validate(directory);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("rejects a marketplace pointing at a copied plugin", (t) => {
  const directory = fixture(t);
  updateJson(directory, ".agents/plugins/marketplace.json", (catalog) => {
    catalog.plugins[0].source.path = "./plugins/orca-skills";
  });
  expectFailure(directory, /must point to the repository root/);
});

test("rejects a legacy Codex manifest", (t) => {
  const directory = fixture(t);
  fs.mkdirSync(path.join(directory, ".codex"));
  fs.writeFileSync(path.join(directory, ".codex/plugin.json"), "{}\n");
  expectFailure(directory, /legacy.*\.codex\/plugin.json/i);
});

test("rejects a redundant plugin copy", (t) => {
  const directory = fixture(t);
  fs.mkdirSync(path.join(directory, "plugins/orca-skills"), { recursive: true });
  expectFailure(directory, /plugins\/orca-skills.*duplicate/i);
});

test("reports a missing skills directory", (t) => {
  const directory = fixture(t);
  fs.rmSync(path.join(directory, "skills"), { recursive: true });
  expectFailure(directory, /skills.*directory/i);
});

test("reports a missing skill file", (t) => {
  const directory = fixture(t);
  fs.unlinkSync(path.join(directory, "skills/orca-alert-triage/SKILL.md"));
  expectFailure(directory, /orca-alert-triage must include SKILL.md/);
});

test("rejects a skill name that differs from its folder", (t) => {
  const directory = fixture(t);
  const skill = path.join(directory, "skills/orca-alert-triage/SKILL.md");
  fs.writeFileSync(skill, fs.readFileSync(skill, "utf8").replace("name: orca-alert-triage", "name: wrong-name"));
  expectFailure(directory, /orca-alert-triage.*name/);
});

for (const style of [">", "|", ">-", "|-"]) {
  test(`accepts a nonempty YAML block description (${style})`, (t) => {
    const directory = fixture(t);
    fs.writeFileSync(path.join(directory, "skills/orca-alert-triage/SKILL.md"), `---\nname: orca-alert-triage\ndescription: ${style}\n  Triage alerts in Orca.\n  Use when investigating alerts.\n---\n\nTriage workflow.\n`);
    const result = validate(directory);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}

test("rejects an empty YAML block description", (t) => {
  const directory = fixture(t);
  fs.writeFileSync(path.join(directory, "skills/orca-alert-triage/SKILL.md"), "---\nname: orca-alert-triage\ndescription: >\n---\n\nTriage workflow.\n");
  expectFailure(directory, /orca-alert-triage.*nonempty.*description/);
});

test("reports malformed manifest JSON", (t) => {
  const directory = fixture(t);
  fs.writeFileSync(path.join(directory, ".codex-plugin/plugin.json"), "{\n");
  expectFailure(directory, /\.codex-plugin\/plugin.json must be valid JSON/);
});

test("rejects plugin version drift from package.json", (t) => {
  const directory = fixture(t);
  updateJson(directory, ".codex-plugin/plugin.json", (manifest) => { manifest.version = "0.0.0"; });
  expectFailure(directory, /\.codex-plugin\/plugin.json must use version/);
});

test("allows coordinated version changes", (t) => {
  const directory = fixture(t);
  for (const file of ["package.json", ".claude-plugin/plugin.json", ".cursor-plugin/plugin.json", ".codex-plugin/plugin.json"]) {
    updateJson(directory, file, (manifest) => { manifest.version = "3.0.0"; });
  }
  updateJson(directory, ".claude-plugin/marketplace.json", (catalog) => { catalog.plugins[0].version = "3.0.0"; });
  const result = validate(directory);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
