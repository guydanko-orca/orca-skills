import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

function fail(message) {
  errors.push(message);
}

function expect(condition, message) {
  if (!condition) fail(message);
}

function readJson(relativePath) {
  const absolutePath = path.join(root, relativePath);
  try {
    const value = JSON.parse(fs.readFileSync(absolutePath, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("expected a JSON object");
    }
    return value;
  } catch (error) {
    fail(`${relativePath} must be valid JSON: ${error.message}`);
    return {};
  }
}

const packageManifest = readJson("package.json");
expect(typeof packageManifest.version === "string" && packageManifest.version.length > 0, "package.json must include a version");

function expectPackageManifest(relativePath) {
  const manifest = readJson(relativePath);
  expect(manifest.name === "orca-skills", `${relativePath} must use name "orca-skills"`);
  expect(manifest.version === packageManifest.version, `${relativePath} must use version "${packageManifest.version}" from package.json`);
  expect(
    manifest.repository === "https://github.com/orcasecurity/orca-skills" ||
      manifest.repository?.url === "https://github.com/orcasecurity/orca-skills.git",
    `${relativePath} must point at the orcasecurity/orca-skills repository`,
  );
  expect(manifest.skills === "./skills/", `${relativePath} must expose ./skills/`);
  return manifest;
}

function validateSkillFolders() {
  const skillsRoot = path.join(root, "skills");
  if (!fs.existsSync(skillsRoot) || !fs.statSync(skillsRoot).isDirectory()) {
    fail("skills must be an existing directory");
    return;
  }
  const skillNames = fs
    .readdirSync(skillsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  expect(skillNames.length > 0, "skills must contain at least one skill folder");

  for (const skillName of skillNames) {
    const skillPath = path.join(skillsRoot, skillName, "SKILL.md");
    if (!fs.existsSync(skillPath) || !fs.statSync(skillPath).isFile()) {
      fail(`${skillName} must include SKILL.md`);
      continue;
    }
    const content = fs.readFileSync(skillPath, "utf8");
    const frontmatter = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/)?.[1];
    expect(frontmatter, `${skillName}/SKILL.md must start with YAML frontmatter`);
    const name = frontmatter?.match(/^name:\s*([^\r\n]+)$/m)?.[1].trim().replace(/^(["'])(.*)\1$/, "$2");
    const description = frontmatter?.match(/^description:[ \t]*(.*(?:\r?\n[ \t]+.*)*)/m)?.[1].trim();
    expect(name === skillName, `${skillName}/SKILL.md name must match its folder`);
    expect(description && !["''", '""', "|", ">", "|-", ">-", "|+", ">+"].includes(description), `${skillName}/SKILL.md must include a nonempty description`);
  }
}

function validateCodexPluginManifest(relativePath) {
  const manifest = expectPackageManifest(relativePath);
  expect(typeof manifest.author?.name === "string", `${relativePath} must include author.name`);
  expect(manifest.interface?.displayName === "Orca Security Skills", `${relativePath} must include Codex interface metadata`);
  expect(
    Array.isArray(manifest.interface?.defaultPrompt) && manifest.interface.defaultPrompt.length > 0,
    `${relativePath} must include at least one defaultPrompt`,
  );
  expect(!("mcpServers" in manifest), `${relativePath} should not reference .mcp.json unless the file is committed`);
}

function validateCodexMarketplace() {
  const marketplace = readJson(".agents/plugins/marketplace.json");
  const entries = Array.isArray(marketplace.plugins) ? marketplace.plugins.filter((entry) => entry?.name === "orca-skills") : [];
  const plugin = entries[0];

  expect(marketplace.name === "orcasecurity", ".agents/plugins/marketplace.json must be named orcasecurity");
  expect(marketplace.interface?.displayName === "Orca Security", ".agents/plugins/marketplace.json must include displayName");
  expect(entries.length === 1, ".agents/plugins/marketplace.json must include exactly one orca-skills plugin entry");

  if (!plugin) return;

  expect(plugin.source?.source === "local", "Codex marketplace entry must use local source");
  expect(plugin.source?.path === "./", "Codex marketplace entry must point to the repository root (./)");
  expect(plugin.policy?.installation === "AVAILABLE", "Codex marketplace installation policy must be AVAILABLE");
  expect(plugin.policy?.authentication === "ON_INSTALL", "Codex marketplace authentication policy must be ON_INSTALL");
  expect(plugin.category === "Security", "Codex marketplace category must be Security");
}

function validateClaudeMarketplace() {
  const marketplace = readJson(".claude-plugin/marketplace.json");
  const entries = Array.isArray(marketplace.plugins) ? marketplace.plugins.filter((entry) => entry?.name === "orca-skills") : [];
  expect(entries.length === 1, "Claude marketplace must include exactly one orca-skills plugin entry");
  expect(entries[0]?.source === "./", "Claude marketplace orca-skills entry must point to the repository root (./)");
  expect(entries[0]?.version === packageManifest.version, "Claude marketplace orca-skills version must match package.json");
}

function validateReadme() {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  expect(readme.includes("### Claude Code CLI"), "README must document Claude Code installation");
  expect(readme.includes("### Codex CLI"), "README must document Codex CLI installation");
  expect(readme.includes("codex mcp add orca-security"), "README must document Codex MCP setup");
  expect(readme.includes("Claude examples use slash commands"), "README must explain Claude slash commands vs Codex natural language");
}

function validateContributorDocs() {
  const contributing = fs.readFileSync(path.join(root, "CONTRIBUTING.md"), "utf8");
  expect(contributing.includes("npm test"), "CONTRIBUTING must document the repository validation command");
  for (const staleReference of ["EVALS.md", "promptfoo", "promptfooconfig.yaml", "test-data/"]) {
    expect(!contributing.includes(staleReference), `CONTRIBUTING must not reference missing ${staleReference}`);
  }
}

validateSkillFolders();
expectPackageManifest(".claude-plugin/plugin.json");
expectPackageManifest(".cursor-plugin/plugin.json");
validateCodexPluginManifest(".codex-plugin/plugin.json");
expect(!fs.existsSync(path.join(root, ".codex/plugin.json")), "Remove legacy .codex/plugin.json; use .codex-plugin/plugin.json");
expect(!fs.existsSync(path.join(root, "plugins/orca-skills")), "plugins/orca-skills is a duplicate; use the root skills directory");
validateCodexMarketplace();
validateClaudeMarketplace();
validateReadme();
validateContributorDocs();

if (errors.length > 0) {
  console.error("Packaging validation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log("Packaging validation passed.");
