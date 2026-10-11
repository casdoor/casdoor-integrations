// Validates every integration under integrations/ and writes dist/:
//   dist/index.json                                  catalog of all integrations
//   dist/integrations/<id>/<version>/bundle.json     manifest plus content files
//   dist/integrations/<id>/<version>/<file>          logo and screenshots, if any
// Paths in index.json are relative to index.json. Run with --check to validate without writing dist/.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.includes("--check");

// Content files of each type: the schema each one follows and whether it must be there.
const contentFiles = {
  app: {"application.json": ["app/application.schema.json", true], "guide.json": ["guide.schema.json", true]},
  provider: {"provider.json": ["provider/provider.schema.json", true], "guide.json": ["guide.schema.json", true]},
  theme: {"theme.json": ["theme/theme.schema.json", true], "guide.json": ["guide.schema.json", false]},
  action: {},
};
const builtInVariables = ["casdoorUrl", "clientId", "clientSecret"];

// Casdoor keeps the old form CSS when an organization admin saves one that could send out what users type
// (object/application_util.go): no backslashes, HTML or image functions, and url() and @import only from places
// whose access logs nobody else can read. An operator can allow more places, but a theme can only count on these.
const unsafeCssTokens = ["\\", "<", "image(", "image-set(", "cross-fade(", "element(", "src("];
const cssUrlPrefixes = [
  "https://fonts.googleapis.com/",
  "https://fonts.gstatic.com/",
  "https://cdn.jsdelivr.net/gh/casdoor/",
  "https://cdn.jsdelivr.net/npm/@fontsource/",
  "https://cdn.jsdelivr.net/npm/@fontsource-variable/",
  "https://cdn.casbin.org/",
  "https://cdn.casdoor.com/",
  "https://cdn.casvisor.com/",
];
const cssImportPrefixes = ["https://fonts.googleapis.com/css", "https://cdn.jsdelivr.net/npm/@fontsource/", "https://cdn.jsdelivr.net/npm/@fontsource-variable/"];
const cssUrlPattern = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^"'()\s]*))\s*\)/g;
const cssImportPattern = /@import\s*(?:url\(\s*)?(?:"([^"]*)"|'([^']*)'|([^"'()\s;]+))/g;
// Casdoor versions before this one reject any url(), @import and @font-face
const cssUrlCasdoorVersion = "4.20.0";

function isCssUrlAllowed(url, prefixes, allowLocal) {
  if (url.startsWith("data:") || url.startsWith("#")) {
    return allowLocal;
  }
  if (/[\x00-\x20\x7f]/.test(url) || ["..", "%2e", "%2f", "%5c"].some((t) => url.includes(t))) {
    return false;
  }
  if (!/^[a-z][a-z0-9+.-]*:/.test(url) && !url.startsWith("//")) {
    return allowLocal;
  }
  return prefixes.some((p) => url.startsWith(p));
}

function checkCss(css) {
  const lower = css.replace(/<\/?style[^>]*>/gi, "").toLowerCase();
  const token = unsafeCssTokens.find((t) => lower.includes(t));
  if (token) {
    return `uses ${token}, which Casdoor rejects in form CSS`;
  }
  const count = (t) => lower.split(t).length - 1;
  const urls = [...lower.matchAll(cssUrlPattern)];
  const imports = [...lower.matchAll(cssImportPattern)];
  if (urls.length !== count("url(") || imports.length !== count("@import")) {
    return "has a url() or @import Casdoor cannot read";
  }
  const urlOf = (m) => (m[1] ?? m[2] ?? m[3] ?? "").trim();
  const badUrl = urls.map(urlOf).find((u) => !isCssUrlAllowed(u, cssUrlPrefixes, true));
  if (badUrl !== undefined) {
    return `loads ${badUrl}, allowed are relative URLs, data: and ${cssUrlPrefixes.join(" ")}`;
  }
  const badImport = imports.map(urlOf).find((u) => !isCssUrlAllowed(u, cssImportPrefixes, false));
  if (badImport !== undefined) {
    return `imports ${badImport}, allowed are ${cssImportPrefixes.join(" ")}`;
  }
  return null;
}

const usesCssUrls = (css) => /url\(|@import|@font-face/i.test(css);
const versionAtLeast = (range, min) => {
  const v = (range.match(/>=\s*(\d+)\.(\d+)\.(\d+)/) ?? []).slice(1).map(Number);
  const m = min.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((v[i] ?? 0) !== m[i]) {
      return (v[i] ?? 0) > m[i];
    }
  }
  return true;
};
// Only a global admin can set these application fields; Casdoor keeps the old value for anyone else.
const globalAdminFields = ["formSideHtml", "footerHtml"];

// strictRequired would reject the conditional "required" lists in if/then, which name properties declared one level up.
const ajv = new Ajv2020({allErrors: true, strict: true, strictRequired: false});
addFormats(ajv);
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const validators = {};
const validator = (schema) => (validators[schema] ??= ajv.compile(readJson(path.join(root, "schema", schema))));

const errors = [];
const fail = (where, message) => errors.push(`${where}: ${message}`);

function checkSchema(where, data, schema) {
  const validate = validator(schema);
  if (!validate(data)) {
    for (const e of validate.errors) {
      fail(where, `${e.instancePath || "/"} ${e.message}`);
    }
  }
}

function collectVariables(value, found) {
  if (typeof value === "string") {
    for (const m of value.matchAll(/\{\{\s*([^}]*?)\s*\}\}/g)) {
      found.add(m[1]);
    }
  } else if (value && typeof value === "object") {
    Object.values(value).forEach((v) => collectVariables(v, found));
  }
  return found;
}

const integrations = [];
const ids = new Map();
for (const type of fs.readdirSync(path.join(root, "integrations")).sort()) {
  if (!(type in contentFiles)) {
    fail(`integrations/${type}`, `unknown type, expected one of ${Object.keys(contentFiles).join(", ")}`);
    continue;
  }
  for (const id of fs.readdirSync(path.join(root, "integrations", type)).sort()) {
    const dir = path.join(root, "integrations", type, id);
    const where = `integrations/${type}/${id}`;
    const manifestFile = path.join(dir, "integration.json");
    if (!fs.existsSync(manifestFile)) {
      fail(where, "missing integration.json");
      continue;
    }

    const manifest = readJson(manifestFile);
    checkSchema(`${where}/integration.json`, manifest, "integration.schema.json");
    if (manifest.id !== id) {
      fail(where, `id "${manifest.id}" does not match the directory name`);
    }
    if (manifest.type !== type) {
      fail(where, `type "${manifest.type}" does not match the parent directory`);
    }
    if (ids.has(manifest.id)) {
      fail(where, `id "${manifest.id}" is also used by ${ids.get(manifest.id)}`);
    }
    ids.set(manifest.id, where);
    for (const file of [manifest.logo, ...(manifest.screenshots ?? [])].filter(Boolean)) {
      if (!fs.existsSync(path.join(dir, file))) {
        fail(where, `${file} not found`);
      }
    }
    if (type === "theme" && !manifest.screenshots?.length) {
      fail(where, "a theme needs at least one screenshot");
    }
    for (const v of manifest.variables ?? []) {
      if (v.type === "color" && !/^#[0-9a-fA-F]{6}$/.test(v.example)) {
        fail(where, `variable ${v.name}: example must be #rrggbb`);
      }
    }

    const files = {};
    for (const [file, [schema, required]] of Object.entries(contentFiles[type])) {
      const p = path.join(dir, file);
      if (!fs.existsSync(p)) {
        if (required) {
          fail(where, `missing ${file}`);
        }
        continue;
      }
      files[file] = readJson(p);
      checkSchema(`${where}/${file}`, files[file], schema);
    }

    const declared = new Set([...builtInVariables, ...(manifest.variables ?? []).map((v) => v.name)]);
    for (const name of collectVariables(files, new Set())) {
      if (!declared.has(name)) {
        fail(where, `{{${name}}} is used but not declared in variables`);
      }
    }

    const theme = files["theme.json"];
    for (const field of ["formCss", "formCssMobile"]) {
      const problem = theme?.[field] ? checkCss(theme[field]) : null;
      if (problem) {
        fail(`${where}/theme.json`, `${field} ${problem}`);
      }
      if (theme?.[field] && usesCssUrls(theme[field]) && !versionAtLeast(manifest.casdoorVersion ?? "", cssUrlCasdoorVersion)) {
        fail(where, `${field} loads files, which needs casdoorVersion >=${cssUrlCasdoorVersion}`);
      }
    }

    integrations.push({manifest, files, dir});
  }
}

if (errors.length) {
  console.error(errors.join("\n"));
  console.error(`\n${errors.length} error(s)`);
  process.exit(1);
}
console.log(`${integrations.length} integration(s) valid`);
if (checkOnly) {
  process.exit(0);
}

const dist = path.join(root, "dist");
fs.rmSync(dist, {recursive: true, force: true});
const strip = ({$schema, ...rest}) => rest;
const index = {schemaVersion: 1, generatedAt: new Date().toISOString(), integrations: [], revoked: []};

for (const {manifest, files, dir} of integrations) {
  const base = `integrations/${manifest.id}/${manifest.version}`;
  const out = path.join(dist, base);
  fs.mkdirSync(out, {recursive: true});

  const bundle = JSON.stringify({manifest: strip(manifest), files: Object.fromEntries(Object.entries(files).map(([f, d]) => [f, strip(d)]))}, null, 2) + "\n";
  fs.writeFileSync(path.join(out, "bundle.json"), bundle);
  for (const file of [manifest.logo, ...(manifest.screenshots ?? [])].filter(Boolean)) {
    fs.copyFileSync(path.join(dir, file), path.join(out, file));
  }

  const {$schema, version, casdoorVersion, logo, screenshots, variables, permissions, ...listing} = manifest;
  const requiresGlobalAdmin = globalAdminFields.some((f) => files["theme.json"]?.[f]);
  index.integrations.push({
    ...listing,
    ...(logo ? {logo: `${base}/${logo}`} : {}),
    ...(screenshots?.length ? {screenshots: screenshots.map((f) => `${base}/${f}`)} : {}),
    ...(requiresGlobalAdmin ? {requiresGlobalAdmin} : {}),
    // Integrations in this repository are maintained by the Casdoor team.
    verified: true,
    latest: version,
    versions: [
      {
        version,
        casdoorVersion,
        url: `${base}/bundle.json`,
        sha256: crypto.createHash("sha256").update(bundle).digest("hex"),
        publishedAt: index.generatedAt,
      },
    ],
  });
}

fs.writeFileSync(path.join(dist, "index.json"), JSON.stringify(index, null, 2) + "\n");
console.log(`wrote ${path.relative(root, dist)}/index.json`);
