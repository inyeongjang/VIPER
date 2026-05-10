const fs = require("fs");
const path = require("path");

const packageRoot = process.argv[2];
const packageName = process.argv[3] || "";

async function main() {
  if (!packageRoot) {
    console.error("Usage: node extract_exports.js <package_root> [package_name]");
    process.exit(1);
  }

  const results = extractExportsFromPackageRoot(packageRoot);
  console.log(JSON.stringify(results));
}

function extractExportsFromPackageRoot(packageRoot) {
  const pkgPath = path.join(packageRoot, "package.json");

  if (!fs.existsSync(pkgPath)) {
    throw new Error(`package.json not found: ${pkgPath}`);
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const entryPoints = resolveEntryPoints(pkg, packageRoot);

  const results = [];

  for (const entry of entryPoints) {
    try {
      const mod = require(entry);
      results.push(...extractFromModule(mod, entry));
    } catch (e) {
      console.error(`Failed to require ${entry}: ${e.message}`);
    }
  }

  return deduplicate(results);
}

function resolveEntryPoints(pkg, packageRoot) {
  const entryPoints = [];

  if (typeof pkg.main === "string") {
    entryPoints.push(resolvePackagePath(packageRoot, pkg.main));
  }

  if (typeof pkg.exports === "string") {
    entryPoints.push(resolvePackagePath(packageRoot, pkg.exports));
  }

  if (pkg.exports && typeof pkg.exports === "object") {
    collectExportPaths(pkg.exports, packageRoot, entryPoints);
  }

  if (entryPoints.length === 0) {
    entryPoints.push(path.join(packageRoot, "index.js"));
  }

  return [...new Set(entryPoints)].filter((entry) => fs.existsSync(entry));
}

function collectExportPaths(exportsField, packageRoot, entryPoints) {
  for (const value of Object.values(exportsField)) {
    if (typeof value === "string") {
      entryPoints.push(resolvePackagePath(packageRoot, value));
    } else if (value && typeof value === "object") {
      collectExportPaths(value, packageRoot, entryPoints);
    }
  }
}

function resolvePackagePath(packageRoot, relativePath) {
  let normalized = relativePath;

  if (normalized.startsWith("./")) {
    normalized = normalized.slice(2);
  }

  return path.join(packageRoot, normalized);
}

function extractFromModule(mod, filePath) {
  const results = [];

  if (typeof mod === "function") {
    results.push(toExportInfo(mod.name || "default", mod, filePath));
    return results;
  }

  if (!mod || typeof mod !== "object") {
    return results;
  }

  for (const [name, value] of Object.entries(mod)) {
    if (typeof value === "function") {
      results.push(toExportInfo(name, value, filePath));
    }
  }

  return results;
}

function toExportInfo(name, fn, filePath) {
  return {
    name,
    filePath,
    params: extractParams(fn),
    isAsync: fn.constructor.name === "AsyncFunction",
  };
}

function extractParams(fn) {
  const src = fn.toString();
  const match = src.match(/^[^(]*\(([^)]*)\)/);

  if (!match) {
    return [];
  }

  return match[1]
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

function deduplicate(exportsList) {
  const seen = new Set();
  const result = [];

  for (const item of exportsList) {
    const key = `${item.name}:${item.filePath}`;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(item);
  }

  return result;
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});