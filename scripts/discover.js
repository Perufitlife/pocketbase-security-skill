#!/usr/bin/env node
// PocketBase Security — KEYLESS DISCOVER MODE.
//
// Parses the user's repo statically to find PocketBase client SDK usage:
//   - PB_URL / process.env references
//   - new PocketBase('...').collection('xxx').getList()
//   - pb.collection('xxx') and pb.files.getUrl() calls
// Then probes the public PocketBase REST API anonymously to confirm leaks:
//   - GET /api/collections/{name}/records → returns rows? Then the listRule is open.
//   - GET /api/files/{collection}/{recordId}/{filename} → file public?
// No admin auth, no superuser token.
//
// Triggered by `pocketbase-security --discover [path]`

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const PATTERNS = {
  // .collection('users').getList(), .collection("users").getOne(...)
  collection: /\.collection\(\s*['"`]([a-zA-Z0-9_-]+)['"`]/g,
  // new PocketBase('https://my.pb.io')
  pbInit: /new\s+PocketBase\s*\(\s*['"`](https?:\/\/[^'"`]+)['"`]/g,
  // POCKETBASE_URL=https://...
  pbUrlEnv: /POCKETBASE_URL\s*=\s*['"`]?(https?:\/\/[^\s'"`]+)/g,
  // process.env.POCKETBASE_URL or NEXT_PUBLIC_POCKETBASE_URL
  pbUrlProcessEnv: /(?:process\.env\.)?(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?POCKETBASE_URL/g,
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", ".turbo",
  "coverage", ".cache", ".vercel", "__pycache__", "pb_data"
]);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
  ".env", ".env.local", ".env.example", ".env.production"
]);

function walk(dir, files = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return files; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, files);
    } else {
      const lower = e.name.toLowerCase();
      const hasExt = [...SCAN_EXTENSIONS].some(x => lower.endsWith(x));
      if (hasExt || lower.startsWith(".env")) files.push(p);
    }
  }
  return files;
}

function readSafe(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }

export function staticScan(root) {
  const files = walk(root);
  const out = {
    pbUrl: null,
    collections: new Set(),
    sourceFiles: 0,
    envFiles: 0,
    rootDir: root,
  };

  for (const file of files) {
    const content = readSafe(file);
    if (!content) continue;
    const isEnv = file.toLowerCase().includes(".env");
    if (isEnv) out.envFiles++; else out.sourceFiles++;

    if (!out.pbUrl) {
      const init = PATTERNS.pbInit.exec(content);
      if (init) out.pbUrl = init[1];
    }
    if (!out.pbUrl && isEnv) {
      const envU = PATTERNS.pbUrlEnv.exec(content);
      if (envU) out.pbUrl = envU[1].replace(/[\s'"`].*$/, "");
    }

    for (const m of content.matchAll(PATTERNS.collection)) out.collections.add(m[1]);
  }

  return { ...out, collections: [...out.collections] };
}

async function probeCollection(pbUrl, collection) {
  try {
    const r = await fetch(`${pbUrl}/api/collections/${encodeURIComponent(collection)}/records?perPage=1`, {
      method: "GET",
      headers: { "User-Agent": "pocketbase-security/0.2 (discover)" },
    });
    const body = await r.text();
    let totalItems = 0;
    let returnedRows = 0;
    if (r.status === 200) {
      try {
        const j = JSON.parse(body);
        totalItems = j.totalItems || 0;
        returnedRows = (j.items || []).length;
      } catch {}
    }
    return {
      status: r.status,
      list_rule_open: r.status === 200 && returnedRows > 0,
      total_items: totalItems,
      body_preview: body.slice(0, 150),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

export async function discover({ root = process.cwd(), pbUrl = null } = {}) {
  const scan = staticScan(root);
  const url = pbUrl || scan.pbUrl;
  const findings = [];
  const probes = [];

  if (!url) {
    return {
      mode: "discover",
      error: "No PocketBase URL detected in repo. Pass --url or set POCKETBASE_URL in .env",
      files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
      collections_found: scan.collections,
    };
  }

  for (const col of scan.collections) {
    const p = await probeCollection(url, col);
    probes.push({ collection: col, ...p });
    if (p.list_rule_open) {
      findings.push({
        check: "collection_list_rule_open",
        severity: "critical",
        title: `Collection \`${col}\` is listable anonymously`,
        explain: "GET /api/collections/" + col + "/records returned records without auth. The collection's listRule is empty or evaluates to true.",
        target: col,
        details: { http_status: p.status, total_items: p.total_items, body_preview: p.body_preview },
        fix: `// In the PocketBase admin UI:
// Settings -> Collections -> "${col}" -> API Rules
// Set "List rule" to something restrictive, e.g.:
//   @request.auth.id != "" && @request.auth.id = user.id
// or leave it as null and require admin auth.`,
        probe: { confirmed: true },
      });
    } else if (p.status === 200 && p.total_items === 0) {
      // Collection exists but empty — can't distinguish locked from empty
      findings.push({
        check: "collection_reachable_no_data_yet",
        severity: "info",
        title: `Collection \`${col}\` is reachable by anon but currently empty`,
        explain: "GET succeeded with 200 but 0 records. Can't tell if the listRule is open or the collection just has no data. Re-run after seeding to confirm.",
        target: col,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    mode: "discover",
    scanned_at: new Date().toISOString(),
    scanned_by: "pocketbase-security v0.2 (discover)",
    root_dir: root,
    pb_url: url,
    files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
    collections_found: scan.collections,
    probes,
    summary,
    findings,
  };
}
