# PocketBase Security Auditor

> Audit any PocketBase instance for over-permissive API rules. Get a shareable HTML report with a fix snippet on every finding. **The active probe fetches data anonymously to PROVE leaks live — not just infer them.**

> ▶ **Run it without installing anything →** [apify.com/renzomacar/pocketbase-security-auditor](https://apify.com/renzomacar/pocketbase-security-auditor) (paste PocketBase URL + admin email/password, get HTML report)

> ⚡ Want me to run it for you and send back a written report? **$99, 24h delivery →** https://perufitlife.github.io/supabase-security-skill/ (one landing covers all five — Supabase, PocketBase, Appwrite, Hasura, Firebase)

> 🔁 **Want this running on a cron?** [RLS Monitor](https://rls-monitor.vercel.app/) does weekly diff-based scans + email alerts when new findings appear — $29/mo, your keys never leave your CI.
>
> 📦 **Need all 5 BaaS stacks at once?** The [BaaS Security Pack](https://perufitlife.github.io/supabase-security-skill/pack.html) bundles every scanner + sample reports + fix-SQL libraries — one $99 download.

> 🪞 **Sister tool**: [aitells](https://aitells.vercel.app/) detects + rewrites AI fingerprints in your text (em-dashes, "delve", parallel bullets). Free detector + $19 lifetime rewriter at [/rewrite](https://aitells.vercel.app/rewrite).

[![npm](https://img.shields.io/npm/v/pocketbase-security?color=red)](https://www.npmjs.com/package/pocketbase-security) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue)

> **Sister tools** for other BaaS platforms (same `--discover` flag, all MIT):
> [supabase-security](https://www.npmjs.com/package/supabase-security) · [appwrite-security](https://www.npmjs.com/package/appwrite-security) · [firebase-security](https://www.npmjs.com/package/firebase-security) · [nhost-security](https://www.npmjs.com/package/nhost-security)

## Why this exists

PocketBase API rules are easy to write and easy to leave too open. Three patterns I see over and over:

- **Empty rule** — leaving `listRule` blank means the collection is fully public. Anyone can list every record without auth.
- **`@request.auth.id != ""`** — looks restrictive but lets ANY logged-in user (including a self-signed-up anonymous one) read or write the entire collection.
- **`true` literal** — leftover from local dev, evaluates to "always allow."

This auditor surfaces all three across every collection in one command.

## Install + run

```bash
npx pocketbase-security \
  --url https://my.pocketbase.io \
  --email admin@me.io \
  --password $PB_ADMIN_PASS \
  --html report.html
```

Or via env vars:

```bash
POCKETBASE_URL=https://my.pb.io \
POCKETBASE_ADMIN_EMAIL=admin@me.io \
POCKETBASE_ADMIN_PASSWORD=$PB_ADMIN_PASS \
npx pocketbase-security --html report.html
```

## What it checks

| # | Check | Severity |
|---|---|---|
| 1 | API rule is empty (collection is fully public for that op) | **CRITICAL** |
| 2 | API rule is `@request.auth.id != ""` (any logged-in user passes) | HIGH |
| 3 | API rule contains `true` literal (bypasses all checks) | HIGH |
| 4 | Auth collection has open signup + lax create rule (combo) | HIGH |
| 5 | OAuth2 provider enabled without redirect URL whitelist | MEDIUM |
| 6 | Email auth without verification requirement | MEDIUM |
| 7 | S3 storage with debug-level logging risk | LOW |

Every finding ships with a fix snippet you paste back into the PocketBase admin UI.

## Active probe

Default: ON. After identifying a suspect collection (empty rule, permissive auth, dangerous literal), the auditor sends an **anonymous GET** to `/api/collections/{name}/records?perPage=1`. If the request returns data, the finding is marked `confirmed: true` with a sample showing the row count, columns visible, and bytes leaked.

Pass `--no-probe` to skip the live fetch (passive mode only, infers from rule metadata).

## Output

- **HTML report** — self-contained (~25KB Tailwind + Chart.js via CDN). Top banner shows X of N suspected leaks confirmed live. Every finding card has a red "CONFIRMED LEAK" block when the probe succeeded.
- **JSON** — full structured findings (default stdout output if no `--html` flag).

## How to get an admin password

You created one when you initialized PocketBase. If you forgot, reset it via the PB CLI on the host machine: `./pocketbase admin update <email> <new-password>`.

The password is used only for this run's admin auth call (collections endpoint requires admin token). The auditor never persists it.


## Sister AI text tools

If your team writes outreach, PR descriptions, or social posts with AI, the [aitells](https://aitells.vercel.app) ecosystem catches the fingerprints before they ship:

- [`@perufitlife/aitells-mcp`](https://www.npmjs.com/package/@perufitlife/aitells-mcp) — MCP server for Claude Code / Cursor. `detect_ai_tells` + `humanize_text` as native tools.
- [`Perufitlife/aitells-action`](https://github.com/Perufitlife/aitells-action) — GitHub Action that scans PR titles/bodies/commits for AI patterns. Posts friendly summary comment.
- [aitells.vercel.app](https://aitells.vercel.app) — free detector + $19 lifetime humanizer (first 100 buyers)

## License

MIT. Free, open source. Built by [@Perufitlife](https://github.com/Perufitlife).

For Supabase, see the sibling tool: https://github.com/Perufitlife/supabase-security-skill
