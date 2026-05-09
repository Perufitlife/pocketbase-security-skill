#!/usr/bin/env node
// Postinstall hook — friendly nudge. Skipped silently in CI.
if (process.env.CI || process.env.NODE_ENV === 'production') process.exit(0);
const lines = [
  "",
  "  +-------------------------------------------------------------------------+",
  "  |  + pocketbase-security installed                                                       ",
  "  |                                                                          ",
  "  |  Run it now (creds never persisted):                                     ",
  "  |    npx pocketbase-security --url https://my.pb.io --email admin@x --password $PB_PASS",
  "  |                                                                          ",
  "  |  No-install version (browser):                                           ",
  "  |    https://apify.com/renzomacar/pocketbase-security-auditor",
  "  |                                                                          ",
  "  |  Want me to run it for you and send back a written report? \9, 24h:    ",
  "  |    https://perufitlife.github.io/supabase-security-skill/                ",
  "  +-------------------------------------------------------------------------+",
  ""
].join("\n");
process.stdout.write(lines);
