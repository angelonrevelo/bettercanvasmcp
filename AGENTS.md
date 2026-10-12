# AGENTS.md

`better-canvas-mcp` is a local Canvas MCP published at
https://github.com/angelonrevelo/bettercanvasmcp. `CLAUDE.md` imports this file.

## What not to change

- Writes are opt-in, not banned: `request_canvas_write` exists behind `CANVAS_ALLOW_WRITES=1` (env) or `--allow-writes`. Without that flag it refuses before anything reaches Canvas. Submitting, posting, grading, and creating all flow through it on purpose; the caller decides what to send.
- Launching the LockDown Browser client from here is fine (`get_lockdown_quiz_launch` resolves the rldb: launch URL and hands it to the OS opener). Do not import a decompiled client, an insert library, or an overlay. Reading a Lockdown Browser quiz's content, questions, and the current user's score through the token API is allowed — the gate is a client check, not an API gate (`get_lockdown_quiz_access`).
- Do not hardcode a school hostname. `CANVAS_BASE_URL` stays required.
- Do not commit `.env` or a live token. `.env.example` keeps an empty token.
- Do not put another student's grade, name, or id into docs, fixtures, or error strings.
- Canvas JSON keys stay as Canvas sends them. New identifiers in this repo are singular. See `docs/CONVENTIONS.md`.

## Gate

```bash
npm run gate
```

`typecheck` is `tsc --noEmit`. `test` is `node scripts/check-surface.mjs` plus `scripts/requirement.test.ts`. A live Canvas call is not part of the gate.

## Layout

- `src/requirement.ts` — keyword and Canvas-field requirement graph shared by the read server and the engagement scan.
- `src/engagement.ts` — reply-need, peer-response language, engagement counts, local watch diff.
- `docs/TOOLS.md` — the tool catalog.
- `ROADMAP.md` — what is not built yet. `docs/roadmap-rejected.md` — what will not be built.
