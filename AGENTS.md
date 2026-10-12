# AGENTS.md

`better-canvas-mcp` is a local, read-only Canvas MCP published at
https://github.com/angelonrevelo/bettercanvasmcp. `CLAUDE.md` imports this file.

## What not to change

- Do not add Canvas writes: no submit, no discussion post, no grade, no mark-as-read, no export job creation.
- Do not hardcode a school hostname. `CANVAS_BASE_URL` stays required.
- Do not commit `.env` or a live token. `.env.example` keeps an empty token.
- Do not put another student's grade, name, or id into docs, fixtures, or error strings.
- Canvas JSON keys stay as Canvas sends them. New identifiers in this repo are singular. See `docs/CONVENTIONS.md`.

## Gate

```bash
npm run gate
```

`typecheck` is `tsc --noEmit`. `test` is `node scripts/check-surface.mjs`. A live Canvas call is not part of the gate.

## Layout

- `src/index.ts` — the read server and its tools.
- `src/engagement.ts` — reply-need, peer-response language, engagement counts, local watch diff.
- `docs/TOOLS.md` — the tool catalog.
- `ROADMAP.md` — what is not built yet. `docs/roadmap-rejected.md` — what will not be built.
