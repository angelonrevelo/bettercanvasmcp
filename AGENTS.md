# AGENTS.md

`better-canvas-mcp` is a local, read-only Canvas MCP published at
https://github.com/angelonrevelo/bettercanvasmcp. `CLAUDE.md` imports this file.

## What not to change

- Do not add Canvas writes: no submit, no discussion post, no grade, no mark-as-read, no export job creation. Opening a quiz attempt (`get_lockdown_quiz_take` with preview false) is allowed as a read-shaped state change — it returns the questions and never answers or submits them.
- Do not start LockDown Browser from this server, and do not import a decompiled client, an insert library, or an overlay. Reading a Lockdown Browser quiz's content, questions, and the current user's score through the token API is allowed — the gate is a client check, not an API gate (`get_lockdown_quiz_access`). Answering or submitting stays manual, so a lockdown quiz's completion stays unknown until the student takes the exam.
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
