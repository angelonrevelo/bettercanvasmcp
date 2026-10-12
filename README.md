<p align="center">
  <img src="https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js&logoColor=white" alt="Node 20+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
  <img src="https://img.shields.io/badge/transport-stdio-111111" alt="stdio">
  <img src="https://img.shields.io/badge/canvas-read--only-blue" alt="read-only">
</p>

# better-canvas-mcp

**A read-only Canvas MCP for students whose real work is not on the assignment list.**

The popular Canvas MCPs are instructor consoles. They create assignments, post grades, and send messages. A student token cannot do that, and the work a student actually owes is often somewhere else: a due-date override, a New Quiz that Canvas will not open over the API, a file linked from the syllabus, a reply quota buried in a discussion, a group workspace that is not the course files tab.

This server reads those surfaces and says when Canvas refused. `submissions/self` is the only completion proof. A planner item, a page view, or an empty list is not.

It is not affiliated with Instructure.

## Before you connect a token

[Instructure's API Policy](https://www.instructure.com/policies/canvas-api-policy), effective 12 August 2025, prohibits connecting to Canvas with a model-context-protocol server Instructure has not approved. Read that policy, and your school's own rules, before you use this.

What this repository will not do:

- It does not submit work, post replies, grade, or mark anything read.
- It does not take a token for anyone but the person running it. The token stays in that machine's environment.
- It does not ship a hosted server. A public Canvas MCP without a per-user gate is how the largest one retired its hosted endpoint.

The process sends `User-Agent: better-canvas-mcp/0.4.0 (+https://github.com/angelonrevelo/bettercanvasmcp)` on every Canvas request.

## What it catches

- **Due dates that are not the assignment's base date.** Overrides, all-dates, course to-do, and the effective due date for the token holder only. If Canvas blocks that map, the result is `blocked_or_absent`, not a guess about other students.
- **New Quizzes and other LTI tools.** Catalog, items, and line items when the token can see them. Blocked internals stay blocked. They are not treated as "done."
- **Instructions that live outside the assignment.** Syllabus, pages, announcements, module locks, and text extracted from linked files (PDF via `pdftotext`, DOCX via unzip, images via `tesseract` when it is installed).
- **Group work and peer replies.** Your own groups, their files and discussions, peer-review rows, and a second binary that flags reply language in prompts.
- **Old course shells.** Term, enrollment, and concluded state, so a leftover course is not treated as this term's work.
- **Anything else the token can GET.** `request_canvas_api` accepts only `/api/...` paths. `get_canvas_api_capability` reports `ok`, `blocked_or_absent`, `skipped`, or `error` for a fixed probe list.

The full tool list is [docs/TOOLS.md](docs/TOOLS.md).

## Quick start

Node 20 or newer.

```bash
git clone https://github.com/angelonrevelo/bettercanvasmcp
cd bettercanvasmcp
npm install
npm run build
cp .env.example .env   # then put your host and token in the client config, not in git
```

Create a token in Canvas under **Account → Settings → Approved Integrations → New Access Token**. Some schools hide that button and issue tokens through IT. A student token expires; when calls start returning 401, make a new one.

### Cursor

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "canvas": {
      "command": "node",
      "args": ["/absolute/path/to/bettercanvasmcp/dist/index.js"],
      "env": {
        "CANVAS_API_TOKEN": "your_token",
        "CANVAS_BASE_URL": "https://your-school.instructure.com"
      }
    }
  }
}
```

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows. Same `mcpServers` block.

### Peer-reply binary

Discussions that require a reply are a second process, same token and host:

```json
"canvas-engagement": {
  "command": "node",
  "args": ["/absolute/path/to/bettercanvasmcp/dist/engagement.js"],
  "env": {
    "CANVAS_API_TOKEN": "your_token",
    "CANVAS_BASE_URL": "https://your-school.instructure.com"
  }
}
```

`get_watch_diff` writes a snapshot under `~/.cache/canvas-engagement` (or `CANVAS_STATE_DIR`). Everything else is read-only. The snapshot stays on your machine.

## Configuration

| Setting | Flag | Env | Default |
|---|---|---|---|
| Canvas host | `--base-url` | `CANVAS_BASE_URL` | required |
| Token | `--token` | `CANVAS_API_TOKEN` | required |
| Default course | `--course` | `CANVAS_COURSE_ID` | none; pass `course_id` per call |
| Timeout | `--request-timeout-ms` | `CANVAS_REQUEST_TIMEOUT_MS` | `30000` |
| Network retries | `--request-retry-count` | `CANVAS_REQUEST_RETRY_COUNT` | `2` (dropped connections only) |
| Engagement snapshot | `--state-dir` | `CANVAS_STATE_DIR` | `~/.cache/canvas-engagement` |

There is no default school. A missing host or token exits before the server listens.

## How it works

```
your agent
    │  stdio, your token, your host
    ▼
better-canvas-mcp  ──GET /api/v1/...──►  Canvas
    │
    ├─ specialized tools (assignment, quiz, group, file, module, …)
    ├─ request_canvas_api for a path that is not wrapped yet
    └─ blocked_or_absent when the token cannot read that family

submissions/self  =  submitted or not
everything else   =  context
```

Optional local tools for file text: `pdftotext` (poppler) and `tesseract`. If they are missing, the file tool returns metadata and says the binary is unsupported. It does not pretend the reading was extracted.

## Develop

```bash
npm run gate    # tsc --noEmit, then the surface checks
npm run dev     # tsx, still requires CANVAS_BASE_URL and CANVAS_API_TOKEN
```

`npm test` checks that the school host is not hardcoded, that the edge-case tools exist, and that the process exits when the host or token is missing. It does not call Canvas.

## License

[MIT](LICENSE).
