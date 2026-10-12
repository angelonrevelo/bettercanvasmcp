# better-canvas-mcp

## 1. Idea + thesis

A local read-only Canvas MCP for a student whose owed work is not on the assignment list. The north star is one answer to "what do I still owe" that uses `submissions/self` and the edges around it, on a Canvas host the caller names.

This is not an instructor console, not a submit button, and not a hosted server. The private build already proved the reads against a student token for a term. The public cut exists because that build was pinned to one school and was not something another person could install. Claims: C1, C2, C4.

## 2. Customer

One persona: a college student who already points an agent at coursework and can create a Canvas personal access token. The job is to reconcile the assignment list with overrides, files, quizzes, and group spaces.

A student whose school will not issue a self-service token is a later segment. The client assumes English Canvas chrome and a network that can reach the host. It does not queue work for a flaky connection.

## 3. Market + competition

vishalsachdev/canvas-mcp (285 stars on 2026-10-12, C1) is the server people mean by the popular one. It covers student reads and a much larger instructor write set, and it retired its public host. DMontgomery40/mcp-canvas-lms (103 stars, C2) submits assignments. r-huijts/canvas-mcp (C3) is a teacher CRUD server that defaults to one school's host, which is the bug this repo just removed.

No Philippine package showed up in the GitHub search. That negative is unverified. The substitute that was actually in use is the Canvas website pasted into a chat. That paste is one screen.

The moat is the student-token matrix: a denial is `blocked_or_absent`, not an empty list. Copying the tool names does not copy that. First mover is not the claim.

## 4. Product form

`on_device`. The student installs a stdio process and keeps the token in their client config.

Rejected: a hosted SaaS, because policy clause (i) bans unapproved MCP access and a shared host would hold other people's tokens (C4, C5). Rejected: an API product, because the buyer is not an integrator. Canvas already is the API.

## 5. v1 cut line

One job: say what is still owed, from submission state and the hiding places. One channel: the GitHub repo under angelonrevelo. One price experiment: MIT at zero, matching the servers people already clone (C1, C2).

Parked on the roadmap, not deleted: an owed-work command, 429 retry, a short tool profile, and folding the engagement tools into the main process.

## 6. Frontend plan

The surface is the README, the tool catalog, and the client config snippet. Onboarding is the time to the first `list_course`. There is no app chrome.

Headline: know what you still owe in Canvas, including the work that is not on the assignment list.

Brand brief for a later pass: positioning is the read-only student server against instructor consoles; the audience is a student with their own token; the tone is plain and specific.

## 7. Backend + API plan

Node 20, the MCP TypeScript SDK, stdio. Rejected commander. Resources are course reads, the token holder's submissions, file text, and a local engagement snapshot. Auth is the env token, never stored. Canvas rate-limits per token and does not publish a fixed budget (C7); this version only retries dropped connections. Logs are stderr. Compute is the student's machine. No telemetry, which is also the honest generative-AI notice: this process does not call a model (C6). The agent the user attached does, and that is their client's notice to give.

## 8. AI architecture

This server does not call a model. `ai.is_used` is false. OCR, when present, is local `tesseract`, not a hosted vision model. The agent that talks to the server is outside this product.

## 9. Data strategy

Not an AI product. The data is the caller's Canvas account, read at request time, not retained, except the engagement snapshot under their cache directory. Edge cases that already broke a naive read: overrides, blocked New Quizzes, group files, old course shells, missing `pdftotext`.

## 10. GTM

Primary channel is the GitHub repo, described the way leakguard and onegrid are: a badge row, a one-line gap, a copy-paste config. npm is listed and not primary. Acquisition cost is assumed at ₱0 because there is no ad spend and no published CAC for this category.

## 11. Money

MIT, ₱0 per install. Build cost and monthly run cost are ₱0 of cash; founder time is not billed. Break-even is not a revenue event. The comps that were opened are MIT and do not list a price (C1, C2). Prices from Quizlet, Chegg, and acquisition announcements were not re-opened and are not used.

## 12. Constraints, edge cases, complaints

The token is a student token. The host must be set. The repo is angelonrevelo's. The API policy is in force.

Users will complain that there are too many tools, and that a 401 appears when the school expires the token. The bottlenecks are schools that will not issue tokens, and the policy prohibition.

## 13. Risk register

The policy risk is the one that can end the project: archive the repo on a takedown or on a school disabling student tokens for this use. The others are a write tool landing, a token committed to git, a blocked endpoint reported as empty, and the catalog crowding the client. Each has a mitigation in the JSON.

## 14. Timeline + team

Weeks 1–2: the public read server. Weeks 3–6: the owed-work report. The assumed AI multiplier is 3 for typing, not for a live token check or a policy review. The team is the founder, not hired.

## 15. Endgame

Lifestyle. No acquirer is the plan. A company that holds student Canvas tokens conflicts with the policy and with the reason the largest hosted endpoint was shut (C1, C4).

## 16. Open question

Whether a local student process is what Instructure meant to ban. Whether the Data Privacy Act's household exclusion covers a published client that can see group members. Whether every host expires student tokens in 30 days. Whether a Philippine Canvas MCP exists and was missed.

## 17. Handoff

Preset: `node-cli`. Package manager npm, ESM, strict TypeScript, no HTTP port. First roadmap items: require the Canvas host, and mark tools read-only. Brand kit can wait; the brief is in section 6.
