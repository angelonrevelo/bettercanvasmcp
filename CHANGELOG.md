# Changelog

## 0.7.0 — 2026-10-13

- Add `get_lockdown_quiz_take`. Opening or resuming a Lockdown Browser quiz attempt and reading its questions is now one call. `preview true` (default) inspects without starting anything; `preview false` opens the attempt, and a time-limited quiz starts its timer the moment it opens. The server never answers or submits — the student finishes in whatever client they choose, and the official client resumes the open attempt.
- The take flow authenticates through the token by itself: the server reads the `canvas_session` cookie from the signed-in browser on the same machine (Chrome family via the Keychain-decrypted cookie store; Firefox and Safari stores are probed too), so no manual cookie pasting is needed.
- Reading a Lockdown Browser exam through the API stays measured and honest: metadata and the current-user score read back fine; the question bank is served only during an active attempt, and Canvas says so when a preview is blocked.

## 0.6.0 — 2026-10-13

- Add `get_lockdown_quiz_access`. For every quiz Canvas flags `require_lockdown_browser`, one read-only call reports the quiz metadata (including the Respondus Monitor fields), a question bank probe with readability status, and the current-user submission with its score. Reading goes through the Canvas API with the same personal token the server already holds, so no separate client is needed. The server never answers or submits — the agent prepares answers for the student, who submits in whatever client they choose.
- Measured on a live token: metadata and the current-user submission with its score read back through the API for a Lockdown Browser exam; the question bank stays server-gated for student tokens outside an active attempt, and Canvas labels that clearly instead of guessing.
- Reframe the Lockdown Browser rules in AGENTS.md, README, and docs/roadmap-rejected.md: reading flagged-quiz content through the API is allowed; launching the official client, decompiled client code, insert libraries, and overlay tools stay out.

## 0.5.0 — 2026-10-12

- Add `get_course_requirement_graph`. Discussion, assignment, quiz, announcement, and the first 20 wiki pages are classified with fixed keywords and Canvas fields: initial post, peer reply, comment, feedback, attendance, form, and Lockdown Browser.
- A countable reply is met only when the current user's reply count reaches the number in the prompt. A reply with no number, a form, or a Lockdown Browser exam stays unknown. This server does not start Respondus.
- The engagement peer-requirement scan uses the same classifier.

## 0.4.0 — 2026-10-12

First public cut, from a private student server that had been used against a live Canvas token for a term.

- Require `CANVAS_BASE_URL`. The previous build defaulted to one school.
- Send a `User-Agent` that names this repository.
- Mark listed tools read-only, except `get_watch_diff`, which writes a local snapshot.
- Ship the engagement server in the same package.
- Leave the private homework runner out. It wrote into a local course tree. A generic owed-work report is on the roadmap.
