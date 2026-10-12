# Changelog

## 0.4.0 — 2026-10-12

First public cut, from a private student server that had been used against a live Canvas token for a term.

- Require `CANVAS_BASE_URL`. The previous build defaulted to one school.
- Send a `User-Agent` that names this repository.
- Mark listed tools read-only, except `get_watch_diff`, which writes a local snapshot.
- Ship the engagement server in the same package.
- Leave the private homework runner out. It wrote into a local course tree. A generic owed-work report is on the roadmap.
