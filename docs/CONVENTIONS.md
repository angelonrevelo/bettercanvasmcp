# Conventions

Singular everywhere for names this repository invents.

- A list is `tool`, `claim`, `course_id` — not `tools` or `courses`.
- A count ends in `_count`. A boolean predicate starts with `is_`.
- TypeScript is camelCase. Env vars and Canvas query keys stay as the platform spells them.

Canvas response fields are an external dialect. Do not rename `submission_types`, `workflow_state`, or any other key Canvas returns. Matching the API is the exception. New wrappers around those payloads still use a singular name on our side (`submission`, `module_item`).

The two servers are one package. Do not add a second lockfile.
