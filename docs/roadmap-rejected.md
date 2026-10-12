# Rejected

Killed on purpose. A later roadmap pass should not bring these back without a new reason.

- **Instructor writes** (create assignment, grade, post announcement, submit on the student's behalf). The popular servers are this product. A student token cannot do it, and this server's contract is that `submissions/self` is the only completion proof.
- **A hosted multi-tenant MCP.** Instructure's API Policy (12 August 2025) prohibits unapproved MCP access, and the largest public Canvas MCP retired its hosted endpoint for the same class of risk. The token stays on the caller's machine.
- **A default school hostname.** It made the private build unusable for anyone else.
- **commander.** The process already parses flags. A CLI framework does not change what Canvas returns.
- **Splitting `src/index.ts` into one file per endpoint family** as a goal of its own. It does not change a single tool result. Do it only when a change cannot land safely in the current file.
- **Copying the private homework runner.** It writes receipts into a local course tree and names a specific desk layout. The public replacement is an owed-work report on stdout, which is a roadmap item, not a port of that script.
- **Starting Lockdown Browser from this server.** The gate is a Respondus client check, not a Canvas API gate. Reading a flagged quiz's content, questions, and the current user's score through the token API is built (`get_lockdown_quiz_access`), and decompiled client code, insert libraries, and overlay tools stay out of this repo. Only launching the official client from here stays rejected.
