#!/usr/bin/env node
import { Command } from 'commander';

interface OwedRow {
  context: string;
  title: string;
  href: string | null;
  due_at: string | null;
  submitted: boolean;
  submitted_at: string | null;
  score: number | null;
}

interface OwedOptions {
  baseUrl?: string;
  token?: string;
  course?: string;
}

function userAgent(): string {
  return 'better-canvas-mcp/0.7.0 (+https://github.com/angelonrevelo/bettercanvasmcp)';
}

async function canvasGet<T>(baseUrl: string, token: string, path: string, param?: Record<string, string>): Promise<T> {
  const url = new URL(path, baseUrl);
  for (const [key, value] of Object.entries(param ?? {})) url.searchParams.append(key, value);
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'User-Agent': userAgent() } });
  if (!res.ok) throw new Error(`Canvas ${res.status} ${res.statusText}: ${path}`);
  return (await res.json()) as T;
}

function unwrap<T>(row: unknown): T[] {
  return Array.isArray(row) ? (row as T[]) : [];
}

function truncate(value: string, max = 90): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

async function runOwed(options: { baseUrl?: string; token?: string; course?: string }): Promise<number> {
  const baseUrl = (options.baseUrl ?? process.env.CANVAS_BASE_URL ?? '').replace(/\/+$/, '');
  const token = options.token ?? process.env.CANVAS_API_TOKEN;
  const courseId = options.course ?? process.env.CANVAS_COURSE_ID;
  if (!baseUrl) {
    console.error('Missing CANVAS_BASE_URL. Pass --base-url or set the env var to your Canvas host, for example https://canvas.example.edu');
    return 1;
  }
  if (!token) {
    console.error('Missing CANVAS_API_TOKEN. Pass --token <t> or set env var.');
    return 1;
  }
  if (!courseId) {
    console.error('Missing --course <id> (or CANVAS_COURSE_ID). The owed report runs against one course.');
    return 1;
  }

  const [assignmentRows, plannerRows, course] = await Promise.all([
    canvasGet<any[]>(baseUrl, token, `/api/v1/courses/${courseId}/assignments`, {
      per_page: '100',
      'include[]': 'submission',
    }),
    canvasGet<any[]>(baseUrl, token, '/api/v1/planner/items', { per_page: '100' }).catch(() => [] as any[]),
    canvasGet<any>(baseUrl, token, `/api/v1/courses/${courseId}`).catch(() => ({})),
  ]);

  const rows: OwedRow[] = (unwrap<any>(assignmentRows))
    .filter((one) => !one?.is_quiz_assignment)
    .map((one) => {
      const submission = one?.submission ?? null;
      const submittedStates = ['submitted', 'graded', 'complete'];
      const submitted = !one?.submission_types?.includes('none') && (submittedStates.includes(submission?.workflow_state ?? '') || !!submission?.submitted_at);
      return {
        context: 'assignment',
        title: one?.name ?? one?.title ?? String(one?.id ?? ''),
        href: one?.html_url ?? null,
        due_at: one?.due_at ?? null,
        submitted,
        submitted_at: submission?.submitted_at ?? null,
        score: submission?.score ?? null,
      };
    });
  for (const item of unwrap<any>(plannerRows)) {
    const plannable = item?.plannable ?? {};
    if (plannable?.context_type === 'course' && String(plannable?.course_id ?? courseId) !== String(courseId)) continue;
    if (plannable?.type === 'planner_note') {
      rows.push({
        context: 'note',
        title: plannable?.title ?? '',
        href: item?.html_url ?? null,
        due_at: item?.plannable_date ?? plannable?.todo_date ?? null,
        submitted: false,
        submitted_at: null,
        score: null,
      });
    }
  }

  const owed = rows.filter((one) => !one.submitted);
  const courseName = (course as any)?.name ? ` — ${(course as any).name}` : '';
  console.log(`# Owed report — course ${courseId}${courseName}`);
  if (!owed.length) {
    console.log('Nothing owed: every visible assignment row is submitted.');
    return 0;
  }
  for (const one of owed) {
    const due = one.due_at ? new Date(one.due_at).toLocaleString('en-PH', { timeZone: 'Asia/Manila' }) : 'no due date';
    console.log(`- ${truncate(one.title)} · ${one.context} · due ${due}${one.href ? ` · ${one.href}` : ''}`);
  }
  console.log(`\n${owed.length} row${owed.length === 1 ? '' : 's'} owed. Planner rows are context, not proof: a planner item without a submission stays listed until Canvas shows the work submitted.`);
  return 0;
}

async function run(): Promise<number> {
  const program = new Command();
  program
    .name('better-canvas-mcp')
    .description('Canvas MCP for students. The owed report prints what the token holder still owes in one course.');

  program
    .command('owed')
    .description('Print what the token holder still owes in one course.')
    .option('--base-url <url>', 'Canvas host (or CANVAS_BASE_URL)')
    .option('--token <token>', 'Canvas personal access token (or CANVAS_API_TOKEN)')
    .option('--course <courseId>', 'Course id (or CANVAS_COURSE_ID)')
    .action(async (options: OwedOptions) => {
      process.exit(await runOwed(options));
    });

  await program.parseAsync(process.argv, { from: 'node' });
  return 0;
}

run().then((code) => process.exit(code)).catch((err) => {
  console.error(`owed failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
