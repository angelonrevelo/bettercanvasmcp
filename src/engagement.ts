#!/usr/bin/env node
/**
 * Canvas Engagement MCP Server
 *
 * Sits alongside a standard Canvas read MCP (e.g. vishalsachdev/canvas-mcp or
 * the local canvas-mcp). Provides the *derived* engagement signals that raw
 * Canvas reads do not give you: which discussions need a reply, which
 * assignments encode peer-response requirements in their description, what
 * your engagement state in a thread is, and what changed since you last
 * checked.
 *
 * Env:
 *   CANVAS_API_TOKEN  — required
 *   CANVAS_BASE_URL   — required, for example https://canvas.example.edu
 *   CANVAS_STATE_DIR  — defaults to ~/.cache/canvas-engagement
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { requirementFromPrompt } from './requirement.js';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

// ============================================================================
// Config
// ============================================================================

const argv = process.argv.slice(2);
function flag(name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : undefined;
}

const BASE_URL_RAW = flag('base-url') ?? process.env.CANVAS_BASE_URL;
const TOKEN = flag('token') ?? process.env.CANVAS_API_TOKEN;
const STATE_DIR =
  flag('state-dir') ?? process.env.CANVAS_STATE_DIR ?? join(homedir(), '.cache', 'canvas-engagement');
const STATE_FILE = join(STATE_DIR, 'state.json');

if (!BASE_URL_RAW) {
  console.error('[Canvas Engagement MCP] Missing CANVAS_BASE_URL. Pass --base-url or set the env var to your Canvas host, for example https://canvas.example.edu');
  process.exit(1);
}
if (!TOKEN) {
  console.error('[Canvas Engagement MCP] Missing CANVAS_API_TOKEN.');
  process.exit(1);
}

const BASE_URL = BASE_URL_RAW.replace(/\/+$/, '');
const USER_AGENT = 'better-canvas-mcp/0.5.0 (+https://github.com/angelonrevelo/bettercanvasmcp)';

function canvasHeader(accept: string): Record<string, string> {
  return { Authorization: `Bearer ${TOKEN}`, Accept: accept, 'User-Agent': USER_AGENT };
}

// ============================================================================
// Canvas REST helpers
// ============================================================================

async function canvasGet<T>(path: string, params?: Record<string, string | number | string[]>): Promise<T> {
  const url = new URL(`/api/v1${path}`, BASE_URL);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (Array.isArray(v)) for (const item of v) url.searchParams.append(k, String(item));
      else url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url, { headers: canvasHeader('application/json') });
  if (!res.ok) {
    throw new Error(`Canvas ${res.status} ${res.statusText} for ${url.pathname}: ${(await res.text()).slice(0, 300)}`);
  }
  return (await res.json()) as T;
}

async function canvasPaginate<T>(path: string, params?: Record<string, string | number | string[]>): Promise<T[]> {
  const url = new URL(`/api/v1${path}`, BASE_URL);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (Array.isArray(v)) for (const item of v) url.searchParams.append(k, String(item));
      else url.searchParams.set(k, String(v));
    }
  }
  url.searchParams.set('per_page', '100');
  const all: T[] = [];
  let next: string | null = url.toString();
  while (next) {
    const res: Response = await fetch(next, { headers: canvasHeader('application/json') });
    if (!res.ok) throw new Error(`Canvas ${res.status} ${res.statusText}: ${(await res.text()).slice(0, 300)}`);
    all.push(...((await res.json()) as T[]));
    const link = res.headers.get('link');
    next = link?.match(/<([^>]+)>;\s*rel="next"/)?.[1] ?? null;
  }
  return all;
}

// Pool of N concurrent async operations
async function pool<T, R>(items: T[], fn: (i: T) => Promise<R>, concurrency = 6): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (true) {
        const idx = cursor++;
        if (idx >= items.length) return;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
}

// ============================================================================
// Identity (cache user id + per-course teacher ids)
// ============================================================================

interface SelfUser {
  id: number;
  name: string;
  short_name: string;
  login_id?: string;
}

let selfCache: SelfUser | null = null;
async function getSelf(): Promise<SelfUser> {
  if (selfCache) return selfCache;
  selfCache = await canvasGet<SelfUser>('/users/self');
  return selfCache;
}

const teacherIdCache = new Map<string, Set<number>>();
async function getTeacherIds(courseId: string): Promise<Set<number>> {
  const cached = teacherIdCache.get(courseId);
  if (cached) return cached;
  const users = await canvasPaginate<{ id: number }>(`/courses/${courseId}/users`, {
    'enrollment_type[]': ['teacher', 'ta'],
  });
  const set = new Set(users.map((u) => u.id));
  teacherIdCache.set(courseId, set);
  return set;
}

// ============================================================================
// State file (get_watch_diff)
// ============================================================================

interface CourseState {
  lastChecked: string; // ISO
  seenEntryIds: number[]; // bounded
  seenAnnouncementIds: number[];
  seenAssignmentIds: number[];
}
interface State {
  courses: Record<string, CourseState>;
}

async function loadState(): Promise<State> {
  try {
    const raw = await readFile(STATE_FILE, 'utf8');
    return JSON.parse(raw) as State;
  } catch {
    return { courses: {} };
  }
}
async function saveState(state: State): Promise<void> {
  await mkdir(dirname(STATE_FILE), { recursive: true });
  await writeFile(STATE_FILE, JSON.stringify(state, null, 2));
}
function bound<T>(arr: T[], cap: number): T[] {
  return arr.length > cap ? arr.slice(arr.length - cap) : arr;
}

// ============================================================================
// Discussion tree walking
// ============================================================================

interface DiscussionEntry {
  id: number;
  user_id: number;
  parent_id: number | null;
  created_at: string;
  updated_at: string;
  message: string;
  rating_sum?: number;
  rating_count?: number;
  replies?: DiscussionEntry[];
}
interface DiscussionView {
  view: DiscussionEntry[]; // top-level entries; replies nested
  unread_entries?: number[];
  participants?: Array<{ id: number; display_name: string }>;
}

function flattenEntries(entries: DiscussionEntry[]): DiscussionEntry[] {
  const out: DiscussionEntry[] = [];
  const walk = (es: DiscussionEntry[]) => {
    for (const e of es) {
      out.push(e);
      if (e.replies && e.replies.length > 0) walk(e.replies);
    }
  };
  walk(entries);
  return out;
}

// ============================================================================
// Tool: list_reply_need
// ============================================================================

interface DiscussionTopic {
  id: number;
  title: string;
  posted_at: string | null;
  last_reply_at: string | null;
  require_initial_post: boolean | null;
  discussion_subentry_count: number;
  unread_count: number;
  read_state: 'read' | 'unread';
  locked: boolean;
  is_announcement: boolean;
  html_url: string;
  permissions?: { reply?: boolean };
  todo_date?: string | null;
  message?: string;
}

interface NeedsReplyHit {
  course_id: string;
  topic_id: number;
  title: string;
  reason: 'must_make_initial_post' | 'instructor_replied_to_me' | 'new_replies_after_my_last_post';
  detail: string;
  url: string;
  last_reply_at: string | null;
}

async function listActiveCourses(): Promise<Array<{ id: number; course_code: string; name: string }>> {
  return canvasPaginate('/courses', { enrollment_state: 'active' });
}

async function checkTopicForReply(
  courseId: string,
  topic: DiscussionTopic,
  selfId: number,
  teacherIds: Set<number>,
): Promise<NeedsReplyHit[]> {
  const hits: NeedsReplyHit[] = [];

  // Skip locked or announcement-only items where you can't reply
  if (topic.locked) return hits;
  if (topic.permissions && topic.permissions.reply === false) return hits;

  // 1. Must make initial post and haven't yet
  if (topic.require_initial_post) {
    // Need to load the view to check whether self has posted
    let view: DiscussionView | null = null;
    try {
      view = await canvasGet<DiscussionView>(`/courses/${courseId}/discussion_topics/${topic.id}/view`);
    } catch {
      view = null;
    }
    if (view) {
      const entries = flattenEntries(view.view ?? []);
      const myEntries = entries.filter((e) => e.user_id === selfId);
      if (myEntries.length === 0) {
        hits.push({
          course_id: courseId,
          topic_id: topic.id,
          title: topic.title,
          reason: 'must_make_initial_post',
          detail: 'This discussion requires an initial post before you can see other replies, and you have not yet posted.',
          url: topic.html_url,
          last_reply_at: topic.last_reply_at,
        });
        return hits;
      }
      // Check the other reasons against the loaded view
      hits.push(...checkRepliesAgainstView(courseId, topic, view, selfId, teacherIds));
      return hits;
    }
  }

  // 2. & 3. Otherwise still walk the tree if there are any replies
  if (topic.discussion_subentry_count === 0) return hits;

  let view: DiscussionView | null = null;
  try {
    view = await canvasGet<DiscussionView>(`/courses/${courseId}/discussion_topics/${topic.id}/view`);
  } catch {
    return hits;
  }
  hits.push(...checkRepliesAgainstView(courseId, topic, view, selfId, teacherIds));
  return hits;
}

function checkRepliesAgainstView(
  courseId: string,
  topic: DiscussionTopic,
  view: DiscussionView,
  selfId: number,
  teacherIds: Set<number>,
): NeedsReplyHit[] {
  const hits: NeedsReplyHit[] = [];
  const entries = flattenEntries(view.view ?? []);
  const myEntries = entries.filter((e) => e.user_id === selfId);
  if (myEntries.length === 0) return hits;

  const myEntryIds = new Set(myEntries.map((e) => e.id));
  const myLastAt = myEntries.reduce((m, e) => (e.created_at > m ? e.created_at : m), myEntries[0].created_at);

  // Instructor replied directly to one of my entries
  for (const e of entries) {
    if (e.parent_id != null && myEntryIds.has(e.parent_id) && teacherIds.has(e.user_id)) {
      hits.push({
        course_id: courseId,
        topic_id: topic.id,
        title: topic.title,
        reason: 'instructor_replied_to_me',
        detail: `Instructor (user ${e.user_id}) replied to your entry at ${e.created_at}.`,
        url: topic.html_url,
        last_reply_at: topic.last_reply_at,
      });
      return hits; // most-actionable signal; no need to also flag the generic case
    }
  }

  // New replies in the thread after my last post
  const repliesAfter = entries.filter((e) => e.user_id !== selfId && e.created_at > myLastAt);
  if (repliesAfter.length > 0) {
    hits.push({
      course_id: courseId,
      topic_id: topic.id,
      title: topic.title,
      reason: 'new_replies_after_my_last_post',
      detail: `${repliesAfter.length} new ${repliesAfter.length === 1 ? 'reply' : 'replies'} from others since your last post (${myLastAt}).`,
      url: topic.html_url,
      last_reply_at: topic.last_reply_at,
    });
  }
  return hits;
}

async function needsReply(args: { course_id?: string; max_topics_per_course?: number }): Promise<NeedsReplyHit[]> {
  const self = await getSelf();
  const courseIds: string[] = args.course_id
    ? [String(args.course_id)]
    : (await listActiveCourses()).map((c) => String(c.id));

  const allHits: NeedsReplyHit[] = [];
  for (const courseId of courseIds) {
    let topics: DiscussionTopic[];
    try {
      topics = await canvasPaginate<DiscussionTopic>(`/courses/${courseId}/discussion_topics`);
    } catch {
      continue;
    }
    if (args.max_topics_per_course && topics.length > args.max_topics_per_course) {
      topics = topics.slice(0, args.max_topics_per_course);
    }
    const teacherIds = await getTeacherIds(courseId);
    const perTopicHits = await pool(topics, (t) => checkTopicForReply(courseId, t, self.id, teacherIds), 4);
    for (const h of perTopicHits) allHits.push(...h);
  }
  return allHits;
}

// ============================================================================
// Tool: list_peer_response_requirement
// ============================================================================

// Requirement kinds come from src/requirement.ts so discussion, assignment, and engagement scans share one detector.
function stripHtml(s: string): string {
  return s.replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

interface PeerReqHit {
  course_id: string;
  source: 'assignment' | 'discussion';
  id: number;
  title: string;
  matched_label: string;
  matched_excerpt: string;
  url: string;
  due_at?: string | null;
  count_required: number | null;
  detector: string;
}

async function peerResponseRequirements(args: { course_id?: string }): Promise<PeerReqHit[]> {
  const courseIds: string[] = args.course_id
    ? [String(args.course_id)]
    : (await listActiveCourses()).map((c) => String(c.id));

  const hits: PeerReqHit[] = [];
  for (const courseId of courseIds) {
    const [assignments, discussions] = await Promise.all([
      canvasPaginate<{ id: number; name: string; description: string | null; due_at: string | null; html_url: string }>(
        `/courses/${courseId}/assignments`,
      ).catch(() => []),
      canvasPaginate<DiscussionTopic>(`/courses/${courseId}/discussion_topics`).catch(() => []),
    ]);

    for (const a of assignments) {
      const text = stripHtml(a.description ?? '');
      const requirement = requirementFromPrompt(text).filter((one) => (
        one.requirement_kind === 'peer_reply'
        || one.requirement_kind === 'comment'
        || one.requirement_kind === 'feedback'
        || one.requirement_kind === 'initial_post'
        || one.requirement_kind === 'attendance'
        || one.requirement_kind === 'form'
      ));
      for (const one of requirement) {
        hits.push({
          course_id: courseId,
          source: 'assignment',
          id: a.id,
          title: a.name,
          matched_label: one.requirement_kind,
          matched_excerpt: one.evidence,
          url: a.html_url,
          due_at: a.due_at,
          count_required: one.count_required,
          detector: one.detector,
        });
      }
    }

    for (const d of discussions) {
      const text = stripHtml(d.message ?? '');
      const requirement = requirementFromPrompt(`${d.title ?? ''} ${text}`).filter((one) => (
        one.requirement_kind === 'peer_reply'
        || one.requirement_kind === 'comment'
        || one.requirement_kind === 'feedback'
        || one.requirement_kind === 'initial_post'
        || one.requirement_kind === 'attendance'
        || one.requirement_kind === 'form'
      ));
      for (const one of requirement) {
        hits.push({
          course_id: courseId,
          source: 'discussion',
          id: d.id,
          title: d.title,
          matched_label: one.requirement_kind,
          matched_excerpt: one.evidence,
          url: d.html_url,
          due_at: d.todo_date ?? null,
          count_required: one.count_required,
          detector: one.detector,
        });
      }
    }
  }
  return hits;
}

// ============================================================================
// Tool: get_my_engagement_state
// ============================================================================

interface EngagementState {
  course_id: string;
  topic_id: number;
  title: string;
  my_post_count: number;
  my_top_level_post_count: number;
  my_reply_count: number;
  my_first_post_at: string | null;
  my_latest_post_at: string | null;
  total_other_posts: number;
  replies_to_me_count: number;
  instructor_replied_to_me: boolean;
  instructor_reply_excerpt: string | null;
  others_posts_after_my_last: number;
  total_entries: number;
  url: string;
}

async function myEngagementState(args: { course_id: string; topic_id: number }): Promise<EngagementState> {
  const courseId = String(args.course_id);
  const topicId = Number(args.topic_id);
  const [self, teacherIds, topic, view] = await Promise.all([
    getSelf(),
    getTeacherIds(courseId),
    canvasGet<DiscussionTopic>(`/courses/${courseId}/discussion_topics/${topicId}`),
    canvasGet<DiscussionView>(`/courses/${courseId}/discussion_topics/${topicId}/view`),
  ]);

  const entries = flattenEntries(view.view ?? []);
  const myEntries = entries.filter((e) => e.user_id === self.id);
  const myEntryIds = new Set(myEntries.map((e) => e.id));
  const repliesToMe = entries.filter((e) => e.parent_id != null && myEntryIds.has(e.parent_id));
  const instructorReplyToMe = repliesToMe.find((e) => teacherIds.has(e.user_id));
  const myLastAt = myEntries.length > 0
    ? myEntries.reduce((m, e) => (e.created_at > m ? e.created_at : m), myEntries[0].created_at)
    : null;
  const othersAfterMyLast = myLastAt
    ? entries.filter((e) => e.user_id !== self.id && e.created_at > myLastAt).length
    : 0;
  const myFirstAt = myEntries.length > 0
    ? myEntries.reduce((m, e) => (e.created_at < m ? e.created_at : m), myEntries[0].created_at)
    : null;

  return {
    course_id: courseId,
    topic_id: topicId,
    title: topic.title,
    my_post_count: myEntries.length,
    my_top_level_post_count: myEntries.filter((e) => e.parent_id == null).length,
    my_reply_count: myEntries.filter((e) => e.parent_id != null).length,
    my_first_post_at: myFirstAt,
    my_latest_post_at: myLastAt,
    total_other_posts: entries.filter((e) => e.user_id !== self.id).length,
    replies_to_me_count: repliesToMe.length,
    instructor_replied_to_me: !!instructorReplyToMe,
    instructor_reply_excerpt: instructorReplyToMe ? stripHtml(instructorReplyToMe.message).slice(0, 240) : null,
    others_posts_after_my_last: othersAfterMyLast,
    total_entries: entries.length,
    url: topic.html_url,
  };
}

// ============================================================================
// Tool: get_watch_diff
// ============================================================================

interface DiffResult {
  course_id: string;
  course_name: string;
  last_checked: string | null;
  new_announcements: Array<{ id: number; title: string; posted_at: string; url: string }>;
  new_assignments: Array<{ id: number; name: string; due_at: string | null; url: string }>;
  topics_with_new_replies: Array<{ id: number; title: string; new_entry_count: number; url: string }>;
}

async function watchDiff(args: { course_id?: string; reset?: boolean }): Promise<DiffResult[]> {
  const state = await loadState();
  if (args.reset) {
    if (args.course_id) delete state.courses[String(args.course_id)];
    else state.courses = {};
    await saveState(state);
  }

  const courses = args.course_id
    ? [{ id: Number(args.course_id), course_code: '', name: '' }]
    : await listActiveCourses();

  const results: DiffResult[] = [];
  for (const c of courses) {
    const courseId = String(c.id);
    const prev = state.courses[courseId] ?? {
      lastChecked: '',
      seenEntryIds: [],
      seenAnnouncementIds: [],
      seenAssignmentIds: [],
    };
    const seenEntryIds = new Set(prev.seenEntryIds);
    const seenAnnouncementIds = new Set(prev.seenAnnouncementIds);
    const seenAssignmentIds = new Set(prev.seenAssignmentIds);

    const [announcements, assignments, topics] = await Promise.all([
      canvasPaginate<{ id: number; title: string; posted_at: string; html_url: string }>(`/announcements`, {
        'context_codes[]': [`course_${courseId}`],
      }).catch(() => []),
      canvasPaginate<{ id: number; name: string; due_at: string | null; html_url: string }>(
        `/courses/${courseId}/assignments`,
      ).catch(() => []),
      canvasPaginate<DiscussionTopic>(`/courses/${courseId}/discussion_topics`).catch(() => []),
    ]);

    const newAnns = announcements.filter((a) => !seenAnnouncementIds.has(a.id));
    const newAssns = assignments.filter((a) => !seenAssignmentIds.has(a.id));

    const topicsWithNewReplies: DiffResult['topics_with_new_replies'] = [];
    for (const t of topics) {
      if (t.discussion_subentry_count === 0 && seenEntryIds.size > 0) continue;
      let view: DiscussionView | null = null;
      try {
        view = await canvasGet<DiscussionView>(`/courses/${courseId}/discussion_topics/${t.id}/view`);
      } catch {
        continue;
      }
      const entries = flattenEntries(view.view ?? []);
      // First-run case: don't flood with everything that ever existed — just record IDs
      if (prev.lastChecked === '') {
        for (const e of entries) seenEntryIds.add(e.id);
        continue;
      }
      const newEntries = entries.filter((e) => !seenEntryIds.has(e.id));
      if (newEntries.length > 0) {
        topicsWithNewReplies.push({ id: t.id, title: t.title, new_entry_count: newEntries.length, url: t.html_url });
        for (const e of newEntries) seenEntryIds.add(e.id);
      }
    }

    results.push({
      course_id: courseId,
      course_name: c.name,
      last_checked: prev.lastChecked || null,
      new_announcements: prev.lastChecked === '' ? [] : newAnns.map((a) => ({ id: a.id, title: a.title, posted_at: a.posted_at, url: a.html_url })),
      new_assignments: prev.lastChecked === '' ? [] : newAssns.map((a) => ({ id: a.id, name: a.name, due_at: a.due_at, url: a.html_url })),
      topics_with_new_replies: topicsWithNewReplies,
    });

    for (const a of announcements) seenAnnouncementIds.add(a.id);
    for (const a of assignments) seenAssignmentIds.add(a.id);

    state.courses[courseId] = {
      lastChecked: new Date().toISOString(),
      seenEntryIds: bound([...seenEntryIds], 5000),
      seenAnnouncementIds: bound([...seenAnnouncementIds], 500),
      seenAssignmentIds: bound([...seenAssignmentIds], 500),
    };
  }

  await saveState(state);
  return results;
}

// ============================================================================
// Tool: get_user_self
// ============================================================================

async function getUserSelf(): Promise<unknown> {
  const self = await getSelf();
  return { ...self, base_url: BASE_URL, state_dir: STATE_DIR };
}

// ============================================================================
// MCP server registration
// ============================================================================

interface MCPTool {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, unknown>; required?: string[] };
}

const tool: MCPTool[] = [
  {
    name: 'get_user_self',
    description: 'Return the current Canvas user (self) and engagement-MCP config (base URL, state dir). Useful for verifying the token resolves.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_reply_need',
    description:
      'Across all enrolled courses (or one course if course_id is given), return discussion topics where you should respond. Three signals: must-make-initial-post, instructor-replied-to-me, new-replies-after-my-last-post. Output is a flat list of hits with reason + URL.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: 'Optional. If omitted, scans all active enrollments.' },
        max_topics_per_course: { type: 'number', description: 'Optional cap to limit per-course scan cost.' },
      },
    },
  },
  {
    name: 'list_peer_response_requirement',
    description:
      'Scan assignment and discussion descriptions for peer-engagement language ("reply to N classmates", "respond to two peers", "comment on a peer post", etc.) that Canvas does not model as structured fields. Useful for THEO/FILI-style courses where the requirement is buried in prose.',
    inputSchema: {
      type: 'object',
      properties: { course_id: { type: 'string', description: 'Optional. If omitted, scans all active enrollments.' } },
    },
  },
  {
    name: 'get_my_engagement_state',
    description:
      'For one discussion topic, return derived engagement state: my post count, my first / latest post timestamps, replies received, whether the instructor replied to you, and the count of other posts after your last post. Drill-down counterpart to list_reply_need.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: 'Course id.' },
        topic_id: { type: 'number', description: 'Discussion topic id.' },
      },
      required: ['course_id', 'topic_id'],
    },
  },
  {
    name: 'get_watch_diff',
    description:
      "Compare the current Canvas state to a locally-cached snapshot. Returns new announcements, new assignments, and discussion topics with new entries since the last call. First call per course establishes the baseline (returns empty diffs); subsequent calls report deltas. Pass reset=true to clear the snapshot.",
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: 'Optional. If omitted, scans all active enrollments.' },
        reset: { type: 'boolean', description: 'If true, drop the cached snapshot before scanning.' },
      },
    },
  },
];

const handler: Record<string, (args: any) => Promise<unknown>> = {
  get_user_self: () => getUserSelf(),
  list_reply_need: (a) => needsReply(a ?? {}),
  list_peer_response_requirement: (a) => peerResponseRequirements(a ?? {}),
  get_my_engagement_state: (a) => myEngagementState(a),
  get_watch_diff: (a) => watchDiff(a ?? {}),
};

Object.assign(handler, {
  // Legacy aliases kept for existing saved MCP calls; listTools exposes the canonical names above.
  whoami: handler.get_user_self,
  needs_reply: handler.list_reply_need,
  peer_response_requirements: handler.list_peer_response_requirement,
  my_engagement_state: handler.get_my_engagement_state,
  watch_diff: handler.get_watch_diff,
});

const server = new Server(
  { name: 'better-canvas-engagement', version: '0.5.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tool.map((item) => ({
    ...item,
    annotations: {
      readOnlyHint: item.name !== 'get_watch_diff',
      destructiveHint: false,
      idempotentHint: item.name !== 'get_watch_diff',
      openWorldHint: true,
    },
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const selectedHandler = handler[name];
  if (!selectedHandler) return { content: [{ type: 'text', text: `Tool "${name}" not implemented` }], isError: true };
  try {
    const result = await selectedHandler(args ?? {});
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[Canvas Engagement MCP] Started @ ${BASE_URL}, state dir ${STATE_DIR}`);
}

main().catch((err) => {
  console.error('[Canvas Engagement MCP] Fatal:', err);
  process.exit(1);
});
