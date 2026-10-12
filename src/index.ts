#!/usr/bin/env node
/**
 * Canvas LMS MCP Server
 *
 * Course-agnostic wrapper around the Canvas REST API. Each tool accepts an
 * optional `course_id`; when omitted, falls back to CANVAS_COURSE_ID / --course.
 *
 * Usage:
 *   CANVAS_API_TOKEN=... CANVAS_BASE_URL=https://canvas.example.edu node dist/index.js
 *   node dist/index.js --token <token> --base-url https://canvas.example.edu --course <id>
 *
 * CANVAS_BASE_URL is required. There is no school default.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { meetRequirement, mergeRequirement, requirementFromCanvas, requirementFromPrompt } from './requirement.js';

const execFileAsync = promisify(execFile);

interface ChromiumCookieStore {
  label: string;
  cookieFile: string;
  keychainService: string;
  keychainAccount: string;
}

async function execSafe(file: string, args: string[]): Promise<{ stdout: string; stderr?: string } | null> {
  try {
    const { stdout } = await execFileAsync(file, args, { encoding: 'utf8' });
    return { stdout };
  } catch (err) {
    return null;
  }
}

export async function extractCanvasSessionCookie(): Promise<{
  source: string | null;
  cookie_value: string | null;
  store: string | null;
  tried: string[];
}> {
  const support = join(process.env.HOME ?? '', 'Library', 'Application Support');
  const hosts: string[] = (() => {
    try {
      return [new URL(BASE_URL).hostname];
    } catch {
      return [];
    }
  })();
  const tried: string[] = [];
  const stores: ChromiumCookieStore[] = [
    { label: 'chrome', cookieFile: join(support, 'Google', 'Chrome', 'Default', 'Cookies'), keychainService: 'Chrome Safe Storage', keychainAccount: 'Chrome' },
    { label: 'brave', cookieFile: join(support, 'BraveSoftware', 'Brave-Browser', 'Default', 'Cookies'), keychainService: 'Brave Safe Storage', keychainAccount: 'Brave' },
    { label: 'edge', cookieFile: join(support, 'Microsoft Edge', 'Default', 'Cookies'), keychainService: 'Microsoft Edge Safe Storage', keychainAccount: 'Microsoft Edge' },
    { label: 'arc', cookieFile: join(support, 'Arc', 'User Data', 'Default', 'Cookies'), keychainService: 'Arc Safe Storage', keychainAccount: 'Arc' },
  ];
  for (const store of stores) {
    tried.push(store.label);
    if (!existsSync(store.cookieFile)) continue;
    const keyResult = await execSafe('/usr/bin/security', ['find-generic-password', '-w', '-a', store.keychainAccount, '-s', store.keychainService]);
    if (!keyResult) continue;
    const tmpParent = mkdtempSync(join(tmpdir(), "lq-"));
    if (!tmpParent) continue;
    const dbCopy = join(tmpParent, 'Cookies');
    try {
      copyFileSync(store.cookieFile, dbCopy);
      if (existsSync(`${store.cookieFile}-wal`)) copyFileSync(`${store.cookieFile}-wal`, `${dbCopy}-wal`);
      const query = await execSafe('/usr/bin/sqlite3', [dbCopy, '-json', `SELECT hex(encrypted_value) AS enc_hex, host_key FROM cookies WHERE name='canvas_session'`]);
      rmSync(tmpParent, { recursive: true, force: true });
      if (!query) continue;
      const rows = JSON.parse(query.stdout) as Array<{ enc_hex?: string; host_key?: string }>;
      for (const row of rows) {
        if (!row.enc_hex) continue;
        try {
          const blob = Buffer.from(row.enc_hex, 'hex');
          const prefix = blob.subarray(0, 3).toString();
          if (prefix !== 'v10') continue;
          const key = pbkdf2Sync(keyResult.stdout.trim(), 'saltysalt', 1003, 16, 'sha1');
          const decipher = createDecipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
          const plain = Buffer.concat([decipher.update(blob.subarray(3)), decipher.final()]);
          const cookieValue = plain.toString('latin1').slice(32);
          const hostKey = row.host_key ?? '';
          const hostMatch = !hostKey || hosts.some((h) => hostKey === h || hostKey === `.${h}` || hostKey.endsWith(`.${h}`));
          if (!hostMatch) continue;
          return { source: 'os-crypt', cookie_value: cookieValue, store: store.label, tried };
        } catch {
          continue;
        }
      }
    } finally {
      rmSync(tmpParent, { recursive: true, force: true });
    }
  }
  return { source: null, cookie_value: null, store: null, tried };
}


// ============================================================================
// CLI args + config
// ============================================================================

const argv = process.argv.slice(2);
function flag(name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : undefined;
}

const BASE_URL_RAW = flag('base-url') ?? process.env.CANVAS_BASE_URL ?? process.env.CANVAS_DEFAULT_HOST;
const TOKEN = flag('token') ?? process.env.CANVAS_API_TOKEN;
const DEFAULT_COURSE_ID = flag('course') ?? process.env.CANVAS_COURSE_ID;
const REQUEST_TIMEOUT_MS = Number(flag('request-timeout-ms') ?? process.env.CANVAS_REQUEST_TIMEOUT_MS ?? 30000);
const REQUEST_RETRY_COUNT = Number(flag('request-retry-count') ?? process.env.CANVAS_REQUEST_RETRY_COUNT ?? 2);
const ALLOW_WRITES = (flag('allow-writes') ?? process.env.CANVAS_ALLOW_WRITES ?? '') === '1';

if (!BASE_URL_RAW) {
  console.error('[Canvas MCP] Missing CANVAS_BASE_URL. Pass --base-url or set the env var to your Canvas host, for example https://canvas.example.edu');
  process.exit(1);
}
if (!TOKEN) {
  console.error('[Canvas MCP] Missing CANVAS_API_TOKEN. Pass --token <t> or set env var.');
  process.exit(1);
}

const BASE_URL = BASE_URL_RAW.replace(/\/+$/, '');
const USER_AGENT = 'better-canvas-mcp/0.7.0 (+https://github.com/angelonrevelo/bettercanvasmcp)';

function canvasHeader(accept: string): Record<string, string> {
  return { Authorization: `Bearer ${TOKEN}`, Accept: accept, 'User-Agent': USER_AGENT };
}

// ============================================================================
// Canvas REST client
// ============================================================================

type CanvasParamValue = string | number | boolean | Array<string | number | boolean>;

function applyParam(url: URL, param?: Record<string, CanvasParamValue>): void {
  if (!param) return;
  for (const [key, value] of Object.entries(param)) {
    if (Array.isArray(value)) for (const item of value) url.searchParams.append(key, String(item));
    else url.searchParams.set(key, String(value));
  }
}

function canvasApiUrl(path: string, param?: Record<string, CanvasParamValue>): URL {
  const requestPath = String(path ?? '').trim();
  if (/^https?:\/\//i.test(requestPath)) {
    throw new Error('request_canvas_api accepts Canvas API paths only, not full URLs');
  }
  if (!requestPath.startsWith('/api/')) {
    throw new Error('request_canvas_api path must start with /api/');
  }
  if (requestPath.includes('..')) {
    throw new Error('request_canvas_api path cannot contain .. segments');
  }
  const url = new URL(requestPath, BASE_URL);
  applyParam(url, param);
  return url;
}

async function canvasFetch(input: URL | string, init: RequestInit): Promise<Response> {
  const retryCount = Math.max(0, REQUEST_RETRY_COUNT);
  let lastError: unknown = null;
  for (let attemptIndex = 0; attemptIndex <= retryCount; attemptIndex += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await fetch(input, { ...init, signal: controller.signal });
    } catch (error) {
      lastError = error;
      if (error instanceof Error && error.name === 'AbortError') {
        const url = typeof input === 'string' ? input : input.pathname;
        throw new Error(`Canvas request timed out after ${REQUEST_TIMEOUT_MS}ms: ${url}`);
      }
      if (attemptIndex >= retryCount) {
        throw error;
      }
      await new Promise((resolveRetry) => setTimeout(resolveRetry, 250 * (attemptIndex + 1)));
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Canvas request failed');
}

async function canvasApiGet(path: string, param?: Record<string, CanvasParamValue>): Promise<unknown> {
  const url = canvasApiUrl(path, param);
  const res = await canvasFetch(url, {
    headers: canvasHeader('application/json'),
  });
  if (!res.ok) throw new Error(`Canvas ${res.status} ${res.statusText} for ${url.pathname}: ${await res.text()}`);
  return res.json();
}

async function canvasApiPaginate<T>(path: string, param?: Record<string, CanvasParamValue>): Promise<T[]> {
  const url = canvasApiUrl(path, param);
  url.searchParams.set('per_page', '100');

  const all: T[] = [];
  let next: string | null = url.toString();
  while (next) {
    const res = await canvasFetch(next, { headers: canvasHeader('application/json') });
    if (!res.ok) throw new Error(`Canvas ${res.status} ${res.statusText}: ${await res.text()}`);
    all.push(...((await res.json()) as T[]));
    const link = res.headers.get('link');
    next = link?.match(/<([^>]+)>;\s*rel="next"/)?.[1] ?? null;
  }
  return all;
}

async function canvasGet(path: string, param?: Record<string, CanvasParamValue>): Promise<unknown> {
  return canvasApiGet(`/api/v1${path}`, param);
}

async function canvasPaginate<T>(path: string, param?: Record<string, CanvasParamValue>): Promise<T[]> {
  return canvasApiPaginate<T>(`/api/v1${path}`, param);
}

async function canvasDownload(url: string): Promise<{ buffer: Buffer; contentType: string }> {
  const res = await canvasFetch(url, { headers: canvasHeader('*/*') });
  if (!res.ok) throw new Error(`Canvas ${res.status} ${res.statusText} while downloading file: ${await res.text()}`);
  return {
    buffer: Buffer.from(await res.arrayBuffer()),
    contentType: res.headers.get('content-type') ?? '',
  };
}

function courseId(args: { course_id?: string | number }): string {
  const id = args.course_id ?? DEFAULT_COURSE_ID;
  if (id === undefined || id === null || id === '') {
    throw new Error('No course_id provided and CANVAS_COURSE_ID/--course not set');
  }
  return String(id);
}

// ============================================================================
// Tool definitions
// ============================================================================

const COURSE_ID_DESC = DEFAULT_COURSE_ID
  ? `Canvas course ID (default: ${DEFAULT_COURSE_ID})`
  : 'Canvas course ID (required — no default configured)';

interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

const tool: MCPTool[] = [
  {
    name: 'list_course',
    description: 'List Canvas courses visible to the current user, including term/enrollment metadata. Use this to decide whether a shell is relevant to the current term before treating assignments as actionable.',
    inputSchema: {
      type: 'object',
      properties: {
        enrollment_state: {
          type: 'string',
          enum: ['active', 'completed'],
          description: 'Enrollment state filter. Defaults to active.',
        },
        state: {
          type: 'string',
          description: 'Optional Canvas course workflow state, e.g. available or completed.',
        },
        include_concluded: {
          type: 'boolean',
          description: 'When true, append include[]=concluded.',
        },
      },
    },
  },
  {
    name: 'get_user_self',
    description: 'Return the Canvas user resolved by the API token.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_user_canvas_context',
    description: 'Fetch bounded current-user Canvas context: profile, safe login and access-token visibility, favorite courses, course nicknames, dashboard cards/positions, custom colors, bookmarks, observees, recent graded submissions, and selected current-course progress/preference includes. Read-only; it does not create bookmarks, favorites, login changes, access tokens, or nickname changes.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_bookmark: {
          type: 'boolean',
          description: 'When true, include current-user bookmarks. Defaults to true.',
        },
        include_dashboard_card: {
          type: 'boolean',
          description: 'When true, include dashboard cards. Defaults to true.',
        },
        include_observee: {
          type: 'boolean',
          description: 'When true, include linked observees when Canvas exposes them. Defaults to true.',
        },
        include_user_preference: {
          type: 'boolean',
          description: 'When true, include current-user custom colors and dashboard positions. Defaults to true.',
        },
        include_graded_submission: {
          type: 'boolean',
          description: 'When true, include current-user most-recently graded submissions. Defaults to true.',
        },
        include_login: {
          type: 'boolean',
          description: 'When true, include sanitized current-user login visibility. Defaults to true.',
        },
        include_access_token: {
          type: 'boolean',
          description: 'When true, include sanitized current-user manually generated access-token visibility. Defaults to true.',
        },
        access_token_id: {
          type: 'string',
          description: 'Optional access token ID for the detail endpoint. Defaults to the first visible token when present. Token values and token hints are never returned.',
        },
        max_bookmark: {
          type: 'number',
          description: 'Maximum bookmark rows to return. Defaults to 80.',
        },
        max_dashboard_card: {
          type: 'number',
          description: 'Maximum dashboard card rows to return. Defaults to 80.',
        },
        max_favorite_course: {
          type: 'number',
          description: 'Maximum favorite course rows to return. Defaults to 80.',
        },
        max_observee: {
          type: 'number',
          description: 'Maximum observee rows to return. Defaults to 20.',
        },
        max_graded_submission: {
          type: 'number',
          description: 'Maximum recent graded submission rows to return. Defaults to 20.',
        },
        max_login: {
          type: 'number',
          description: 'Maximum sanitized current-user login rows to return. Defaults to 20.',
        },
        max_access_token: {
          type: 'number',
          description: 'Maximum sanitized current-user access-token rows to return. Defaults to 20.',
        },
      },
    },
  },
  {
    name: 'get_user_page_view_context',
    description: 'Fetch bounded current-user Canvas page-view history as weak activity evidence. Read-only; uses only the GET page-view endpoint for users/self and does not create async page-view query jobs.',
    inputSchema: {
      type: 'object',
      properties: {
        start_time: {
          type: 'string',
          description: 'Optional ISO start timestamp for page-view history.',
        },
        end_time: {
          type: 'string',
          description: 'Optional ISO end timestamp for page-view history.',
        },
        max_page_view: {
          type: 'number',
          description: 'Maximum page-view rows to request and return. Defaults to 25; capped at 100.',
        },
      },
    },
  },
  {
    name: 'get_user_file_context',
    description: 'Fetch bounded current-user Canvas file storage context: user files, folders, root folder, and quota. Read-only; does not create folders, upload files, copy files, or change usage rights.',
    inputSchema: {
      type: 'object',
      properties: {
        max_folder: {
          type: 'number',
          description: 'Maximum current-user folder rows to return. Defaults to 100.',
        },
        max_file: {
          type: 'number',
          description: 'Maximum current-user file rows to return. Defaults to 200.',
        },
        include_folder_file: {
          type: 'boolean',
          description: 'When true, sample files directly from readable user folders. Defaults to true.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract text from a bounded set of reading-like current-user Canvas files.',
        },
        extract_file_id: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional Canvas file IDs to prioritize for extraction.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum files to extract when extract_file is true. Defaults to 3.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum extracted characters per file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'get_user_eportfolio_context',
    description: 'Fetch bounded current-user Canvas ePortfolio context: ePortfolio list, optional detail, and page metadata/content when Canvas permits it. Read-only; does not delete, restore, or moderate ePortfolios.',
    inputSchema: {
      type: 'object',
      properties: {
        eportfolio_id: {
          type: 'string',
          description: 'Optional ePortfolio ID to inspect. When omitted, visible current-user ePortfolios are sampled up to max_eportfolio.',
        },
        include_page: {
          type: 'boolean',
          description: 'When true, include bounded ePortfolio page rows. Defaults to true.',
        },
        max_eportfolio: {
          type: 'number',
          description: 'Maximum ePortfolio rows to inspect. Defaults to 20.',
        },
        max_page: {
          type: 'number',
          description: 'Maximum page rows per ePortfolio to return. Defaults to 50.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped page content characters per row. Defaults to 1000.',
        },
      },
    },
  },
  {
    name: 'get_user_content_share_context',
    description: 'Fetch bounded current-user Canvas Content Share context: sent shares, received shares, unread count, and optional detail for a visible share. Read-only; does not create, update, delete, mark read/unread, or add receivers.',
    inputSchema: {
      type: 'object',
      properties: {
        content_share_id: {
          type: 'string',
          description: 'Optional visible content share ID to fetch in detail. If omitted, the first received or sent share is used when available.',
        },
        max_content_share: {
          type: 'number',
          description: 'Maximum sent/received share rows to return. Defaults to 50.',
        },
      },
    },
  },
  {
    name: 'request_canvas_api',
    description: 'Read any Canvas API GET path the token can access, including non-/api/v1 namespaces such as /api/quiz/v1. This is a read-only escape hatch for endpoint probing; use specialized tools when they exist.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Canvas API path beginning with /api/, for example /api/v1/users/self or /api/quiz/v1/courses/:course_id/quizzes. Full URLs are rejected.',
        },
        param: {
          type: 'object',
          description: 'Optional query parameter map. Values may be strings, numbers, booleans, or arrays of those primitives.',
          additionalProperties: true,
        },
        paginate: {
          type: 'boolean',
          description: 'When true, follow Canvas Link rel=next pagination and return a combined array. Use only for endpoints that return arrays.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'get_canvas_api_capability',
    description: 'Probe a bounded read-only Canvas API capability matrix through the MCP and report ok/blocked/skipped/error per endpoint family. Returns only status, row counts, sample keys, paths, and source docs; it does not persist raw private content.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: {
          type: 'string',
          description: 'Canvas course ID to probe. Defaults to course_id env/flag or the newest visible active course.',
        },
        assignment_id: {
          type: 'string',
          description: 'Assignment ID used for assignment-scoped probes. Defaults to a visible assignment with a due date.',
        },
        quiz_id: {
          type: 'string',
          description: 'Classic Quiz ID used for Classic Quiz submission probe. Defaults to the first visible Classic Quiz.',
        },
        course_report_type: {
          type: 'string',
          description: 'Optional Course Reports report_type for Course Report status probes.',
        },
        course_report_id: {
          type: 'string',
          description: 'Optional Course Reports report ID for the specific report status probe.',
        },
        content_migration_id: {
          type: 'string',
          description: 'Optional Content Migration ID for migration detail/issue/selective-data probes.',
        },
        migration_issue_id: {
          type: 'string',
          description: 'Optional migration issue ID for the specific migration issue detail probe.',
        },
        account_id: {
          type: 'string',
          description: 'Optional account ID for account-scoped probes. Defaults to course.root_account_id, then course.account_id.',
        },
        account_notification_id: {
          type: 'string',
          description: 'Optional account notification ID for the account notification detail probe.',
        },
        section_id: {
          type: 'string',
          description: 'Optional section ID for section detail and section-user probes. Defaults to the first visible section.',
        },
        temporary_enrollment_pairing_id: {
          type: 'string',
          description: 'Optional temporary enrollment pairing ID for the temporary enrollment pairing detail probe.',
        },
        enrollment_term_id: {
          type: 'string',
          description: 'Optional enrollment term ID for enrollment term detail probes.',
        },
        role_id: {
          type: 'string',
          description: 'Optional role ID for account role detail probes.',
        },
        sis_import_id: {
          type: 'string',
          description: 'Optional SIS import ID for SIS import detail/error probes.',
        },
        account_domain: {
          type: 'string',
          description: 'Optional account domain for the account_domain lookup probe. Defaults to the configured Canvas host.',
        },
        start_date: {
          type: 'string',
          description: 'YYYY-MM-DD window start for planner/calendar reads. Defaults to 14 days ago.',
        },
        end_date: {
          type: 'string',
          description: 'YYYY-MM-DD window end for planner/calendar reads. Defaults to 45 days from now.',
        },
        probe_id: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional capability probe IDs to run. Omit to run the full bounded matrix. Use list_canvas_api_endpoint to discover IDs.',
        },
      },
    },
  },
  {
    name: 'list_canvas_api_endpoint',
    description: 'List the Canvas endpoint families known to this MCP capability matrix, including probe IDs, method, pagination shape, required context, and documentation links.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'resolve_canvas_link',
    description: 'Resolve a Canvas web URL, Canvas API path, or Canvas file link into the matching read-only MCP/API response. Can extract text from linked Canvas files and returns links found inside extracted text.',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'Canvas URL or path, for example /courses/:course_id/assignments/:assignment_id, /courses/:course_id/files/:file_id, or /api/v1/users/self.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true and the link resolves to a Canvas file, download and extract bounded text/links using extract_file_text.',
        },
        include_assignment_context: {
          type: 'boolean',
          description: 'When true and the link resolves to an assignment, return get_assignment_context instead of plain assignment metadata.',
        },
        include_discussion_context: {
          type: 'boolean',
          description: 'When true and the link resolves to a discussion, return get_discussion_context instead of plain topic metadata.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum extracted characters for file or assignment attachment extraction. Defaults to 1200.',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'get_course',
    description: `Get Canvas course metadata + syllabus body.${DEFAULT_COURSE_ID ? ` Default course_id is ${DEFAULT_COURSE_ID}.` : ''}`,
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
      },
    },
  },
  {
    name: 'get_course_action_context',
    description: 'Fetch sanitized course-level action context for owed-work checks: planner/todo/missing queues, calendar, grade/weight keys, own groups, tabs, appointments, outcomes, activity summary, and recent history. This is cross-check context; use submissions/self for completion truth.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        start_date: {
          type: 'string',
          description: 'YYYY-MM-DD window start for planner/calendar reads. Defaults to 14 days ago.',
        },
        end_date: {
          type: 'string',
          description: 'YYYY-MM-DD window end for planner/calendar reads. Defaults to 45 days from now.',
        },
        max_history: {
          type: 'number',
          description: 'Maximum recent-history/activity rows to return after sanitization. Defaults to 25.',
        },
        include_conversation_body: {
          type: 'boolean',
          description: 'When true, fetch unread course conversation bodies and return only short due-date candidate excerpts. Raw bodies are never returned.',
        },
        max_conversation: {
          type: 'number',
          description: 'Maximum unread conversations to inspect when include_conversation_body is true. Defaults to 5.',
        },
      },
    },
  },
  {
    name: 'get_course_planner_context',
    description: 'Fetch bounded course planner context: planner items, planner notes, planner overrides, linked-object URLs, marked-complete/dismissed signals, and reminder text. This is user-visible planning context, not submission truth.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        start_date: {
          type: 'string',
          description: 'YYYY-MM-DD or ISO date window start. Defaults to 30 days ago.',
        },
        end_date: {
          type: 'string',
          description: 'YYYY-MM-DD or ISO date window end. Defaults to 60 days from now.',
        },
        filter: {
          type: 'string',
          enum: ['incomplete_items', 'complete_items', 'new_activity'],
          description: 'Optional Canvas planner item filter. Defaults to incomplete_items.',
        },
        max_item: {
          type: 'number',
          description: 'Maximum planner items to return. Defaults to 120.',
        },
        max_note: {
          type: 'number',
          description: 'Maximum planner notes to return. Defaults to 80.',
        },
        max_override: {
          type: 'number',
          description: 'Maximum planner overrides to return. Defaults to 120.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped planner note text characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_due_date_context',
    description: 'Fetch bounded current-user course due-date and policy context: assignment all_dates/overrides, effective due dates for the token user only, course todo, course settings, and selected course permissions.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional assignment IDs to prioritize for effective due-date lookup. When omitted, visible assignments are sampled up to max_assignment.',
        },
        include_assignment: {
          type: 'boolean',
          description: 'When true, read course assignments with all_dates and overrides. Defaults to true.',
        },
        include_setting: {
          type: 'boolean',
          description: 'When true, read course settings. Defaults to true.',
        },
        include_permission: {
          type: 'boolean',
          description: 'When true, read selected course permissions for the current token user. Defaults to true.',
        },
        permission_name: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional Canvas permission names for /courses/:course_id/permissions. Defaults to a small read/grade/assignment-oriented set.',
        },
        max_assignment: {
          type: 'number',
          description: 'Maximum assignment rows/effective due-date IDs to return. Defaults to 120.',
        },
      },
    },
  },
  {
    name: 'get_course_outcome_context',
    description: 'Fetch bounded read-only course outcome context: root outcome group, outcome groups, outcome links, current-user outcome alignments/results/rollups, and assignment-scoped outcome evidence when an assignment_id is provided.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: {
          type: 'string',
          description: 'Optional assignment ID used to filter outcome alignments for the current user.',
        },
        include_result: {
          type: 'boolean',
          description: 'When true, include current-user outcome results and rollups. Defaults to true.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum outcome group rows to return. Defaults to 80.',
        },
        max_link: {
          type: 'number',
          description: 'Maximum outcome link rows to return. Defaults to 120.',
        },
        max_alignment: {
          type: 'number',
          description: 'Maximum outcome alignment rows to return. Defaults to 120.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped description/title characters per outcome row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_assessment_context',
    description: 'Fetch bounded read-only rubric catalog/detail/used-location context, LiveAssessments, assessment question banks/questions, assignment-embedded rubric, learning-object date detail, and current-user rubric/document read-state context. Catalog/detail/live/date/question-bank endpoints may be blocked under a student PAT.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: {
          type: 'string',
          description: 'Optional Canvas assignment id for embedded rubric, learning-object date detail, and read-state checks.',
        },
        max_rubric: {
          type: 'number',
          description: 'Maximum course rubric catalog rows to return. Defaults to 50.',
        },
        rubric_id: {
          type: 'string',
          description: 'Optional Canvas rubric id for single-rubric detail and used-location checks.',
        },
        max_question_bank: {
          type: 'number',
          description: 'Maximum course assessment question-bank rows to return. Defaults to 50.',
        },
        max_question: {
          type: 'number',
          description: 'Maximum selected assessment question rows to return. Defaults to 80.',
        },
        live_assessment_id: {
          type: 'string',
          description: 'Optional Canvas LiveAssessment id for result lookup.',
        },
        max_live_assessment: {
          type: 'number',
          description: 'Maximum LiveAssessment rows to return. Defaults to 50.',
        },
        max_live_assessment_result: {
          type: 'number',
          description: 'Maximum selected LiveAssessment result rows to return. Defaults to 80.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped question/title characters per question-bank row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_assignment_moderation_context',
    description: 'Fetch read-only Moderated Grading visibility for one assignment: moderated-student rows and current-user provisional-grade status when Canvas permits them. It never selects, publishes, or mutates provisional grades.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: { type: 'string', description: 'Canvas assignment id' },
        anonymous_id: {
          type: 'string',
          description: 'Optional anonymous grading ID for anonymous provisional-grade status.',
        },
        max_student: {
          type: 'number',
          description: 'Maximum moderated-student rows to return. Defaults to 80.',
        },
      },
      required: ['assignment_id'],
    },
  },
  {
    name: 'get_course_roster_context',
    description: 'Fetch bounded read-only course roster/scope context: sections, current-user enrollment, compact visible course users, group categories, groups in categories, category-user visibility, and LTI Names and Role membership visibility. This is section/group scope evidence, not assignment completion proof.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_user: {
          type: 'boolean',
          description: 'When true, include compact visible course users with enrollment summaries. Defaults to true.',
        },
        include_category_group: {
          type: 'boolean',
          description: 'When true, include bounded groups inside visible group categories. Defaults to true.',
        },
        include_category_user: {
          type: 'boolean',
          description: 'When true, include bounded users visible through group-category membership endpoints. Defaults to true.',
        },
        include_lti_name_role: {
          type: 'boolean',
          description: 'When true, include bounded LTI Names and Role course/group membership rows when Canvas permits them. Defaults to true.',
        },
        include_section_detail: {
          type: 'boolean',
          description: 'When true, include detail for one visible section. Defaults to true.',
        },
        include_section_user: {
          type: 'boolean',
          description: 'When true, include bounded users for one visible section. Defaults to true.',
        },
        max_user: {
          type: 'number',
          description: 'Maximum course-user rows to return. Defaults to 80.',
        },
        max_section_user: {
          type: 'number',
          description: 'Maximum section-user rows to return. Defaults to 80.',
        },
        max_group_category: {
          type: 'number',
          description: 'Maximum group-category rows to inspect. Defaults to 40.',
        },
        max_category_group: {
          type: 'number',
          description: 'Maximum groups to return per group category. Defaults to 40.',
        },
        max_category_user: {
          type: 'number',
          description: 'Maximum users to return per group category. Defaults to 40.',
        },
        max_lti_name_role: {
          type: 'number',
          description: 'Maximum LTI Names and Role member rows to return per endpoint. Defaults to 80.',
        },
      },
    },
  },
  {
    name: 'get_course_group_context',
    description: 'Fetch bounded current-user group workspace context for one course: own groups, group tabs, permissions, memberships, members, files/folders, pages, discussions, activity stream/summary, embedded links/files, and requirement signals. This does not pull broad course rosters or change group membership.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        group_id: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional own group IDs to inspect. When omitted, all current-user groups for the course are inspected up to max_group.',
        },
        include_member: {
          type: 'boolean',
          description: 'When true, include bounded group-member rows for own groups. Defaults to true.',
        },
        include_workspace: {
          type: 'boolean',
          description: 'When true, read group tabs, permissions, memberships, files/folders/pages/discussions/activity stream and summary. Defaults to true.',
        },
        include_page_body: {
          type: 'boolean',
          description: 'When true, fetch bounded group page bodies for links and requirement signals. Defaults to true.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract bounded text from Canvas files linked in own group workspaces.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum own group rows to inspect. Defaults to 10.',
        },
        max_member: {
          type: 'number',
          description: 'Maximum group member rows per own group. Defaults to 20.',
        },
        max_file: {
          type: 'number',
          description: 'Maximum file rows per own group. Defaults to 50.',
        },
        max_page: {
          type: 'number',
          description: 'Maximum page rows per own group. Defaults to 30.',
        },
        max_discussion: {
          type: 'number',
          description: 'Maximum discussion rows per own group. Defaults to 30.',
        },
        max_activity: {
          type: 'number',
          description: 'Maximum activity-stream rows per own group. Defaults to 30.',
        },
        max_membership: {
          type: 'number',
          description: 'Maximum membership rows per own group. Defaults to 40.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum group-linked files to extract when extract_file is true. Defaults to 6.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped text/extracted characters per body/file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'get_course_collaboration_context',
    description: 'Fetch bounded read-only collaboration context for a course and the current user own groups: course collaborations, own-group collaborations, collaboration members, provider/document links, and group-work signals. This does not scan broad potential collaborator rosters.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_group_collaboration: {
          type: 'boolean',
          description: 'When true, include collaboration rows from current-user own groups in the course. Defaults to true.',
        },
        include_member: {
          type: 'boolean',
          description: 'When true, fetch bounded /collaborations/:id/members rows for visible collaborations. Defaults to true.',
        },
        max_collaboration: {
          type: 'number',
          description: 'Maximum course/group collaboration rows to return. Defaults to 80.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum current-user own groups to inspect for group collaborations. Defaults to 10.',
        },
        max_member: {
          type: 'number',
          description: 'Maximum collaboration members per collaboration to return. Defaults to 25.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped collaboration description characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_calendar_context',
    description: 'Fetch bounded course calendar context: event rows, assignment-event rows, event details, appointment groups, embedded links/files, location/online/onsite/device/deadline signals, and optional linked-file extraction. This is read-only and does not reserve slots.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        start_date: {
          type: 'string',
          description: 'YYYY-MM-DD or ISO date window start. Defaults to 30 days ago.',
        },
        end_date: {
          type: 'string',
          description: 'YYYY-MM-DD or ISO date window end. Defaults to 60 days from now.',
        },
        include_event_detail: {
          type: 'boolean',
          description: 'When true, fetch bounded detail rows through /calendar_events/:id for concrete event ids. Defaults to true.',
        },
        include_group_calendar: {
          type: 'boolean',
          description: 'When true, include current-user course group context codes in the calendar query when available. Defaults to true.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract bounded text from Canvas files linked in calendar event descriptions.',
        },
        max_event: {
          type: 'number',
          description: 'Maximum calendar event rows to return. Defaults to 80.',
        },
        max_detail: {
          type: 'number',
          description: 'Maximum event detail rows to fetch. Defaults to 20.',
        },
        max_appointment_group: {
          type: 'number',
          description: 'Maximum appointment group rows to return. Defaults to 30.',
        },
        max_appointment_user: {
          type: 'number',
          description: 'Maximum users from one visible appointment group participant list to return. Defaults to 40.',
        },
        max_appointment_group_participant: {
          type: 'number',
          description: 'Maximum groups from one visible appointment group participant list to return. Defaults to 40.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum calendar-linked files to extract when extract_file is true. Defaults to 6.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped event/extracted file characters per row/file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'get_course_term_context',
    description: 'Fetch current-user course term/section/enrollment context: term, section dates, grading periods, concluded/course-date flags, teachers when Canvas includes them, and own enrollment rows. Use this to decide whether a Canvas shell is relevant before classifying work.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_completed: {
          type: 'boolean',
          description: 'When true, include completed enrollment rows in current-user enrollment context. Defaults to false.',
        },
      },
    },
  },
  {
    name: 'get_course_grade_context',
    description: 'Fetch bounded read-only current-user grade, assignment-group weight, grading-period, and grading-standard context. Grade context is cross-check evidence and never overrides submission truth.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        max_assignment_group: {
          type: 'number',
          description: 'Maximum assignment group rows to return. Defaults to 80.',
        },
        max_grading_standard: {
          type: 'number',
          description: 'Maximum grading standard rows to return. Defaults to 40.',
        },
        assignment_id: {
          type: 'string',
          description: 'Optional assignment ID used to filter the current-user Gradebook History feed.',
        },
        max_gradebook_history_feed: {
          type: 'number',
          description: 'Maximum current-user Gradebook History feed rows to return. Defaults to 20.',
        },
        max_grade_change_event: {
          type: 'number',
          description: 'Maximum Grade Change Log audit rows to return per course/assignment scope. Defaults to 20.',
        },
        start_time: {
          type: 'string',
          description: 'ISO/date window start for Grade Change Log audit events. Defaults to 30 days ago.',
        },
        end_time: {
          type: 'string',
          description: 'ISO/date window end for Grade Change Log audit events. Defaults to today.',
        },
        include_custom_gradebook_column_data: {
          type: 'boolean',
          description: 'When true, fetch data for the first visible custom gradebook column and return only current-user rows. Defaults to false.',
        },
        max_custom_gradebook_column: {
          type: 'number',
          description: 'Maximum custom gradebook column metadata rows to return. Defaults to 40.',
        },
        max_custom_gradebook_column_datum: {
          type: 'number',
          description: 'Maximum current-user custom gradebook column data rows to return when included. Defaults to 20.',
        },
      },
    },
  },
  {
    name: 'get_course_activity_context',
    description: 'Fetch bounded read-only activity, course audit-log, recent-history, unread inbox, and optional sanitized conversation-detail context for a course. Raw conversation bodies are never returned.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_conversation_detail: {
          type: 'boolean',
          description: 'When true, fetch details for returned unread conversations and return only short deadline-related excerpts. Defaults to false.',
        },
        max_activity: {
          type: 'number',
          description: 'Maximum course activity stream rows to return. Defaults to 80.',
        },
        max_audit_event: {
          type: 'number',
          description: 'Maximum course audit-log event rows to return when visible. Defaults to 25.',
        },
        max_history: {
          type: 'number',
          description: 'Maximum recent-history rows to return after course filtering. Defaults to 25.',
        },
        max_conversation: {
          type: 'number',
          description: 'Maximum unread course conversation rows to return/inspect. Defaults to 20.',
        },
      },
    },
  },
  {
    name: 'get_course_analytics_context',
    description: 'Fetch bounded read-only course and current-user analytics visibility for a course. Analytics is cross-check evidence only and may be blocked under a student PAT.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        max_assignment: {
          type: 'number',
          description: 'Maximum course/user analytics assignment rows to return. Defaults to 80.',
        },
        max_student_summary: {
          type: 'number',
          description: 'Maximum student summary rows to return after current-user filtering. Defaults to 10.',
        },
        max_participation: {
          type: 'number',
          description: 'Maximum participation rows from current-user analytics activity to return. Defaults to 80.',
        },
      },
    },
  },
  {
    name: 'get_course_material_context',
    description: 'Build a compact coursework material graph for one course: readings, attached files, source surfaces, deadlines, submission types, reply signals, group-work signals, modules, and queue/calendar cross-checks.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        start_date: {
          type: 'string',
          description: 'YYYY-MM-DD window start for queue/calendar reads. Defaults to 14 days ago.',
        },
        end_date: {
          type: 'string',
          description: 'YYYY-MM-DD window end for queue/calendar reads. Defaults to 45 days from now.',
        },
        include_page_body: {
          type: 'boolean',
          description: 'When true, fetch wiki page bodies and include compact reading/link evidence. Defaults to true.',
        },
        max_item: {
          type: 'number',
          description: 'Maximum material rows returned per surface. Defaults to 150.',
        },
        extract_reading: {
          type: 'boolean',
          description: 'When true, download and extract a bounded set of Canvas file reading sources for the reading_index.',
        },
        extract_material_id: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional material_id values to prioritize for extraction, for example assignment:<id>. All reading sources still appear in the index.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum Canvas file sources to extract when extract_reading is true. Defaults to 8.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum extracted characters per reading source. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'get_course_syllabus_context',
    description: 'Fetch bounded read-only course syllabus context: syllabus body text, embedded links/files, requirement signals, term/section hints, and optional extraction for syllabus-linked Canvas files.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract text from bounded Canvas files linked from the syllabus.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum syllabus-linked Canvas files to extract. Defaults to 4.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum syllabus body/extracted characters to return per field. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'get_course_search_context',
    description: 'Search Canvas course content with the official Smart Search API when available, across pages, assignments, announcements, and discussion topics. This beta endpoint may be disabled by Canvas; blocked/absent status is returned as evidence.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        query: {
          type: 'array',
          items: { type: 'string' },
          description: 'Search query strings. Defaults to a small coursework-oriented set: reading, quiz, assignment, deadline, group.',
        },
        filter: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional Smart Search filters. Supported by Canvas: pages, assignments, announcements, discussion_topics.',
        },
        include_module: {
          type: 'boolean',
          description: 'When true, request module membership for each search result. Defaults to true.',
        },
        include_status: {
          type: 'boolean',
          description: 'When true, request status/due-date metadata for each search result. Defaults to true.',
        },
        include_recipient_search: {
          type: 'boolean',
          description: 'When true, also probe the official Search API for messageable course/section/group context scoped to this course. Defaults to true.',
        },
        include_public_course_search: {
          type: 'boolean',
          description: 'When true, also probe the public course search index with the current course code/name. Defaults to true.',
        },
        max_query: {
          type: 'number',
          description: 'Maximum query strings to run. Defaults to 5.',
        },
        max_result: {
          type: 'number',
          description: 'Maximum result rows to return per query. Defaults to 20.',
        },
        max_recipient: {
          type: 'number',
          description: 'Maximum Search API recipient/context rows to return. Defaults to 20.',
        },
        max_public_course: {
          type: 'number',
          description: 'Maximum public course search rows to return. Defaults to 10.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped content/snippet characters per result. Defaults to 500.',
        },
      },
    },
  },
  {
    name: 'get_course_media_context',
    description: 'Fetch bounded read-only Canvas media attachment context for a course and current-user own groups, including audio/video metadata and links when Canvas exposes them.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_group_media: {
          type: 'boolean',
          description: 'When true, include media attachments from current-user own groups in the course. Defaults to true.',
        },
        include_kaltura_config: {
          type: 'boolean',
          description: 'When true, include read-only Kaltura plugin config status. Defaults to true.',
        },
        max_media: {
          type: 'number',
          description: 'Maximum course media attachment rows to return. Defaults to 80.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum current-user own groups to inspect for media attachments. Defaults to 10.',
        },
        max_group_media: {
          type: 'number',
          description: 'Maximum media attachment rows per group to return. Defaults to 40.',
        },
      },
    },
  },
  {
    name: 'get_course_conference_context',
    description: 'Fetch bounded read-only Canvas Conferences context for current user, course, and current-user own groups. Useful for class meeting or recording context; does not start, join, or manage conferences.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_user_conference: {
          type: 'boolean',
          description: 'When true, include current-user conferences across courses/groups. Defaults to true.',
        },
        include_group_conference: {
          type: 'boolean',
          description: 'When true, include conferences from current-user own groups in the course. Defaults to true.',
        },
        state: {
          type: 'string',
          enum: ['live'],
          description: 'Optional Conferences API state filter. Canvas currently documents live.',
        },
        max_conference: {
          type: 'number',
          description: 'Maximum course/current-user conference rows to return. Defaults to 80.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum current-user own groups to inspect for conferences. Defaults to 10.',
        },
        max_group_conference: {
          type: 'number',
          description: 'Maximum conference rows per group to return. Defaults to 40.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped conference description characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_export_context',
    description: 'Fetch bounded read-only Canvas content/ePub export context, optional Course Report status, and existing Progress rows exposed by export progress_url values. Does not create/cancel export or report jobs.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_user_export: {
          type: 'boolean',
          description: 'When true, include current-user content exports. Defaults to true.',
        },
        include_group_export: {
          type: 'boolean',
          description: 'When true, include content exports from current-user own groups in the course. Defaults to true.',
        },
        include_epub_export: {
          type: 'boolean',
          description: 'When true, include current-user course ePub export metadata. Defaults to true.',
        },
        include_progress: {
          type: 'boolean',
          description: 'When true, resolve existing Progress rows from export progress_url values. Defaults to true.',
        },
        course_report_type: {
          type: 'string',
          description: 'Optional Course Reports report_type to read last report status. The tool never starts reports.',
        },
        course_report_id: {
          type: 'string',
          description: 'Optional Course Reports report ID to read a specific report status when course_report_type is also provided.',
        },
        content_migration_id: {
          type: 'string',
          description: 'Optional Content Migration ID to inspect; defaults to the first visible course migration when present.',
        },
        migration_issue_id: {
          type: 'string',
          description: 'Optional Content Migration issue ID to inspect when a migration is visible.',
        },
        max_export: {
          type: 'number',
          description: 'Maximum course/user export rows to return. Defaults to 40.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum current-user own groups to inspect for exports. Defaults to 10.',
        },
        max_group_export: {
          type: 'number',
          description: 'Maximum content export rows per group to return. Defaults to 20.',
        },
        max_epub_export: {
          type: 'number',
          description: 'Maximum ePub export course rows to return. Defaults to 80.',
        },
        max_migration: {
          type: 'number',
          description: 'Maximum content migration rows to return. Defaults to 20.',
        },
        max_migration_issue: {
          type: 'number',
          description: 'Maximum migration issue rows to return for the selected migration. Defaults to 20.',
        },
        max_progress: {
          type: 'number',
          description: 'Maximum export progress_url rows to resolve. Defaults to 20.',
        },
      },
    },
  },
  {
    name: 'get_canvas_progress_context',
    description: 'Fetch read-only Canvas async Progress status by progress_id/progress_url or LTI progress id. Does not cancel Progress jobs.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: 'Canvas course ID for LTI progress paths. Optional for /api/v1/progress/:id.' },
        progress_id: {
          type: 'string',
          description: 'Canvas Progress ID for /api/v1/progress/:id.',
        },
        progress_url: {
          type: 'string',
          description: 'Progress URL from Canvas metadata, for example a content export progress_url.',
        },
        lti_progress_id: {
          type: 'string',
          description: 'LTI Progress ID for /api/lti/courses/:course_id/progress/:id.',
        },
      },
    },
  },
  {
    name: 'get_course_pacing_context',
    description: 'Fetch bounded read-only course pacing context: course blackout dates and optional Course Pace details when a course_pace_id is known. Does not create, update, or delete pacing records.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        course_pace_id: {
          type: 'string',
          description: 'Optional Course Pace ID. When omitted, only blackout dates are read and course pace detail is skipped.',
        },
        max_blackout_date: {
          type: 'number',
          description: 'Maximum blackout date rows to return. Defaults to 80.',
        },
        max_module: {
          type: 'number',
          description: 'Maximum Course Pace module rows to return when course_pace_id is provided. Defaults to 80.',
        },
        max_item: {
          type: 'number',
          description: 'Maximum Course Pace item rows to return when course_pace_id is provided. Defaults to 200.',
        },
      },
    },
  },
  {
    name: 'get_course_poll_context',
    description: 'Fetch bounded read-only Canvas Polls context for current-user polls plus opened/closed poll sessions visible to the current user. Does not create polls or submit poll choices.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        max_poll: {
          type: 'number',
          description: 'Maximum poll rows to return. Defaults to 80.',
        },
        max_session: {
          type: 'number',
          description: 'Maximum opened/closed poll session rows to return. Defaults to 80 each.',
        },
        max_submission: {
          type: 'number',
          description: 'Maximum visible poll submission rows per session to return when Canvas exposes them. Defaults to 20.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped poll question/description characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_user_notification_context',
    description: 'Fetch bounded read-only current-user communication channel and notification preference context. Does not create channels or update notification preferences.',
    inputSchema: {
      type: 'object',
      properties: {
        max_channel: {
          type: 'number',
          description: 'Maximum communication channel rows to return and inspect. Defaults to 20.',
        },
        max_preference: {
          type: 'number',
          description: 'Maximum notification preference rows per channel to return. Defaults to 120.',
        },
        max_category: {
          type: 'number',
          description: 'Maximum notification preference category rows per channel to return. Defaults to 80.',
        },
      },
    },
  },
  {
    name: 'get_user_comm_message_context',
    description: 'Fetch bounded read-only Canvas notification message metadata for the current user. Raw message bodies are not returned; only short deadline-like excerpts are included.',
    inputSchema: {
      type: 'object',
      properties: {
        start_time: {
          type: 'string',
          description: 'ISO datetime window start. Defaults to 30 days ago.',
        },
        end_time: {
          type: 'string',
          description: 'ISO datetime window end. Defaults to now.',
        },
        max_message: {
          type: 'number',
          description: 'Maximum CommMessage rows to return. Defaults to 40.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum sanitized subject/excerpt characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_account_context',
    description: 'Fetch read-only account-scoped context for the selected course, including active global account notifications, account domain lookup rows, admin-role visibility, API token scope metadata, and safe authentication provider metadata visible to the current user.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        account_id: {
          type: 'string',
          description: 'Optional Canvas account ID. Defaults to course.root_account_id, then course.account_id.',
        },
        account_notification_id: {
          type: 'string',
          description: 'Optional account notification ID for the detail endpoint. Defaults to the first visible notification when present.',
        },
        account_name: {
          type: 'string',
          description: 'Optional campus/account name query for the official account domain lookup endpoint.',
        },
        account_domain: {
          type: 'string',
          description: 'Optional account domain query. Defaults to the configured Canvas host.',
        },
        include_domain_lookup: {
          type: 'boolean',
          description: 'When false, skip the account domain lookup endpoint. Defaults to true.',
        },
        include_api_scope: {
          type: 'boolean',
          description: 'When false, skip the API token scope catalog endpoint. Defaults to true.',
        },
        include_auth_provider: {
          type: 'boolean',
          description: 'When false, skip authentication provider metadata endpoints. Defaults to true.',
        },
        include_account_surface: {
          type: 'boolean',
          description: 'When false, skip account metadata, permission, help-link, sub-account, and report-list endpoints. Defaults to true.',
        },
        include_admin: {
          type: 'boolean',
          description: 'When false, skip account admin list and current-user admin-role endpoints. Defaults to true.',
        },
        include_login: {
          type: 'boolean',
          description: 'When false, skip account login visibility endpoint. Defaults to true.',
        },
        include_authentication_event: {
          type: 'boolean',
          description: 'When false, skip account authentication-event audit visibility. Defaults to true.',
        },
        include_sis_import: {
          type: 'boolean',
          description: 'When false, skip SIS import and SIS import error visibility. Defaults to true.',
        },
        include_temporary_enrollment_pairing: {
          type: 'boolean',
          description: 'When false, skip temporary enrollment pairing list/detail/new visibility. Defaults to true.',
        },
        include_deleted_admin: {
          type: 'boolean',
          description: 'When true, ask Canvas to include deleted account admins when the caller has permission. Defaults to false.',
        },
        temporary_enrollment_pairing_id: {
          type: 'string',
          description: 'Optional temporary enrollment pairing ID for the detail endpoint. Defaults to the first visible pairing when present.',
        },
        sis_import_id: {
          type: 'string',
          description: 'Optional SIS import ID for detail and import-specific error endpoints. Defaults to the first visible import when present.',
        },
        auth_provider_id: {
          type: 'string',
          description: 'Optional authentication provider ID for the detail endpoint. Defaults to the first visible provider when present.',
        },
        role_id: {
          type: 'string',
          description: 'Optional Canvas role ID for the role detail endpoint. Defaults to the first visible role when present.',
        },
        role_permission: {
          type: 'string',
          description: 'Optional Canvas permission key for static permission help text. Defaults to read_reports.',
        },
        account_permission: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional account permission keys to check. Defaults to a small Canvas-check-oriented set.',
        },
        max_domain: {
          type: 'number',
          description: 'Maximum account domain lookup rows to return. Canvas returns up to 5; defaults to 5.',
        },
        max_api_scope: {
          type: 'number',
          description: 'Maximum API token scope rows to return. Defaults to 80.',
        },
        max_auth_provider: {
          type: 'number',
          description: 'Maximum authentication provider rows to return. Defaults to 20.',
        },
        max_sub_account: {
          type: 'number',
          description: 'Maximum sub-account rows to return. Defaults to 20.',
        },
        max_account_report: {
          type: 'number',
          description: 'Maximum available account report rows to return. Defaults to 20.',
        },
        max_role: {
          type: 'number',
          description: 'Maximum account role rows to return. Defaults to 40.',
        },
        max_role_permission: {
          type: 'number',
          description: 'Maximum assignable permission metadata rows to return. Defaults to 80.',
        },
        max_admin: {
          type: 'number',
          description: 'Maximum account admin rows to return. Defaults to 80.',
        },
        max_login: {
          type: 'number',
          description: 'Maximum sanitized account login rows to return. Defaults to 80.',
        },
        max_authentication_event: {
          type: 'number',
          description: 'Maximum account authentication-event audit rows to return. Defaults to 25.',
        },
        max_sis_import: {
          type: 'number',
          description: 'Maximum SIS import rows to return. Defaults to 20.',
        },
        max_sis_import_error: {
          type: 'number',
          description: 'Maximum sanitized SIS import error rows to return. Defaults to 20.',
        },
        max_temporary_enrollment_pairing: {
          type: 'number',
          description: 'Maximum temporary enrollment pairing rows to return. Defaults to 20.',
        },
        start_time: {
          type: 'string',
          description: 'ISO/date window start for authentication audit events and SIS import created_since. Defaults to 30 days ago.',
        },
        end_time: {
          type: 'string',
          description: 'ISO/date window end for authentication audit events and SIS import created_before. Defaults to today.',
        },
        include_past: {
          type: 'boolean',
          description: 'When true, include past/dismissed global notifications if Canvas permits it.',
        },
        show_is_closed: {
          type: 'boolean',
          description: 'When true, request per-notification closed/read state when Canvas exposes it. Defaults to true.',
        },
        max_notification: {
          type: 'number',
          description: 'Maximum account notification rows to return. Defaults to 40.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped notification message characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_brand_context',
    description: 'Fetch read-only Canvas Brand Config variables for the root domain, selected course account, and selected course when Canvas permits them.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        account_id: {
          type: 'string',
          description: 'Optional Canvas account ID. Defaults to course.root_account_id, then course.account_id.',
        },
        max_variable: {
          type: 'number',
          description: 'Maximum brand variable keys to return per context. Defaults to 80.',
        },
      },
    },
  },
  {
    name: 'get_course_account_calendar_context',
    description: 'Fetch read-only Account Calendar visibility for the selected course account and current user.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        account_id: {
          type: 'string',
          description: 'Optional Canvas account ID. Defaults to course.root_account_id, then course.account_id.',
        },
        account_calendar_id: {
          type: 'string',
          description: 'Optional account calendar ID for detail. Defaults to the selected course account ID.',
        },
        search_term: {
          type: 'string',
          description: 'Optional search term for visible account calendars.',
        },
        max_calendar: {
          type: 'number',
          description: 'Maximum account calendar rows to return. Defaults to 40.',
        },
      },
    },
  },
  {
    name: 'get_course_blueprint_context',
    description: 'Fetch read-only Blueprint Course/subscription/import context for the selected course when Canvas permits it.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        blueprint_template_id: {
          type: 'string',
          description: 'Optional blueprint template ID. Defaults to Canvas default template.',
        },
        blueprint_subscription_id: {
          type: 'string',
          description: 'Optional blueprint subscription ID. Defaults to Canvas default subscription for import history.',
        },
        blueprint_migration_id: {
          type: 'string',
          description: 'Optional blueprint migration/import ID for detail endpoints.',
        },
        max_blueprint: {
          type: 'number',
          description: 'Maximum blueprint rows to return per list. Defaults to 20.',
        },
      },
    },
  },
  {
    name: 'get_course_grading_period_context',
    description: 'Fetch read-only account/course grading-period visibility for the selected course, including course grading-period detail when Canvas exposes an ID.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        account_id: {
          type: 'string',
          description: 'Optional Canvas account ID. Defaults to course.root_account_id, then course.account_id.',
        },
        grading_period_id: {
          type: 'string',
          description: 'Optional course grading period ID for detail. Defaults to the first visible course grading period.',
        },
        max_grading_period: {
          type: 'number',
          description: 'Maximum grading-period rows to return per list. Defaults to 40.',
        },
      },
    },
  },
  {
    name: 'get_course_feature_context',
    description: 'Fetch bounded read-only Canvas late-policy, CSP setting, and feature-flag context for a course/current user. Does not set feature flags, change late policy, or mutate CSP domains.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        account_id: {
          type: 'string',
          description: 'Optional Canvas account ID for account CSP settings. Defaults to course.root_account_id, then course.account_id.',
        },
        max_feature: {
          type: 'number',
          description: 'Maximum course/user feature rows to return. Defaults to 120 each.',
        },
        max_enabled_feature: {
          type: 'number',
          description: 'Maximum course/user enabled feature names to return. Defaults to 120 each.',
        },
        max_environment_feature: {
          type: 'number',
          description: 'Maximum environment feature keys to return. Defaults to 160.',
        },
        max_csp_domain: {
          type: 'number',
          description: 'Maximum CSP allowed-domain/tool rows to return per setting. Defaults to 80.',
        },
      },
    },
  },
  {
    name: 'get_course_module_context',
    description: 'Fetch bounded course module context: module state, prerequisites, sequential progress, completion requirements, module items with content details, embedded links/files, requirement tags, and reading/reply/deadline/device/group/submission signals.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_student_progress: {
          type: 'boolean',
          description: 'When true, request student_id=self so Canvas includes current-user module state/progress when permitted. Defaults to true.',
        },
        include_item_detail: {
          type: 'boolean',
          description: 'When true, fetch module items separately for modules where inline items are missing. Defaults to true.',
        },
        include_override: {
          type: 'boolean',
          description: 'When true, read module assignment overrides for returned modules when Canvas permits it. Defaults to true.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract bounded text from Canvas file module items.',
        },
        max_module: {
          type: 'number',
          description: 'Maximum module rows to return. Defaults to 80.',
        },
        max_item: {
          type: 'number',
          description: 'Maximum module item rows to return. Defaults to 250.',
        },
        max_override: {
          type: 'number',
          description: 'Maximum module assignment override rows to return across modules. Defaults to 80.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum module-linked files to extract when extract_file is true. Defaults to 6.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped text/extracted characters per item/file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'list_module',
    description: 'List all modules in the course with their items (titles, types, ids, urls).',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
      },
    },
  },
  {
    name: 'get_module_item',
    description: 'Fetch a single module item by id (page body, assignment, quiz, file, external url, etc).',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        module_id: { type: 'string', description: 'Module id' },
        item_id: { type: 'string', description: 'Module item id' },
      },
      required: ['module_id', 'item_id'],
    },
  },
  {
    name: 'get_module_item_context',
    description: 'Fetch a module item and resolve its Canvas target when possible: assignment, page, file, discussion, quiz, or external/tool link. Keeps external/LTI targets as links only.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        module_id: {
          type: 'string',
          description: 'Canvas module id. Optional when item_id can be read through /modules/items/:item_id.',
        },
        item_id: { type: 'string', description: 'Canvas module item id' },
        extract_file: {
          type: 'boolean',
          description: 'When true and the target is a Canvas file or assignment with prompt/submission files, extract bounded text/links.',
        },
        include_assignment_context: {
          type: 'boolean',
          description: 'When true and the target is an assignment, return get_assignment_context instead of plain assignment metadata.',
        },
        include_discussion_context: {
          type: 'boolean',
          description: 'When true and the target is a discussion, return get_discussion_context instead of plain topic metadata.',
        },
        include_sequence: {
          type: 'boolean',
          description: 'When true, read Canvas module_item_sequence for this module item to expose previous/current/next course sequence context. Defaults to true.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum extracted characters for file/assignment/discussion body snippets. Defaults to 1200.',
        },
      },
      required: ['item_id'],
    },
  },
  {
    name: 'get_course_external_tool_context',
    description: 'Fetch bounded read-only external tool/LTI context for a course: installed course/parent tools when visible, external-tool tabs, external-tool module items, optional assignment launch metadata, and optional sessionless launch URL checks. This does not fetch third-party content or bypass LTI permissions.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: {
          type: 'string',
          description: 'Optional assignment ID for an explicit assessment launch URL status check when include_sessionless_launch is true.',
        },
        include_parent: {
          type: 'boolean',
          description: 'When true, include parent-account tools visible through the course external tools endpoint. Defaults to true.',
        },
        include_tool_detail: {
          type: 'boolean',
          description: 'When true, fetch bounded /external_tools/:id details for visible tools. Defaults to true.',
        },
        include_sessionless_launch: {
          type: 'boolean',
          description: 'When true, call Canvas sessionless_launch GET endpoints for bounded module/assignment launch URL status checks. Defaults to false.',
        },
        max_tool: {
          type: 'number',
          description: 'Maximum external tool rows/details to return. Defaults to 80.',
        },
        max_module_item: {
          type: 'number',
          description: 'Maximum external-tool module items to return. Defaults to 80.',
        },
        max_tab: {
          type: 'number',
          description: 'Maximum external tool navigation tabs to return. Defaults to 50.',
        },
        max_launch: {
          type: 'number',
          description: 'Maximum sessionless launch checks when include_sessionless_launch is true. Defaults to 10.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped external tool description characters per row. Defaults to 600.',
        },
      },
    },
  },
  {
    name: 'get_course_quiz_lti_context',
    description: 'Fetch read-only New Quiz and LTI line-item visibility for one course/assignment. Use this to explain quiz/external-tool ambiguity without treating blocked internals as submission proof.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: {
          type: 'string',
          description: 'Optional Canvas assignment id associated with a New Quiz or external-tool item.',
        },
        include_item: {
          type: 'boolean',
          description: 'When true, try New Quiz item reads for the selected assignment id. Defaults to true.',
        },
        max_quiz: {
          type: 'number',
          description: 'Maximum New Quiz rows to return from the catalog. Defaults to 30.',
        },
        max_item: {
          type: 'number',
          description: 'Maximum New Quiz item rows to return. Defaults to 50.',
        },
        max_line_item: {
          type: 'number',
          description: 'Maximum LTI line item rows to return. Defaults to 50.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped instruction/description characters per row. Defaults to 500.',
        },
      },
    },
  },
  {
    name: 'list_assignment',
    description: 'List all assignments in the course (name, due_at, points_possible, description). Optionally asks Canvas to include the current user submission object when Canvas honors include[]=submission.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_submission: {
          type: 'boolean',
          description: 'When true, request include[]=submission. Some Canvas contexts omit it; use list_my_submission for the authoritative per-user state.',
        },
      },
    },
  },
  {
    name: 'get_assignment',
    description: 'Fetch a single assignment with its full description/instructions HTML.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: { type: 'string', description: 'Canvas assignment id' },
      },
      required: ['assignment_id'],
    },
  },
  {
    name: 'get_assignment_context',
    description: 'Fetch one assignment plus the current user submission state, linked Canvas file ids, optional attachment text extraction, and discovered nested links. This is the preferred read for owed-work checks.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: { type: 'string', description: 'Canvas assignment id' },
        include_history: {
          type: 'boolean',
          description: 'When true, include submission_history, rubric_assessment, and comments.',
        },
        extract_attachment: {
          type: 'boolean',
          description: 'When true, download linked Canvas files and extract text when possible.',
        },
        extract_submission_attachment: {
          type: 'boolean',
          description: 'When true, download current-user submitted file attachments and extract bounded text/links when possible.',
        },
        max_submission_attachment: {
          type: 'number',
          description: 'Maximum submitted file attachments to inspect. Defaults to 4.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum extracted characters per attachment. Defaults to 4000.',
        },
      },
      required: ['assignment_id'],
    },
  },
  {
    name: 'get_peer_review_context',
    description: 'Fetch read-only peer-review context for one assignment: all readable peer review rows, current-user submission peer reviews when resolvable, assigned-to-me and reviewing-my-submission counts, and included comment/user evidence when Canvas permits it.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: { type: 'string', description: 'Canvas assignment id' },
        submission_id: {
          type: 'string',
          description: 'Optional Canvas submission id. When omitted, the MCP tries to resolve the current-user submission id through submissions/self.',
        },
        include_user: {
          type: 'boolean',
          description: 'When true, ask Canvas to include user objects on peer review rows. Defaults to true.',
        },
        include_submission_comment: {
          type: 'boolean',
          description: 'When true, ask Canvas to include submission comments on peer review rows. Defaults to true.',
        },
        max_comment_chars: {
          type: 'number',
          description: 'Maximum stripped characters per included peer-review submission comment. Defaults to 240.',
        },
      },
      required: ['assignment_id'],
    },
  },
  {
    name: 'list_announcement',
    description: 'List all announcements posted to the course.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
      },
    },
  },
  {
    name: 'get_course_announcement_context',
    description: 'Fetch bounded course announcement context: announcements over a date window, embedded links/files, requirement tags, reading/reply/deadline/device/group/submission signals, and optional linked-file extraction.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        start_date: {
          type: 'string',
          description: 'YYYY-MM-DD or ISO date window start. Defaults to 30 days ago.',
        },
        end_date: {
          type: 'string',
          description: 'YYYY-MM-DD or ISO date window end. Defaults to 60 days from now.',
        },
        active_only: {
          type: 'boolean',
          description: 'When true, ask Canvas for active announcements only.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract bounded text from Canvas files linked inside announcement bodies.',
        },
        max_announcement: {
          type: 'number',
          description: 'Maximum announcement rows to return. Defaults to 80.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum linked Canvas files to extract when extract_file is true. Defaults to 6.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped announcement/extracted file characters to return per row/file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'get_course_feed_context',
    description: 'Fetch read-only Announcement External Feed context for the course and current-user own groups, showing RSS/Atom feeds that can auto-create announcements.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_group_feed: {
          type: 'boolean',
          description: 'When true, also list external feeds for current-user own groups in this course. Defaults to true.',
        },
        max_feed: {
          type: 'number',
          description: 'Maximum external feed rows to return per course/group. Defaults to 40.',
        },
        max_group: {
          type: 'number',
          description: 'Maximum current-user own groups to inspect for external feeds. Defaults to 10.',
        },
      },
    },
  },
  {
    name: 'get_page',
    description: 'Fetch the body of a wiki page by url-slug. Note: pages may be disabled for some courses.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        page_url: { type: 'string', description: 'The url-slug of the page (not full URL)' },
      },
      required: ['page_url'],
    },
  },
  {
    name: 'get_course_page_context',
    description: 'Fetch a bounded read-only page/wiki context for a course: page index, front page when readable, selected page bodies, module placement, embedded links/files, requirement tags, and optional linked-file extraction.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        page_url: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional page URL slugs to fetch. When omitted, the tool fetches pages from the course page index and page module items.',
        },
        include_body: {
          type: 'boolean',
          description: 'When true, fetch each selected page body and include bounded body text plus requirement evidence. Defaults to true.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract bounded text from Canvas files linked inside selected page bodies.',
        },
        max_page: {
          type: 'number',
          description: 'Maximum page bodies to fetch/return. Defaults to 80.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum linked Canvas files to extract when extract_file is true. Defaults to 6.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum stripped body/extracted file characters to return per page/file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'list_file',
    description: 'List files in the course. Note: may return 403 if files area is restricted.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
      },
    },
  },
  {
    name: 'get_file',
    description: 'Fetch Canvas file metadata by file id. The returned url is usually the authenticated download URL.',
    inputSchema: {
      type: 'object',
      properties: {
        file_id: { type: 'string', description: 'Canvas file id' },
      },
      required: ['file_id'],
    },
  },
  {
    name: 'get_course_file_context',
    description: 'Build a bounded course file/folder context: root folder, all readable folders, course files with folder placement, usage-right keys, reading-like file types, and optional extraction for selected file IDs.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_folder_file: {
          type: 'boolean',
          description: 'When true, sample files directly from readable folders to verify folder/file linkage. Defaults to true.',
        },
        max_folder: {
          type: 'number',
          description: 'Maximum folder rows to return/probe. Defaults to 100.',
        },
        max_file: {
          type: 'number',
          description: 'Maximum course file rows to return. Defaults to 200.',
        },
        extract_file: {
          type: 'boolean',
          description: 'When true, extract text from a bounded set of reading-like Canvas files.',
        },
        extract_file_id: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional Canvas file IDs to prioritize for extraction.',
        },
        max_extract_file: {
          type: 'number',
          description: 'Maximum files to extract when extract_file is true. Defaults to 6.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum extracted characters per file. Defaults to 1200.',
        },
      },
    },
  },
  {
    name: 'extract_file_text',
    description: 'Download a Canvas file and extract text when possible. Supports text/html/JSON/CSV, DOCX via unzip, PDFs via pdftotext, and images via tesseract OCR when installed. Binary files return metadata plus an explicit unsupported note.',
    inputSchema: {
      type: 'object',
      properties: {
        file_id: { type: 'string', description: 'Canvas file id. Required unless download_url is provided.' },
        download_url: { type: 'string', description: 'Authenticated Canvas file url. Optional when file_id is provided.' },
        max_chars: { type: 'number', description: 'Maximum extracted characters to return. Defaults to 12000.' },
      },
    },
  },
  {
    name: 'list_my_submission',
    description: 'List the current user submission state for a course via /students/submissions?student_ids[]=self. Use this before classifying assignment work as missing or done.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_assignment: {
          type: 'boolean',
          description: 'When true, include each assignment object with the submission. Defaults to true.',
        },
        include_history: {
          type: 'boolean',
          description: 'When true, include submission_history and rubric_assessment.',
        },
      },
    },
  },
  {
    name: 'get_my_submission',
    description: 'Fetch the current user submission state for one assignment, including submitted_at, workflow_state, late, missing, grade/score, attachments, and optional history.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: { type: 'string', description: 'Canvas assignment id' },
        include_history: {
          type: 'boolean',
          description: 'When true, include submission_history and rubric_assessment.',
        },
      },
      required: ['assignment_id'],
    },
  },
  {
    name: 'get_submission_feedback_context',
    description: 'Fetch read-only feedback context for the current-user assignment submission: comments, rubric assessment keys, submission history summary, attachment count, and rubric/document annotation read-state endpoints when Canvas permits them.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        assignment_id: { type: 'string', description: 'Canvas assignment id' },
        max_comment_chars: {
          type: 'number',
          description: 'Maximum stripped characters per submission comment. Defaults to 300.',
        },
        max_history: {
          type: 'number',
          description: 'Maximum submission_history rows to compact. Defaults to 12.',
        },
      },
      required: ['assignment_id'],
    },
  },
  {
    name: 'list_discussion',
    description: 'List all discussion topics in the course.',
    inputSchema: {
      type: 'object',
      properties: { course_id: { type: 'string', description: COURSE_ID_DESC } },
    },
  },
  {
    name: 'get_discussion',
    description: 'Fetch a single discussion topic with its message body.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        discussion_id: { type: 'string', description: 'Discussion topic id' },
      },
      required: ['discussion_id'],
    },
  },
  {
    name: 'get_discussion_context',
    description: 'Fetch one discussion topic plus its entry counts and a deterministic requirement graph (initial post, peer reply, comment, feedback, attendance, form, lockdown). Counts come from Canvas fields and prompt keywords. is_met is null when completion cannot be seen.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        discussion_id: { type: 'string', description: 'Discussion topic id' },
        include_entry_body: {
          type: 'boolean',
          description: 'When true, include bounded stripped entry body text. Defaults to false.',
        },
        max_entry: {
          type: 'number',
          description: 'Maximum flattened discussion entries to return. Defaults to 50.',
        },
        max_chars: {
          type: 'number',
          description: 'Maximum characters per entry body when include_entry_body is true. Defaults to 400.',
        },
      },
      required: ['discussion_id'],
    },
  },
  {
    name: 'get_course_requirement_graph',
    description: 'Build a keyword-and-field requirement graph for one course: discussions, assignments, quizzes, announcements, and the first page of wiki pages. Rows cover replies, comments, feedback, attendance, forms, and Lockdown Browser flags. This server does not start Lockdown Browser or submit a form.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_view: {
          type: 'boolean',
          description: 'When true, load discussion views to compare the current user against countable requirements. Defaults to true.',
        },
        max_discussion_view: {
          type: 'number',
          description: 'Maximum discussion views to load. Defaults to 20.',
        },
      },
    },
  },
  {
    name: 'list_quiz',
    description: 'List all quizzes in the course (may 404 if disabled at course level).',
    inputSchema: {
      type: 'object',
      properties: { course_id: { type: 'string', description: COURSE_ID_DESC } },
    },
  },
  {
    name: 'get_quiz',
    description: 'Fetch a single quiz with metadata + description.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        quiz_id: { type: 'string', description: 'Quiz id' },
      },
      required: ['quiz_id'],
    },
  },
  {
    name: 'get_quiz_question',
    description: 'List all questions for a quiz (may 403 if you lack permission).',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        quiz_id: { type: 'string', description: 'Quiz id' },
      },
      required: ['quiz_id'],
    },
  },
  {
    name: 'get_quiz_context',
    description: 'Fetch Classic Quiz context in one read-only call: quiz metadata, questions/question groups when readable, current-user quiz submission, optional submission events, linked files/URLs, and assignment mapping.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        quiz_id: {
          type: 'string',
          description: 'Classic Quiz id. If omitted, the first visible Classic Quiz in the course is used when available.',
        },
        include_question: {
          type: 'boolean',
          description: 'When true, include quiz questions when Canvas permits it. Defaults to true.',
        },
        include_question_group: {
          type: 'boolean',
          description: 'When true, include Classic Quiz question groups when Canvas permits it. Defaults to true.',
        },
        question_group_id: {
          type: 'string',
          description: 'Optional Classic Quiz question group ID for the detail endpoint. Defaults to the first visible group when present.',
        },
        include_submission_event: {
          type: 'boolean',
          description: 'When true, try to read events for the current-user quiz submission when a submission id is available. Defaults to false.',
        },
        include_submission_time: {
          type: 'boolean',
          description: 'When true, try to read current timing data for the current-user quiz submission when a submission id is available. Defaults to true.',
        },
        include_submission_list: {
          type: 'boolean',
          description: 'When true, try to read visible quiz submission attempt rows. Submit-only users should only see their own allowed rows. Defaults to true.',
        },
        include_submission_question: {
          type: 'boolean',
          description: 'When true, try to read current-user quiz submission question status without returning raw answers. Defaults to true.',
        },
        include_report_statistic: {
          type: 'boolean',
          description: 'When true, try read-only quiz report/statistics metadata. Defaults to true.',
        },
        include_ip_filter: {
          type: 'boolean',
          description: 'When true, try read-only Classic Quiz IP filter metadata. Defaults to true.',
        },
        max_question: {
          type: 'number',
          description: 'Maximum quiz question rows to return. Defaults to 50.',
        },
      },
    },
  },
  {
    name: 'get_lockdown_quiz_access',
    description: 'Accessibility view of Lockdown Browser exams in one read-only call: quizzes Canvas flags require_lockdown_browser, question bank preview, and the current user submission with its score, all readable through the token API without the Respondus client.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        include_question_preview: {
          type: 'boolean',
          description: 'When true, probe the question bank for each Lockdown Browser quiz. Defaults to true.',
        },
        include_question_text: {
          type: 'boolean',
          description: 'When true, include question text in the preview. Defaults to true.',
        },
      },
    },
  },
  {
    name: 'get_lockdown_quiz_take',
    description: 'Open or resume the current-user attempt for a Lockdown Browser quiz and return its questions so the agent can prepare answers. Preview mode (default) touches nothing; with preview false an attempt is started through the web take flow, and a time-limited quiz starts its timer. The server never answers or submits.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        quiz_id: { type: 'string', description: 'Lockdown Browser quiz id' },
        preview: {
          type: 'boolean',
          description: 'When true, inspect without starting an attempt. Defaults to true.',
        },
        session_cookie: {
          type: 'string',
          description: 'Optional canvas_session cookie for the HTML take flow when the API refuses to start the attempt. Only sent when preview is false.',
        },
      },
      required: ['quiz_id'],
    },
  },
  {
    name: 'get_lockdown_quiz_launch',
    description: 'Launch the official Lockdown Browser client for a flagged quiz: resolves the rldb: launch URL via the session-authenticated launch page and opens it with the OS opener. Starting the client does not answer or submit.',
    inputSchema: {
      type: 'object',
      properties: {
        course_id: { type: 'string', description: COURSE_ID_DESC },
        quiz_id: { type: 'string', description: 'Lockdown Browser quiz id' },
        session_cookie: {
          type: 'string',
          description: 'Optional canvas_session cookie; resolved automatically from a signed-in browser when omitted.',
        },
      },
      required: ['quiz_id'],
    },
  },
  {
    name: 'extract_course',    description: 'Extract everything in the course (modules, pages, assignments, discussions, quizzes, announcements, files, plus categorized embeds — youtube/gsheets/gforms/etc). Single efficient call. Returns the same structure as the canvas-toolkit extractor.',    inputSchema: {
      type: 'object',
      properties: { course_id: { type: 'string', description: COURSE_ID_DESC } },
    },
  },
];

// ============================================================================
// Handlers
// ============================================================================

async function safe<T>(fn: () => Promise<T>): Promise<{ value: T | null; error: string | null }> {
  try { return { value: await fn(), error: null }; }
  catch (err) { return { value: null, error: err instanceof Error ? err.message : String(err) }; }
}

async function pool<T, R>(items: T[], fn: (i: T) => Promise<R>, n = 8): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (true) { const idx = i++; if (idx >= items.length) return; out[idx] = await fn(items[idx]); }
  }));
  return out;
}

const URL_RE = /(?:href|src|data-api-endpoint)=["']([^"']+)["']/gi;
const RAW_URL_RE = /\bhttps?:\/\/[^\s<>"')]+/gi;
const KIND_PATTERNS: Array<[string, RegExp]> = [
  ['youtube', /(?:youtube\.com|youtu\.be)/i],
  ['gsheets', /docs\.google\.com\/spreadsheets/i],
  ['gdocs', /docs\.google\.com\/document/i],
  ['gslides', /docs\.google\.com\/presentation/i],
  ['gforms', /(?:forms\.gle|docs\.google\.com\/forms)/i],
  ['gdrive', /drive\.google\.com/i],
  ['canvas-file', /instructure\.com.*\/files\//i],
  ['canvas-page', /instructure\.com.*\/(courses|pages)\//i],
  ['pdf', /\.pdf(?:\?|$)/i],
  ['image', /\.(?:png|jpe?g|gif|webp|svg)(?:\?|$)/i],
];
function classify(u: string): string { for (const [k, r] of KIND_PATTERNS) if (r.test(u)) return k; return 'external'; }
function extractEmbeds(html: string | null | undefined, source: { type: string; id?: any; title?: string }): any[] {
  if (!html) return [];
  const found = new Map<string, any>();
  const add = (raw: string) => {
    const url = raw.replace(/&amp;/g, '&').trim();
    if (!url || !/^https?:\/\//i.test(url) || found.has(url)) return;
    found.set(url, { kind: classify(url), url, source });
  };
  let m: RegExpExecArray | null;
  while ((m = URL_RE.exec(html))) add(m[1]);
  while ((m = RAW_URL_RE.exec(html))) add(m[0]);
  return [...found.values()];
}

function extractFileId(html: string | null | undefined): string[] {
  if (!html) return [];
  const found = new Set<string>();
  for (const match of String(html).matchAll(/\/files\/(\d+)/g)) found.add(match[1]);
  for (const match of String(html).matchAll(/data-api-endpoint=["'][^"']*\/files\/(\d+)["']/g)) found.add(match[1]);
  return [...found];
}

function normalizeCanvasLink(raw: string): { original_url: string; normalized_url: string; path: string; search: string; is_canvas_url: boolean; external_host: string | null } {
  const original = String(raw ?? '').trim().replace(/&amp;/g, '&');
  if (!original) throw new Error('resolve_canvas_link url is required');
  const base = new URL(BASE_URL);
  if (/^https?:\/\//i.test(original)) {
    const url = new URL(original);
    const isCanvasUrl = url.host === base.host;
    return {
      original_url: original,
      normalized_url: url.toString(),
      path: url.pathname,
      search: url.search,
      is_canvas_url: isCanvasUrl,
      external_host: isCanvasUrl ? null : url.host,
    };
  }
  const url = new URL(original.startsWith('/') ? original : `/${original}`, base);
  return {
    original_url: original,
    normalized_url: url.toString(),
    path: url.pathname,
    search: url.search,
    is_canvas_url: true,
    external_host: null,
  };
}

function submissionState(submission: any): Record<string, unknown> {
  const submitted = !!submission && (
    submission.workflow_state === 'submitted' ||
    submission.workflow_state === 'graded' ||
    !!submission.submitted_at
  );
  return {
    submitted,
    graded: submission?.workflow_state === 'graded' || submission?.grade != null || submission?.score != null,
    missing: !!submission?.missing,
    late: !!submission?.late,
    workflow_state: submission?.workflow_state ?? null,
    submitted_at: submission?.submitted_at ?? null,
    grade: submission?.grade ?? null,
    score: submission?.score ?? null,
    attachment_count: submission?.attachments?.length ?? 0,
  };
}

function isoDateKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function dateOffset(date: Date, day: number): string {
  const copy = new Date(date);
  copy.setUTCDate(copy.getUTCDate() + day);
  return isoDateKey(copy);
}

function keySample(value: unknown): string[] {
  const row = Array.isArray(value) ? value[0] : value;
  if (!row || typeof row !== 'object') return [];
  const sensitiveKey = new Set(['token', 'token_hint', 'visible_token']);
  return Object.keys(row).filter((key) => !sensitiveKey.has(key)).slice(0, 16);
}

function rowCount(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') {
    const row = value as any;
    for (const key of ['results', 'assessments', 'members', 'conferences', 'courses', 'events', 'polls', 'poll_choices', 'poll_sessions', 'quiz_groups', 'notification_preferences', 'categories', 'quiz_submissions', 'enrollment_terms', 'account_calendars', 'grading_period_set', 'grading_period_sets', 'grading_periods']) {
      if (Array.isArray(row?.[key])) return row[key].length;
    }
    return 1;
  }
  return 0;
}

function endpointStatus(error: string | null): 'ok' | 'blocked_or_absent' | 'error' {
  if (!error) return 'ok';
  return /Canvas (?:401|403|404)\b/i.test(error) || /does not support viewing metadata/i.test(error)
    ? 'blocked_or_absent'
    : 'error';
}

function limitRow<T>(value: T[], cap: number): T[] {
  return value.slice(0, Math.max(0, cap));
}

function compactPlannerItem(row: any): Record<string, unknown> {
  const plannable = row?.plannable ?? {};
  const submission = Array.isArray(row?.submissions) ? row.submissions[0] : null;
  const plannerOverride = row?.planner_override ?? null;
  return {
    plannable_id: row?.plannable_id ?? plannable?.id ?? null,
    plannable_type: row?.plannable_type ?? null,
    assignment_id: plannable?.assignment_id ?? (row?.plannable_type === 'assignment' ? row?.plannable_id : null),
    title: plannable?.title ?? plannable?.name ?? row?.title ?? null,
    date_at: row?.plannable_date ?? null,
    html_url: row?.html_url ?? plannable?.html_url ?? null,
    submission_state: submission?.workflow_state ?? null,
    is_new_activity: !!row?.new_activity,
    planner_override_id: plannerOverride?.id ?? null,
    is_marked_complete: !!plannerOverride?.marked_complete,
    is_dismissed: !!plannerOverride?.dismissed,
  };
}

function compactPlannerNote(row: any, maxChar = 600): Record<string, unknown> {
  return {
    planner_note_id: row?.id ?? null,
    title: row?.title ?? null,
    details_text: stripHtml(row?.details ?? row?.description ?? '').slice(0, maxChar),
    todo_date: row?.todo_date ?? null,
    course_id: row?.course_id ?? null,
    user_id: row?.user_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    linked_object_type: row?.linked_object_type ?? null,
    linked_object_id: row?.linked_object_id ?? null,
    linked_object_html_url: row?.linked_object_html_url ?? null,
    linked_object_url: row?.linked_object_url ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
  };
}

function compactPlannerOverride(row: any): Record<string, unknown> {
  return {
    planner_override_id: row?.id ?? null,
    plannable_type: row?.plannable_type ?? null,
    plannable_id: row?.plannable_id ?? null,
    assignment_id: row?.assignment_id ?? null,
    user_id: row?.user_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    is_marked_complete: !!row?.marked_complete,
    is_dismissed: !!row?.dismissed,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    deleted_at: row?.deleted_at ?? null,
  };
}

function compactTodoItem(row: any): Record<string, unknown> {
  const assignment = row?.assignment ?? {};
  return {
    type: row?.type ?? null,
    course_id: assignment?.course_id ?? row?.course_id ?? null,
    assignment_id: assignment?.id ?? row?.assignment_id ?? null,
    title: assignment?.name ?? row?.title ?? null,
    due_at: assignment?.due_at ?? null,
    html_url: row?.html_url ?? assignment?.html_url ?? null,
  };
}

function compactCourseDueAssignment(row: any): Record<string, unknown> {
  const allDate = Array.isArray(row?.all_dates) ? row.all_dates : [];
  const override = Array.isArray(row?.overrides) ? row.overrides : [];
  return {
    assignment_id: row?.id ?? null,
    title: row?.name ?? row?.title ?? null,
    due_at: row?.due_at ?? null,
    unlock_at: row?.unlock_at ?? null,
    lock_at: row?.lock_at ?? null,
    only_visible_to_overrides: !!row?.only_visible_to_overrides,
    has_overrides: !!row?.has_overrides || override.length > 0,
    all_date_count: allDate.length,
    all_date: limitRow(allDate.map((one: any) => ({
      id: one?.id ?? null,
      base: !!one?.base,
      title: one?.title ?? null,
      due_at: one?.due_at ?? null,
      unlock_at: one?.unlock_at ?? null,
      lock_at: one?.lock_at ?? null,
    })), 20),
    override_count: override.length,
    override: limitRow(override.map((one: any) => ({
      assignment_override_id: one?.id ?? null,
      title: one?.title ?? null,
      due_at: one?.due_at ?? null,
      unlock_at: one?.unlock_at ?? null,
      lock_at: one?.lock_at ?? null,
      is_student_override: !!one?.student_ids,
      is_group_override: !!one?.group_id,
      is_section_override: !!one?.course_section_id,
    })), 20),
    submission_type: Array.isArray(row?.submission_types) ? row.submission_types : [],
    html_url: row?.html_url ?? null,
    workflow_state: row?.workflow_state ?? null,
  };
}

function compactEffectiveDueDate(value: unknown, assignmentId: string[], userId: string | null): Record<string, unknown>[] {
  if (!value || typeof value !== 'object') return [];
  return assignmentId.map((id) => {
    const assignmentRow = (value as any)?.[id] ?? (value as any)?.[Number(id)];
    const userRow = userId ? (assignmentRow?.[userId] ?? assignmentRow?.[Number(userId)]) : null;
    return {
      assignment_id: id,
      user_id: userId,
      status: userRow ? 'ok' : 'not_returned_for_current_user',
      due_at: userRow?.due_at ?? null,
      unlock_at: userRow?.unlock_at ?? null,
      lock_at: userRow?.lock_at ?? null,
      grading_period_id: userRow?.grading_period_id ?? null,
      in_closed_grading_period: userRow?.in_closed_grading_period ?? null,
    };
  });
}

function compactCourseSetting(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    allow_student_discussion_topics: row?.allow_student_discussion_topics ?? null,
    allow_student_forum_attachments: row?.allow_student_forum_attachments ?? null,
    allow_student_discussion_editing: row?.allow_student_discussion_editing ?? null,
    allow_student_discussion_reporting: row?.allow_student_discussion_reporting ?? null,
    allow_student_anonymous_discussion_topics: row?.allow_student_anonymous_discussion_topics ?? null,
    lock_all_announcements: row?.lock_all_announcements ?? null,
    restrict_student_past_view: row?.restrict_student_past_view ?? null,
    restrict_student_future_view: row?.restrict_student_future_view ?? null,
    show_announcements_on_home_page: row?.show_announcements_on_home_page ?? null,
    home_page_announcement_limit: row?.home_page_announcement_limit ?? null,
    hide_final_grades: row?.hide_final_grades ?? null,
  };
}

function compactCoursePermission(row: any): Record<string, unknown> {
  if (!row || typeof row !== 'object') return {};
  return Object.fromEntries(Object.entries(row).filter(([key, value]) => (
    typeof value === 'boolean' ||
    key === 'read_grades' ||
    key === 'view_all_grades' ||
    key === 'manage_assignments' ||
    key === 'manage_grades' ||
    key === 'manage_files' ||
    key === 'read_as_admin'
  )));
}

function compactAssignmentLike(row: any): Record<string, unknown> {
  return {
    assignment_id: row?.id ?? row?.assignment_id ?? null,
    title: row?.name ?? row?.title ?? null,
    due_at: row?.due_at ?? row?.all_day_date ?? null,
    html_url: row?.html_url ?? null,
    workflow_state: row?.workflow_state ?? null,
  };
}

function compactCourseTerm(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    enrollment_term_id: row?.id ?? null,
    name: row?.name ?? null,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    workflow_state: row?.workflow_state ?? null,
  };
}

function compactEnrollmentTerm(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  const override = row?.overrides && typeof row.overrides === 'object' ? row.overrides : {};
  return {
    enrollment_term_id: row?.id ?? null,
    name: row?.name ?? null,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    workflow_state: row?.workflow_state ?? null,
    created_at: row?.created_at ?? null,
    grading_period_group_id: row?.grading_period_group_id ?? null,
    course_count: row?.course_count ?? null,
    has_override: Object.keys(override).length > 0,
    student_override: override.StudentEnrollment ? {
      start_at: override.StudentEnrollment?.start_at ?? null,
      end_at: override.StudentEnrollment?.end_at ?? null,
    } : null,
    teacher_override: override.TeacherEnrollment ? {
      start_at: override.TeacherEnrollment?.start_at ?? null,
      end_at: override.TeacherEnrollment?.end_at ?? null,
    } : null,
    key: keySample(row),
  };
}

function compactAccountNotification(row: any, maxChar = 600): Record<string, unknown> {
  const message = stripHtml(row?.message ?? '');
  return {
    account_notification_id: row?.id ?? null,
    subject: stripHtml(row?.subject ?? '').slice(0, maxChar),
    message_text: message.slice(0, maxChar),
    message_truncated: message.length > maxChar,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    icon: row?.icon ?? null,
    role_id: Array.isArray(row?.role_ids) ? row.role_ids : [],
    role: Array.isArray(row?.roles) ? row.roles : [],
    is_closed: row?.is_closed ?? row?.closed ?? null,
    author: row?.author ? {
      user_id: row.author?.id ?? null,
      name: row.author?.name ?? null,
    } : null,
    key: keySample(row),
  };
}

function compactAccountDomain(row: any): Record<string, unknown> {
  return {
    name: row?.name ?? null,
    domain: row?.domain ?? null,
    distance: row?.distance ?? null,
    authentication_provider: row?.authentication_provider ?? null,
    key: keySample(row),
  };
}

function compactAccount(row: any): Record<string, unknown> {
  return {
    account_id: row?.id ?? null,
    name: row?.name ?? null,
    workflow_state: row?.workflow_state ?? null,
    parent_account_id: row?.parent_account_id ?? null,
    root_account_id: row?.root_account_id ?? null,
    default_time_zone: row?.default_time_zone ?? null,
    course_count: row?.course_count ?? null,
    sub_account_count: row?.sub_account_count ?? null,
    key: keySample(row),
  };
}

function compactAccountSetting(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    setting_count: Object.keys(row).length,
    setting_key: Object.keys(row).sort(),
    key: keySample(value),
  };
}

function compactAccountPermission(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    permission_count: Object.keys(row).length,
    permission: Object.fromEntries(Object.entries(row).map(([key, permissionValue]) => [key, permissionValue])),
    key: keySample(value),
  };
}

function compactAccountHelpLink(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const linkValue = [
    ...(
      Array.isArray((row as any).custom_help_links)
        ? (row as any).custom_help_links
        : []
    ),
    ...(
      Array.isArray((row as any).default_help_links)
        ? (row as any).default_help_links
        : []
    ),
  ];
  return {
    help_link_name: (row as any).help_link_name ?? null,
    help_link_icon: (row as any).help_link_icon ?? null,
    help_link_count: linkValue.length,
    help_link: linkValue.map((one: any) => ({
      text: one?.text ?? one?.label ?? null,
      subtext: one?.subtext ?? null,
      url: one?.url ?? null,
      type: one?.type ?? null,
      is_available_to: one?.available_to ?? null,
      key: keySample(one),
    })),
    key: keySample(value),
  };
}

function compactAccountReport(row: any): Record<string, unknown> {
  const parameter = row?.parameters && typeof row.parameters === 'object'
    ? Object.keys(row.parameters).sort()
    : [];
  return {
    report: row?.report ?? row?.name ?? null,
    title: row?.title ?? null,
    description: stripHtml(row?.description ?? '').slice(0, 300) || null,
    parameter_key: parameter,
    last_run_at: row?.last_run_at ?? null,
    key: keySample(row),
  };
}

function compactTemporaryEnrollmentPairing(row: any): Record<string, unknown> {
  return {
    temporary_enrollment_pairing_id: row?.id ?? null,
    workflow_state: row?.workflow_state ?? null,
    ending_enrollment_state: row?.ending_enrollment_state ?? null,
    key: keySample(row),
  };
}

function compactApiScope(row: any): Record<string, unknown> {
  return {
    resource: row?.resource ?? null,
    resource_name: row?.resource_name ?? null,
    controller: row?.controller ?? null,
    action: row?.action ?? null,
    verb: row?.verb ?? null,
    scope: row?.scope ?? null,
    key: keySample(row),
  };
}

function compactRole(row: any): Record<string, unknown> {
  const permission = row?.permissions && typeof row.permissions === 'object'
    ? Object.keys(row.permissions).sort()
    : [];
  return {
    role_id: row?.id ?? null,
    label: row?.label ?? null,
    role: row?.role ?? null,
    base_role_type: row?.base_role_type ?? null,
    workflow_state: row?.workflow_state ?? null,
    account_id: row?.account_id ?? null,
    is_built_in: row?.is_built_in ?? null,
    permission_count: permission.length,
    permission_key: permission.slice(0, 80),
    key: keySample(row),
  };
}

function compactAccountAdmin(row: any): Record<string, unknown> {
  const user = row?.user && typeof row.user === 'object' ? row.user : null;
  return {
    admin_id: row?.id ?? null,
    role_id: row?.role_id ?? row?.role?.id ?? null,
    role: row?.role ?? row?.role_name ?? null,
    workflow_state: row?.workflow_state ?? null,
    user: user ? {
      user_id: user?.id ?? user?.user_id ?? null,
      name: user?.name ?? user?.display_name ?? null,
      sortable_name: user?.sortable_name ?? null,
      short_name: user?.short_name ?? null,
    } : null,
    key: keySample(row),
  };
}

function compactRolePermission(row: any): Record<string, unknown> {
  return {
    permission: row?.permission_name ?? row?.permission ?? row?.name ?? null,
    label: row?.label ?? null,
    group: row?.group ?? null,
    context_type: row?.context_type ?? null,
    available_to: row?.available_to ?? null,
    is_readonly: row?.readonly ?? null,
    key: keySample(row),
  };
}

function compactPermissionHelp(value: unknown, maxChar = 600): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    permission: (row as any).permission_name ?? (row as any).permission ?? null,
    label: (row as any).label ?? null,
    context_type: (row as any).context_type ?? null,
    help: stripHtml((row as any).help ?? (row as any).description ?? '').slice(0, maxChar) || null,
    consideration: stripHtml((row as any).considerations ?? '').slice(0, maxChar) || null,
    key: keySample(value),
  };
}

function compactLogin(row: any): Record<string, unknown> {
  const sensitiveKey = new Set(['unique_id', 'sis_user_id', 'integration_id']);
  return {
    login_id: row?.id ?? null,
    user_id: row?.user_id ?? null,
    account_id: row?.account_id ?? null,
    authentication_provider_id: row?.authentication_provider_id ?? null,
    authentication_provider_type: row?.authentication_provider_type ?? null,
    workflow_state: row?.workflow_state ?? null,
    declared_user_type: row?.declared_user_type ?? null,
    created_at: row?.created_at ?? null,
    is_unique_id_present: typeof row?.unique_id === 'string' ? row.unique_id.length > 0 : row?.unique_id != null,
    is_sis_user_id_present: typeof row?.sis_user_id === 'string' ? row.sis_user_id.length > 0 : row?.sis_user_id != null,
    is_integration_id_present: typeof row?.integration_id === 'string' ? row.integration_id.length > 0 : row?.integration_id != null,
    key: keySample(row).filter((key) => !sensitiveKey.has(key)),
  };
}

function compactAccessToken(row: any): Record<string, unknown> {
  const scope = Array.isArray(row?.scopes) ? row.scopes.map((one: any) => String(one)).filter(Boolean) : [];
  const sensitiveKey = new Set(['token', 'token_hint', 'visible_token']);
  return {
    access_token_id: row?.id ?? null,
    user_id: row?.user_id ?? null,
    purpose: row?.purpose ?? null,
    app_name: row?.app_name ?? null,
    workflow_state: row?.workflow_state ?? null,
    created_at: row?.created_at ?? null,
    expires_at: row?.expires_at ?? null,
    last_used_at: row?.last_used_at ?? null,
    real_user_id: row?.real_user_id ?? null,
    remember_access: row?.remember_access ?? null,
    can_manually_regenerate: row?.can_manually_regenerate ?? null,
    scope_count: scope.length,
    scope: scope.slice(0, 80),
    key: keySample(row).filter((key) => !sensitiveKey.has(key)),
  };
}

function authenticationEventList(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object' && Array.isArray((value as any).events)) return (value as any).events;
  return [];
}

function compactAuthenticationEvent(row: any): Record<string, unknown> {
  const link = row?.links && typeof row.links === 'object' ? row.links : {};
  const sensitiveKey = new Set([
    'hostname',
    'ip',
    'ip_address',
    'request_id',
    'session_id',
    'user_agent',
    'unique_id',
    'sis_user_id',
    'integration_id',
  ]);
  return {
    authentication_event_id: row?.id ?? null,
    event_type: row?.event_type ?? row?.type ?? null,
    created_at: row?.created_at ?? row?.createdAt ?? null,
    pseudonym_id: row?.pseudonym_id ?? row?.login_id ?? link.login ?? link.pseudonym ?? null,
    account_id: row?.account_id ?? link.account ?? null,
    user_id: row?.user_id ?? link.user ?? null,
    key: keySample(row).filter((key) => !sensitiveKey.has(key)),
  };
}

function compactSisImport(row: any): Record<string, unknown> {
  const data = row?.data && typeof row.data === 'object' ? row.data : {};
  const statistic = row?.statistics && typeof row.statistics === 'object' ? row.statistics : {};
  return {
    sis_import_id: row?.id ?? null,
    account_id: row?.account_id ?? null,
    user_id: row?.user_id ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    ended_at: row?.ended_at ?? null,
    workflow_state: row?.workflow_state ?? null,
    progress: row?.progress ?? null,
    batch_mode: row?.batch_mode ?? data?.batch_mode ?? null,
    diffing_data_set_identifier: row?.diffing_data_set_identifier ?? data?.diffing_data_set_identifier ?? null,
    import_type: row?.import_type ?? data?.import_type ?? null,
    error_count: row?.errors_attachment ? 1 : row?.error_count ?? statistic?.error_count ?? null,
    warning_count: row?.warning_count ?? statistic?.warning_count ?? null,
    has_error_attachment: Boolean(row?.errors_attachment),
    has_statistics: Object.keys(statistic).length > 0,
    key: keySample(row).filter((key) => key !== 'errors_attachment'),
  };
}

function sisImportErrorList(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object' && Array.isArray((value as any).errors)) return (value as any).errors;
  if (value && typeof value === 'object' && Array.isArray((value as any).sis_import_error)) return (value as any).sis_import_error;
  return [];
}

function compactSisImportError(row: any, maxChar = 400): Record<string, unknown> {
  const sensitiveKey = new Set(['row_info', 'raw_row', 'csv_row']);
  return {
    sis_import_id: row?.sis_import_id ?? row?.import_id ?? null,
    file: row?.file ?? row?.filename ?? null,
    row: row?.row ?? row?.row_number ?? row?.line ?? row?.line_number ?? null,
    field: row?.field ?? row?.column ?? null,
    message: stripHtml(row?.message ?? row?.error_message ?? row?.description ?? '').slice(0, maxChar) || null,
    workflow_state: row?.workflow_state ?? null,
    is_failure: row?.failure ?? row?.is_failure ?? null,
    key: keySample(row).filter((key) => !sensitiveKey.has(key)),
  };
}

function compactAuthProvider(row: any): Record<string, unknown> {
  const federatedAttribute = row?.federated_attributes && typeof row.federated_attributes === 'object'
    ? Object.keys(row.federated_attributes).sort()
    : [];
  return {
    auth_provider_id: row?.id ?? null,
    auth_type: row?.auth_type ?? null,
    position: row?.position ?? null,
    login_attribute: row?.login_attribute ?? null,
    identifier_format: row?.identifier_format ?? null,
    jit_provisioning: row?.jit_provisioning ?? null,
    mfa_required: row?.mfa_required ?? null,
    federated_attribute_key: federatedAttribute,
    key: keySample(row),
  };
}

function compactBrandVariable(value: unknown, maxVariable = 80): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const variableKey = Object.keys(row).sort().slice(0, maxVariable);
  const selectedKey = [
    'ic-brand-primary',
    'ic-brand-font-color-dark',
    'ic-brand-font-color-light',
    'ic-brand-global-nav-bgd',
    'ic-brand-global-nav-ic-icon-svg-fill',
    'ic-brand-global-nav-logo-bgd',
    'ic-brand-login-background',
    'ic-brand-login-logo',
    'ic-brand-watermark',
  ].filter((key) => Object.prototype.hasOwnProperty.call(row, key));
  return {
    variable_count: Object.keys(row).length,
    variable_key: variableKey,
    selected_variable: Object.fromEntries(selectedKey.map((key) => [key, row[key]])),
    key: keySample(value),
  };
}

function compactAccountCalendar(row: any): Record<string, unknown> {
  return {
    account_id: row?.id ?? row?.account_id ?? null,
    name: row?.name ?? null,
    parent_account_id: row?.parent_account_id ?? null,
    root_account_id: row?.root_account_id ?? null,
    visible: row?.visible ?? null,
    auto_subscribe: row?.auto_subscribe ?? null,
    sub_account_count: row?.sub_account_count ?? null,
    key: keySample(row),
  };
}

function compactBlueprintTemplate(row: any): Record<string, unknown> {
  return {
    blueprint_template_id: row?.id ?? null,
    course_id: row?.course_id ?? null,
    last_export_completed_at: row?.last_export_completed_at ?? null,
    associated_course_count: row?.associated_course_count ?? null,
    latest_migration: row?.latest_migration ? compactBlueprintMigration(row.latest_migration) : null,
    key: keySample(row),
  };
}

function compactBlueprintMigration(row: any): Record<string, unknown> {
  return {
    blueprint_migration_id: row?.id ?? null,
    blueprint_template_id: row?.template_id ?? null,
    blueprint_subscription_id: row?.subscription_id ?? null,
    user_id: row?.user_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    created_at: row?.created_at ?? null,
    exports_started_at: row?.exports_started_at ?? null,
    exports_completed_at: row?.exports_completed_at ?? null,
    imports_queued_at: row?.imports_queued_at ?? null,
    imports_completed_at: row?.imports_completed_at ?? null,
    comment: row?.comment ? stripHtml(String(row.comment)).slice(0, 400) : null,
    key: keySample(row),
  };
}

function compactBlueprintSubscription(row: any): Record<string, unknown> {
  return {
    blueprint_subscription_id: row?.id ?? row?.subscription_id ?? null,
    blueprint_course_id: row?.blueprint_course_id ?? row?.template_id ?? null,
    course_id: row?.course_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    last_export_completed_at: row?.last_export_completed_at ?? null,
    key: keySample(row),
  };
}

function compactBlueprintCourse(row: any): Record<string, unknown> {
  return {
    course_id: row?.id ?? row?.course_id ?? null,
    course_code: row?.course_code ?? null,
    name: row?.name ?? null,
    workflow_state: row?.workflow_state ?? null,
    account_id: row?.account_id ?? null,
    enrollment_term_id: row?.enrollment_term_id ?? null,
    key: keySample(row),
  };
}

function compactBlueprintChange(row: any): Record<string, unknown> {
  return {
    asset_id: row?.asset_id ?? row?.content_id ?? null,
    asset_type: row?.asset_type ?? row?.content_type ?? null,
    asset_name: row?.asset_name ?? row?.name ?? row?.title ?? null,
    change_type: row?.change_type ?? null,
    html_url: row?.html_url ?? null,
    locked: row?.locked ?? null,
    key: keySample(row),
  };
}

function compactCourseSection(row: any): Record<string, unknown> {
  return {
    section_id: row?.id ?? null,
    name: row?.name ?? null,
    course_id: row?.course_id ?? null,
    sis_section_id: row?.sis_section_id ?? null,
    integration_id: row?.integration_id ?? null,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    restrict_enrollments_to_section_dates: !!row?.restrict_enrollments_to_section_dates,
    total_student_count: row?.total_students ?? row?.students_count ?? null,
    enrollment_role: row?.enrollment_role ?? null,
  };
}

function compactGradingPeriod(row: any): Record<string, unknown> {
  return {
    grading_period_id: row?.id ?? null,
    grading_period_group_id: row?.grading_period_group_id ?? null,
    title: row?.title ?? null,
    start_at: row?.start_date ?? row?.start_at ?? null,
    end_at: row?.end_date ?? row?.end_at ?? null,
    close_at: row?.close_date ?? row?.close_at ?? null,
    weight: row?.weight ?? null,
    is_closed: row?.is_closed ?? null,
    key: keySample(row),
  };
}

function compactGradingPeriodSet(row: any): Record<string, unknown> {
  return {
    grading_period_set_id: row?.id ?? null,
    title: row?.title ?? null,
    is_weighted: row?.weighted ?? row?.is_weighted ?? null,
    display_totals_for_all_grading_period: row?.display_totals_for_all_grading_periods ?? null,
    enrollment_term_id: row?.enrollment_term_id ?? row?.enrollment_term_ids ?? null,
    grading_period_count: Array.isArray(row?.grading_periods) ? row.grading_periods.length : null,
    grading_period: limitRow(unwrapCanvasArray(row?.grading_periods, 'grading_periods'), 20).map(compactGradingPeriod),
    key: keySample(row),
  };
}

function compactEnrollment(row: any): Record<string, unknown> {
  return {
    enrollment_id: row?.id ?? null,
    user_id: row?.user_id ?? null,
    course_id: row?.course_id ?? null,
    course_section_id: row?.course_section_id ?? null,
    type: row?.type ?? null,
    role: row?.role ?? row?.role_name ?? null,
    enrollment_state: row?.enrollment_state ?? row?.workflow_state ?? null,
    limit_privileges_to_course_section: !!row?.limit_privileges_to_course_section,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    current_grading_period_id: row?.current_grading_period_id ?? row?.grades?.current_grading_period_id ?? null,
    current_grading_period_title: row?.current_grading_period_title ?? row?.grades?.current_grading_period_title ?? null,
    has_grading_period: !!(row?.has_grading_periods ?? row?.grades?.has_grading_periods),
    computed_current_score: row?.computed_current_score ?? row?.grades?.current_score ?? null,
    computed_final_score: row?.computed_final_score ?? row?.grades?.final_score ?? null,
  };
}

function compactAssignmentGroup(row: any): Record<string, unknown> {
  const rule = row?.rules && typeof row.rules === 'object' ? row.rules : {};
  return {
    assignment_group_id: row?.id ?? null,
    name: row?.name ?? null,
    position: row?.position ?? null,
    group_weight: row?.group_weight ?? null,
    is_any_assignment_in_closed_grading_period: row?.any_assignment_in_closed_grading_period ?? null,
    assignment_count: Array.isArray(row?.assignments) ? row.assignments.length : null,
    drop_lowest: rule?.drop_lowest ?? null,
    drop_highest: rule?.drop_highest ?? null,
    never_drop_assignment_id: Array.isArray(rule?.never_drop) ? rule.never_drop : [],
  };
}

function compactGradingStandard(row: any): Record<string, unknown> {
  const data = Array.isArray(row?.grading_scheme) ? row.grading_scheme : Array.isArray(row?.data) ? row.data : [];
  return {
    grading_standard_id: row?.id ?? null,
    title: row?.title ?? row?.name ?? null,
    context_type: row?.context_type ?? null,
    context_id: row?.context_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    grading_scheme_count: data.length,
    grading_scheme: limitRow(data.map((one: any) => ({
      name: one?.name ?? null,
      value: one?.value ?? null,
    })), 20),
  };
}

function compactGradebookHistoryFeed(row: any): Record<string, unknown> {
  return {
    submission_version_id: row?.id ?? row?.submission_id ?? null,
    assignment_id: row?.assignment_id ?? null,
    assignment_name: row?.assignment_name ?? null,
    user_id: row?.user_id ?? null,
    workflow_state: row?.workflow_state ?? row?.current_workflow_state ?? null,
    grade: row?.grade ?? row?.current_grade ?? null,
    score: row?.score ?? row?.current_score ?? null,
    graded_at: row?.graded_at ?? row?.current_graded_at ?? null,
    submitted_at: row?.submitted_at ?? row?.current_submitted_at ?? null,
    attempt: row?.attempt ?? row?.current_attempt ?? null,
    grader_id: row?.grader_id ?? row?.grader?.id ?? null,
  };
}

function gradeChangeEventList(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object' && Array.isArray((value as any).events)) return (value as any).events;
  return [];
}

function compactGradeChangeEvent(row: any): Record<string, unknown> {
  const link = row?.links && typeof row.links === 'object' ? row.links : {};
  const sensitiveKey = new Set(['request_id', 'page_view']);
  return {
    grade_change_event_id: row?.id ?? null,
    event_type: row?.event_type ?? row?.type ?? null,
    created_at: row?.created_at ?? row?.createdAt ?? null,
    assignment_id: row?.assignment_id ?? link.assignment ?? null,
    course_id: row?.course_id ?? link.course ?? null,
    student_id: row?.student_id ?? link.student ?? row?.user_id ?? null,
    grader_id: row?.grader_id ?? link.grader ?? null,
    grade_before: row?.grade_before ?? null,
    grade_after: row?.grade_after ?? null,
    is_excused_before: row?.excused_before ?? null,
    is_excused_after: row?.excused_after ?? null,
    is_graded_anonymously: row?.graded_anonymously ?? null,
    version_number: row?.version_number ?? null,
    key: keySample(row).filter((key) => !sensitiveKey.has(key)),
  };
}

function compactCustomGradebookColumn(row: any): Record<string, unknown> {
  return {
    custom_gradebook_column_id: row?.id ?? null,
    teacher_note: row?.teacher_notes ?? null,
    title: row?.title ?? null,
    position: row?.position ?? null,
    is_hidden: !!row?.hidden,
    read_only: !!row?.read_only,
  };
}

function compactCustomGradebookColumnDatum(row: any, userId: string | null): Record<string, unknown> | null {
  if (!userId || String(row?.user_id ?? '') !== userId) return null;
  return {
    custom_gradebook_column_id: row?.column_id ?? row?.custom_gradebook_column_id ?? null,
    user_id: row?.user_id ?? null,
    content: row?.content ?? null,
  };
}

function compactCalendarItem(row: any): Record<string, unknown> {
  const assignment = row?.assignment ?? {};
  return {
    event_id: row?.id ?? null,
    title: row?.title ?? assignment?.name ?? null,
    type: row?.type ?? null,
    assignment_id: assignment?.id ?? row?.assignment_id ?? null,
    start_at: row?.start_at ?? row?.all_day_date ?? assignment?.due_at ?? null,
    html_url: row?.html_url ?? assignment?.html_url ?? null,
  };
}

function compactCalendarEvent(row: any): Record<string, unknown> {
  const assignment = row?.assignment ?? {};
  return {
    event_id: row?.id ?? null,
    title: row?.title ?? assignment?.name ?? null,
    type: row?.type ?? null,
    context_code: row?.context_code ?? null,
    effective_context_code: row?.effective_context_code ?? null,
    context_name: row?.context_name ?? null,
    assignment_id: assignment?.id ?? row?.assignment_id ?? null,
    appointment_group_id: row?.appointment_group_id ?? null,
    parent_event_id: row?.parent_event_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    start_at: row?.start_at ?? row?.all_day_date ?? assignment?.due_at ?? null,
    end_at: row?.end_at ?? row?.all_day_date ?? assignment?.due_at ?? null,
    all_day_date: row?.all_day_date ?? null,
    is_all_day: !!row?.all_day,
    is_hidden: !!row?.hidden,
    is_important_date: !!row?.important_dates,
    is_blackout_date: !!row?.blackout_date,
    is_own_reservation: !!row?.own_reservation,
    is_reserved: !!row?.reserved,
    participant_type: row?.participant_type ?? null,
    available_slot_count: row?.available_slots ?? null,
    location_name: row?.location_name ?? null,
    location_address: row?.location_address ?? null,
    html_url: row?.html_url ?? assignment?.html_url ?? null,
    url: row?.url ?? null,
    series_uuid: row?.series_uuid ?? null,
    series_natural_language: row?.series_natural_language ?? null,
  };
}

function compactAppointmentGroup(row: any): Record<string, unknown> {
  const appointment = Array.isArray(row?.appointments) ? row.appointments : [];
  const reservedTime = Array.isArray(row?.reserved_times) ? row.reserved_times : [];
  const childEvent = Array.isArray(row?.child_events) ? row.child_events : [];
  return {
    appointment_group_id: row?.id ?? null,
    title: row?.title ?? null,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    workflow_state: row?.workflow_state ?? null,
    participant_type: row?.participant_type ?? null,
    participant_count: row?.participant_count ?? null,
    appointment_count: appointment.length,
    child_event_count: childEvent.length,
    reserved_time_count: reservedTime.length,
    is_requiring_action: !!row?.requiring_action,
    is_published: row?.published ?? null,
    min_appointment_per_participant: row?.min_appointments_per_participant ?? null,
    max_appointment_per_participant: row?.max_appointments_per_participant ?? null,
    participant_per_appointment: row?.participants_per_appointment ?? null,
    location_name: row?.location_name ?? null,
    location_address: row?.location_address ?? null,
    html_url: row?.html_url ?? null,
    context_code: Array.isArray(row?.context_codes) ? row.context_codes : [],
    sub_context_code: Array.isArray(row?.sub_context_codes) ? row.sub_context_codes : [],
  };
}

function compactGroup(row: any): Record<string, unknown> {
  const tab = Array.isArray(row?.tabs) ? row.tabs : [];
  return {
    group_id: row?.id ?? null,
    group_name: row?.name ?? null,
    course_id: row?.course_id ?? null,
    group_category_id: row?.group_category_id ?? null,
    member_count: row?.members_count ?? null,
    tab_count: tab.length,
    tab: tab.map((one: any) => ({
      id: one?.id ?? null,
      label: one?.label ?? null,
      type: one?.type ?? null,
      html_url: one?.html_url ?? one?.full_url ?? null,
    })),
  };
}

function compactGroupCategory(row: any): Record<string, unknown> {
  return {
    group_category_id: row?.id ?? null,
    name: row?.name ?? null,
    role: row?.role ?? null,
    self_signup: row?.self_signup ?? null,
    context_type: row?.context_type ?? null,
    context_id: row?.context_id ?? null,
    group_count: row?.groups_count ?? row?.group_count ?? null,
    is_protected: !!row?.protected,
    is_non_collaborative: !!row?.non_collaborative,
    allows_multiple_memberships: row?.allows_multiple_memberships ?? null,
    created_at: row?.created_at ?? null,
  };
}

function compactGroupMember(row: any): Record<string, unknown> {
  return {
    user_id: row?.id ?? row?.user_id ?? null,
    name: row?.name ?? row?.display_name ?? null,
    sortable_name: row?.sortable_name ?? null,
    short_name: row?.short_name ?? null,
    avatar_url: row?.avatar_url ?? null,
  };
}

function compactGroupMembership(row: any): Record<string, unknown> {
  return {
    membership_id: row?.id ?? null,
    group_id: row?.group_id ?? row?.group?.id ?? null,
    user_id: row?.user_id ?? row?.user?.id ?? null,
    workflow_state: row?.workflow_state ?? null,
    is_moderator: !!row?.moderator,
    just_created: row?.just_created ?? null,
    sis_import_id: row?.sis_import_id ?? null,
  };
}

function compactGroupPermission(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object') return {};
  const row = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, permission] of Object.entries(row)) {
    if (typeof permission === 'boolean') out[key] = permission;
    else if (permission && typeof permission === 'object' && 'enabled' in (permission as Record<string, unknown>)) {
      out[key] = !!(permission as Record<string, unknown>).enabled;
    }
  }
  return out;
}

function nameRoleMember(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') {
    const row = value as any;
    for (const key of ['members', 'results', 'name_role', 'names_and_roles']) {
      if (Array.isArray(row?.[key])) return row[key];
    }
  }
  return [];
}

function compactLtiNameRoleMember(row: any): Record<string, unknown> {
  const role = Array.isArray(row?.roles) ? row.roles : Array.isArray(row?.role) ? row.role : [];
  const message = Array.isArray(row?.message) ? row.message : [];
  return {
    lti_user_id: row?.user_id ?? row?.userId ?? row?.sub ?? null,
    canvas_user_id: row?.canvas_user_id ?? row?.canvas_user?.id ?? row?.id ?? null,
    name: row?.name ?? row?.display_name ?? null,
    given_name: row?.given_name ?? null,
    family_name: row?.family_name ?? null,
    status: row?.status ?? null,
    role,
    role_count: role.length,
    message_count: message.length,
    context_id: row?.context_id ?? row?.context?.id ?? null,
    person_sourced_id: row?.lis_person_sourcedid ?? row?.person_sourcedid ?? null,
  };
}

function compactGroupDiscussion(row: any): Record<string, unknown> {
  return {
    discussion_id: row?.id ?? null,
    title: row?.title ?? null,
    discussion_type: row?.discussion_type ?? null,
    posted_at: row?.posted_at ?? null,
    delayed_post_at: row?.delayed_post_at ?? null,
    lock_at: row?.lock_at ?? null,
    require_initial_post: !!row?.require_initial_post,
    assignment_id: row?.assignment_id ?? row?.assignment?.id ?? null,
    todo_date: row?.todo_date ?? null,
    unread_count: row?.unread_count ?? null,
    discussion_subentry_count: row?.discussion_subentry_count ?? null,
    workflow_state: row?.workflow_state ?? null,
    html_url: row?.html_url ?? null,
    user_can_see_posts: row?.user_can_see_posts ?? null,
    author: row?.author ? compactUser(row.author) : null,
  };
}

function compactCollaboration(row: any, maxChar = 600): Record<string, unknown> {
  return {
    collaboration_id: row?.id ?? null,
    title: row?.title ?? null,
    description_text: stripHtml(row?.description ?? '').slice(0, maxChar),
    collaboration_type: row?.collaboration_type ?? row?.type ?? null,
    document_id: row?.document_id ?? null,
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    user_id: row?.user_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    url: row?.url ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
  };
}

function compactCollaborator(row: any): Record<string, unknown> {
  return {
    collaborator_id: row?.id ?? row?.user_id ?? row?.group_id ?? null,
    type: row?.type ?? row?.collaborator_type ?? null,
    name: row?.name ?? row?.display_name ?? null,
  };
}

function compactUser(row: any): Record<string, unknown> {
  return {
    user_id: row?.id ?? row?.user_id ?? null,
    name: row?.name ?? row?.display_name ?? null,
    sortable_name: row?.sortable_name ?? null,
    short_name: row?.short_name ?? null,
    avatar_url: row?.avatar_url ?? null,
  };
}

function compactCourseUser(row: any): Record<string, unknown> {
  const enrollment = Array.isArray(row?.enrollments) ? row.enrollments : [];
  return {
    user_id: row?.id ?? row?.user_id ?? null,
    name: row?.name ?? row?.display_name ?? null,
    sortable_name: row?.sortable_name ?? null,
    short_name: row?.short_name ?? null,
    pronouns: row?.pronouns ?? null,
    enrollment_count: enrollment.length,
    enrollment: enrollment.map((one: any) => ({
      enrollment_id: one?.id ?? null,
      type: one?.type ?? null,
      role: one?.role ?? one?.role_name ?? null,
      course_section_id: one?.course_section_id ?? null,
      enrollment_state: one?.enrollment_state ?? one?.workflow_state ?? null,
      limit_privileges_to_course_section: !!one?.limit_privileges_to_course_section,
    })),
  };
}

function compactEportfolio(row: any): Record<string, unknown> {
  return {
    eportfolio_id: row?.id ?? null,
    user_id: row?.user_id ?? null,
    name: row?.name ?? null,
    is_public: !!row?.public,
    workflow_state: row?.workflow_state ?? null,
    spam_status: row?.spam_status ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    deleted_at: row?.deleted_at ?? null,
  };
}

function compactEportfolioPage(row: any, maxChar = 1000): Record<string, unknown> {
  return {
    eportfolio_page_id: row?.id ?? row?.page_id ?? null,
    eportfolio_id: row?.eportfolio_id ?? null,
    position: row?.position ?? null,
    name: row?.name ?? row?.title ?? null,
    content_text: stripHtml(row?.content ?? row?.body ?? '').slice(0, maxChar),
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
  };
}

function compactProfile(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    user_id: row?.id ?? row?.user_id ?? null,
    name: row?.name ?? null,
    short_name: row?.short_name ?? null,
    sortable_name: row?.sortable_name ?? null,
    title: row?.title ?? null,
    bio_text: stripHtml(row?.bio ?? '').slice(0, 600),
    primary_email: row?.primary_email ?? null,
    time_zone: row?.time_zone ?? null,
    locale: row?.locale ?? null,
    effective_locale: row?.effective_locale ?? null,
    avatar_url: row?.avatar_url ?? null,
    calendar: row?.calendar ? {
      ics: row.calendar?.ics ?? null,
    } : null,
    login_id: row?.login_id ?? null,
    pronouns: row?.pronouns ?? null,
  };
}

function compactCoursePreference(row: any): Record<string, unknown> {
  return {
    course_id: row?.id ?? row?.course_id ?? null,
    name: row?.name ?? null,
    course_code: row?.course_code ?? null,
    workflow_state: row?.workflow_state ?? null,
    term_name: row?.term?.name ?? null,
    start_at: row?.start_at ?? null,
    end_at: row?.end_at ?? null,
    is_public: !!row?.is_public,
    is_favorite: row?.is_favorite ?? row?.favorite ?? null,
    image_download_url: row?.image_download_url ?? row?.image_url ?? null,
  };
}

function compactDashboardCard(row: any): Record<string, unknown> {
  return {
    course_id: row?.id ?? row?.course_id ?? null,
    short_name: row?.shortName ?? row?.short_name ?? null,
    original_name: row?.originalName ?? row?.original_name ?? null,
    course_code: row?.courseCode ?? row?.course_code ?? null,
    enrollment_type: row?.enrollmentType ?? row?.enrollment_type ?? null,
    asset_string: row?.assetString ?? row?.asset_string ?? null,
    href: row?.href ?? null,
    image: row?.image ?? null,
    color: row?.color ?? null,
    position: row?.position ?? null,
    is_published: row?.published ?? null,
    is_favorite: row?.isFavorited ?? row?.is_favorite ?? null,
  };
}

function compactBookmark(row: any): Record<string, unknown> {
  return {
    bookmark_id: row?.id ?? null,
    name: row?.name ?? null,
    url: row?.url ?? null,
    position: row?.position ?? null,
    data: row?.data ?? null,
  };
}

function compactUserColor(row: any): Record<string, unknown>[] {
  const color = row?.custom_colors && typeof row.custom_colors === 'object'
    ? row.custom_colors
    : {};
  return Object.entries(color).map(([assetString, hexcode]) => ({
    asset_string: assetString,
    hexcode,
  }));
}

function compactDashboardPosition(row: any): Record<string, unknown>[] {
  const position = row?.dashboard_positions && typeof row.dashboard_positions === 'object'
    ? row.dashboard_positions
    : {};
  return Object.entries(position).map(([assetString, value]) => ({
    asset_string: assetString,
    position: value,
  }));
}

function compactGradedSubmission(row: any): Record<string, unknown> {
  const assignment = row?.assignment ?? null;
  return {
    submission_id: row?.id ?? null,
    assignment_id: row?.assignment_id ?? assignment?.id ?? null,
    course_id: row?.course_id ?? assignment?.course_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    submitted_at: row?.submitted_at ?? null,
    graded_at: row?.graded_at ?? null,
    grade: row?.grade ?? null,
    score: row?.score ?? null,
    late: row?.late ?? null,
    missing: row?.missing ?? null,
    assignment: assignment ? compactAssignmentLike(assignment) : null,
    key: keySample(row),
  };
}

function compactPageView(row: any): Record<string, unknown> {
  return {
    page_view_id: row?.id ?? row?.request_id ?? null,
    created_at: row?.created_at ?? row?.timestamp ?? row?.occurred_at ?? null,
    url: row?.url ?? null,
    context_type: row?.context_type ?? null,
    context_id: row?.context_id ?? null,
    asset_type: row?.asset_type ?? null,
    asset_id: row?.asset_id ?? null,
    controller: row?.controller ?? null,
    action: row?.action ?? null,
    http_method: row?.http_method ?? row?.method ?? null,
    interaction_second: row?.interaction_seconds ?? null,
    participated: row?.participated ?? null,
    user_agent_present: Boolean(row?.user_agent),
    key: keySample(row),
  };
}

function compactCourseProgress(row: any): Record<string, unknown> | null {
  const progress = row?.course_progress ?? row?.progress ?? null;
  if (!progress || typeof progress !== 'object') return null;
  return {
    requirement_count: progress.requirement_count ?? null,
    requirement_completed_count: progress.requirement_completed_count ?? null,
    next_requirement_url: progress.next_requirement_url ?? null,
    completed_at: progress.completed_at ?? null,
  };
}

function compactFolder(row: any): Record<string, unknown> {
  return {
    folder_id: row?.id ?? null,
    name: row?.name ?? null,
    full_name: row?.full_name ?? null,
    parent_folder_id: row?.parent_folder_id ?? null,
    file_count: row?.files_count ?? null,
    folder_count: row?.folders_count ?? null,
    position: row?.position ?? null,
    is_hidden: !!row?.hidden,
    is_hidden_for_user: !!row?.hidden_for_user,
    is_locked: !!row?.locked,
    is_locked_for_user: !!row?.locked_for_user,
    is_for_submission: !!row?.for_submissions,
    unlock_at: row?.unlock_at ?? null,
    lock_at: row?.lock_at ?? null,
    updated_at: row?.updated_at ?? null,
  };
}

function compactFile(row: any, folderById = new Map<string, any>()): Record<string, unknown> {
  const folder = row?.folder_id === undefined || row?.folder_id === null ? null : folderById.get(String(row.folder_id));
  const type = fileType(row);
  return {
    file_id: row?.id ?? null,
    display_name: row?.display_name ?? row?.filename ?? null,
    file_name: row?.filename ?? null,
    file_type: type,
    content_type: row?.['content-type'] ?? row?.content_type ?? null,
    size_byte: row?.size ?? null,
    folder_id: row?.folder_id ?? null,
    folder_name: folder?.full_name ?? folder?.name ?? null,
    is_locked: !!row?.locked,
    is_locked_for_user: !!row?.locked_for_user,
    is_hidden: !!row?.hidden,
    is_hidden_for_user: !!row?.hidden_for_user,
    unlock_at: row?.unlock_at ?? null,
    lock_at: row?.lock_at ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    modified_at: row?.modified_at ?? null,
    visibility_level: row?.visibility_level ?? null,
    mime_class: row?.mime_class ?? null,
    media_entry_id: row?.media_entry_id ?? null,
    thumbnail_url: row?.thumbnail_url ?? null,
    preview_url: row?.preview_url ?? null,
    url: row?.url ?? null,
    usage_rights_key: keySample(row?.usage_rights),
    is_reading_like: ['pdf', 'docx', 'presentation', 'html', 'text'].includes(String(type)),
  };
}

function compactFilePublicUrl(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    public_url: row?.public_url ?? row?.url ?? null,
    preview_url: row?.preview_url ?? null,
    key: keySample(row),
  };
}

function compactOriginalityReport(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    originality_report_id: row?.id ?? null,
    file_id: row?.file_id ?? null,
    originality_score: row?.originality_score ?? null,
    originality_report_file_id: row?.originality_report_file_id ?? null,
    originality_report_url: row?.originality_report_url ?? null,
    workflow_state: row?.workflow_state ?? null,
    error_report: row?.error_report ?? row?.error_message ?? null,
    submission_time: row?.submission_time ?? null,
    root_account_id: row?.root_account_id ?? null,
    tool_setting_key: keySample(row?.tool_setting),
  };
}

function compactFileQuota(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    quota_byte: row?.quota ?? row?.quota_bytes ?? null,
    quota_used_byte: row?.quota_used ?? row?.quota_used_bytes ?? null,
  };
}

function compactShareUser(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    user_id: row?.id ?? row?.user_id ?? null,
    display_name: row?.display_name ?? row?.name ?? null,
    html_url: row?.html_url ?? null,
    avatar_url: row?.avatar_image_url ?? row?.avatar_url ?? null,
  };
}

function compactContentShare(row: any): Record<string, unknown> {
  return {
    content_share_id: row?.id ?? null,
    name: row?.name ?? null,
    content_type: row?.content_type ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    user_id: row?.user_id ?? null,
    read_state: row?.read_state ?? null,
    sender: compactShareUser(row?.sender),
    receiver: Array.isArray(row?.receivers) ? row.receivers.map(compactShareUser).filter(Boolean) : [],
    source_course: row?.source_course ? {
      course_id: row.source_course?.id ?? null,
      name: row.source_course?.name ?? null,
      course_code: row.source_course?.course_code ?? null,
    } : null,
    content_export_id: row?.content_export?.id ?? row?.content_export_id ?? null,
    key: keySample(row),
  };
}

function compactPage(row: any): Record<string, unknown> {
  return {
    page_id: row?.page_id ?? row?.id ?? null,
    page_url: row?.url ?? null,
    title: row?.title ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    published: row?.published ?? null,
    is_front_page: !!row?.front_page,
    is_locked_for_user: !!row?.locked_for_user,
    lock_info_key: keySample(row?.lock_info),
    editing_roles: row?.editing_roles ?? null,
    html_url: row?.html_url ?? null,
  };
}

function compactAnnouncement(row: any): Record<string, unknown> {
  return {
    announcement_id: row?.id ?? null,
    discussion_topic_id: row?.discussion_topic_id ?? row?.id ?? null,
    context_code: row?.context_code ?? null,
    title: row?.title ?? null,
    posted_at: row?.posted_at ?? null,
    delayed_post_at: row?.delayed_post_at ?? null,
    lock_at: row?.lock_at ?? row?.locked_at ?? null,
    workflow_state: row?.workflow_state ?? null,
    is_locked: !!row?.locked,
    is_podcast_enabled: !!row?.podcast_enabled,
    unread_count: row?.unread_count ?? null,
    read_state: row?.read_state ?? null,
    html_url: row?.html_url ?? null,
    author: row?.author ? compactUser(row.author) : null,
  };
}

function compactTab(row: any): Record<string, unknown> {
  return {
    id: row?.id ?? null,
    label: row?.label ?? null,
    type: row?.type ?? null,
    visibility: row?.visibility ?? null,
    is_external: /external/i.test(String(row?.type ?? row?.id ?? '')),
    html_url: row?.html_url ?? row?.full_url ?? null,
  };
}

const EXTERNAL_TOOL_PLACEMENT_KEY = [
  'account_navigation',
  'assignment_edit',
  'assignment_group_menu',
  'assignment_index_menu',
  'assignment_menu',
  'assignment_selection',
  'collaboration',
  'conference_selection',
  'course_assignments_menu',
  'course_home_sub_navigation',
  'course_navigation',
  'course_settings_sub_navigation',
  'discussion_topic_menu',
  'editor_button',
  'file_index_menu',
  'global_navigation',
  'homework_submission',
  'link_selection',
  'migration_selection',
  'module_group_menu',
  'module_index_menu',
  'module_index_menu_modal',
  'module_menu',
  'post_grades',
  'quiz_index_menu',
  'similarity_detection',
  'student_context_card',
  'submission_type_selection',
  'top_navigation',
  'user_navigation',
];

function externalToolPlacementKey(row: any): string[] {
  return EXTERNAL_TOOL_PLACEMENT_KEY.filter((key) => row?.[key]);
}

function compactExternalTool(row: any, maxChar = 600): Record<string, unknown> {
  return {
    external_tool_id: row?.id ?? null,
    name: row?.name ?? null,
    description_text: stripHtml(row?.description ?? '').slice(0, maxChar),
    domain: row?.domain ?? null,
    url: row?.url ?? null,
    privacy_level: row?.privacy_level ?? null,
    workflow_state: row?.workflow_state ?? null,
    is_course_navigation: !!row?.course_navigation,
    is_rce_favorite: !!row?.is_rce_favorite,
    is_top_nav_favorite: !!row?.is_top_nav_favorite,
    placement_key: externalToolPlacementKey(row),
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
  };
}

function compactExternalToolModuleItem(row: any, module: any): Record<string, unknown> {
  const contentDetail = row?.content_details ?? {};
  return {
    module_id: module?.id ?? row?.module_id ?? null,
    module_name: module?.name ?? null,
    module_item_id: row?.id ?? null,
    title: row?.title ?? null,
    content_id: row?.content_id ?? null,
    external_url: row?.external_url ?? contentDetail?.url ?? null,
    html_url: row?.html_url ?? null,
    url: row?.url ?? null,
    is_new_quiz_lti: !!row?.quiz_lti,
    content_detail_key: keySample(contentDetail),
    indent: row?.indent ?? null,
    position: row?.position ?? null,
    completion_requirement: row?.completion_requirement ?? null,
    is_published: row?.published ?? null,
    is_locked_for_user: !!row?.locked_for_user,
  };
}

function compactSessionlessLaunch(row: any): Record<string, unknown> {
  return {
    external_tool_id: row?.id ?? null,
    name: row?.name ?? null,
    url: row?.url ?? null,
  };
}

function compactConversation(row: any): Record<string, unknown> {
  return {
    conversation_id: row?.id ?? null,
    subject: row?.subject ?? null,
    workflow_state: row?.workflow_state ?? null,
    updated_at: row?.updated_at ?? null,
    message_count: row?.message_count ?? row?.messages_count ?? null,
    context_name: row?.context_name ?? null,
  };
}

function flattenDiscussionEntry(entry: any[]): any[] {
  const out: any[] = [];
  const walk = (row: any[]) => {
    for (const one of row) {
      out.push(one);
      if (Array.isArray(one?.replies) && one.replies.length > 0) walk(one.replies);
    }
  };
  walk(Array.isArray(entry) ? entry : []);
  return out;
}

function compactDiscussionEntry(row: any, includeBody: boolean, maxChar: number): Record<string, unknown> {
  return {
    entry_id: row?.id ?? null,
    user_id: row?.user_id ?? null,
    parent_id: row?.parent_id ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    reply_count: Array.isArray(row?.replies) ? row.replies.length : 0,
    rating_count: row?.rating_count ?? null,
    rating_sum: row?.rating_sum ?? null,
    ...(includeBody ? { body_text: stripHtml(row?.message).slice(0, maxChar) } : {}),
  };
}

function stripHtml(value: string | null | undefined): string {
  return String(value ?? '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

const DEADLINE_RE = /\b(deadline|due|submit|submission|extend|extension|late|quiz|assignment|activity|tonight|tomorrow|today|asap|\d{1,2}[/-]\d{1,2}|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2})\b/i;

function excerptAround(value: string, regex = DEADLINE_RE, size = 320): string | null {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  const match = text.match(regex);
  if (!match || match.index === undefined) return null;
  const start = Math.max(0, match.index - Math.floor(size / 2));
  return text.slice(start, start + size).trim();
}

function compactConversationDetail(row: any): Record<string, unknown>[] {
  const message = Array.isArray(row?.messages) ? row.messages : [];
  return message.flatMap((one: any) => {
    const excerpt = excerptAround(stripHtml(one?.body ?? one?.generated_body ?? ''));
    if (!excerpt) return [];
    return [{
      conversation_id: row?.id ?? null,
      subject: row?.subject ?? null,
      message_id: one?.id ?? null,
      created_at: one?.created_at ?? null,
      author_id: one?.author_id ?? null,
      excerpt,
    }];
  });
}

function compactActivity(row: any): Record<string, unknown> {
  return {
    id: row?.id ?? null,
    type: row?.type ?? null,
    title: row?.title ?? null,
    context_type: row?.context_type ?? null,
    course_id: row?.course_id ?? null,
    read_state: row?.read_state ?? null,
    created_at: row?.created_at ?? null,
    html_url: row?.html_url ?? null,
  };
}

function courseAuditEventList(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object' && Array.isArray((value as any).events)) return (value as any).events;
  return [];
}

function compactCourseAuditEvent(row: any): Record<string, unknown> {
  const link = row?.links && typeof row.links === 'object' ? row.links : {};
  return {
    id: row?.id ?? null,
    event_type: row?.event_type ?? row?.type ?? null,
    created_at: row?.created_at ?? row?.createdAt ?? null,
    request_id: row?.request_id ?? null,
    course_id: link.course ?? row?.course_id ?? null,
    user_id: link.user ?? row?.user_id ?? null,
    page_view_id: link.page_view ?? row?.page_view_id ?? null,
  };
}

function compactHistory(row: any): Record<string, unknown> {
  return {
    asset_code: row?.asset_code ?? null,
    asset_category: row?.asset_readable_category ?? null,
    asset_name: row?.asset_name ?? null,
    context_id: row?.context_id ?? null,
    visited_at: row?.visited_at ?? null,
    interaction_second: row?.interaction_seconds ?? null,
    visited_url: row?.visited_url ?? null,
  };
}

function compactCourseSearchResult(row: any, maxChar = 500): Record<string, unknown> {
  const content = stripHtml(row?.content ?? row?.body ?? row?.text ?? row?.description ?? row?.snippet ?? '');
  const module = Array.isArray(row?.modules) ? row.modules : [];
  return {
    result_id: row?.id ?? row?.content_id ?? row?.asset_id ?? null,
    content_type: row?.content_type ?? row?.type ?? row?.asset_type ?? null,
    title: row?.title ?? row?.name ?? null,
    html_url: row?.html_url ?? row?.url ?? row?.canvas_url ?? null,
    distance: row?.distance ?? row?.score ?? null,
    published: row?.published ?? row?.workflow_state ?? null,
    due_at: row?.due_at ?? row?.due_date ?? null,
    module: module.map((one: any) => ({
      module_id: one?.id ?? one?.module_id ?? null,
      name: one?.name ?? one?.title ?? null,
    })),
    content_text: content.slice(0, maxChar),
    content_truncated: content.length > maxChar,
  };
}

function compactSearchRecipient(row: any): Record<string, unknown> {
  return {
    recipient_id: row?.id ?? null,
    name: row?.name ?? null,
    full_name: row?.full_name ?? null,
    type: row?.type ?? null,
    user_count: row?.user_count ?? null,
    common_course_count: row?.common_courses && typeof row.common_courses === 'object'
      ? Object.keys(row.common_courses).length
      : null,
    common_group_count: row?.common_groups && typeof row.common_groups === 'object'
      ? Object.keys(row.common_groups).length
      : null,
    permission: row?.permissions && typeof row.permissions === 'object' ? row.permissions : null,
    key: keySample(row),
  };
}

function compactPublicCourseSearch(row: any): Record<string, unknown> {
  return {
    course_id: row?.id ?? row?.course_id ?? null,
    course_code: row?.course_code ?? row?.courseCode ?? null,
    name: row?.name ?? row?.title ?? null,
    public_description: stripHtml(row?.public_description ?? row?.description ?? '').slice(0, 300),
    is_public: row?.is_public ?? row?.public ?? null,
    is_open_enrollment: row?.open_enrollment ?? row?.is_open_enrollment ?? null,
    enrollment_term_id: row?.enrollment_term_id ?? null,
    key: keySample(row),
  };
}

function compactMediaAttachment(row: any, source: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    media_id: row?.id ?? row?.media_id ?? row?.attachment_id ?? null,
    title: row?.title ?? row?.display_name ?? row?.filename ?? null,
    media_type: row?.media_type ?? row?.type ?? row?.content_type ?? null,
    content_type: row?.content_type ?? row?.mime_class ?? null,
    duration_second: row?.duration ?? row?.duration_seconds ?? null,
    user_id: row?.user_id ?? row?.owner_id ?? null,
    context_type: row?.context_type ?? null,
    context_id: row?.context_id ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    url: row?.url ?? row?.media_url ?? row?.html_url ?? null,
    thumbnail_url: row?.thumbnail_url ?? row?.thumbnail ?? null,
    source,
    key: keySample(row),
  };
}

function compactKalturaConfig(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    is_enabled: row.enabled ?? null,
    domain: row.domain ?? null,
    resource_domain: row.resources_domain ?? row.resource_domain ?? null,
    rtmp_domain: row.rtmp_domain ?? null,
    partner_id: row.partner_id ?? null,
    key: keySample(row),
  };
}

function conferenceList(value: unknown): any[] {
  const row = value as any;
  if (Array.isArray(row)) return row;
  if (Array.isArray(row?.conferences)) return row.conferences;
  if (Array.isArray(row?.conference)) return row.conference;
  return [];
}

function compactConference(row: any, source: Record<string, unknown> = {}, maxChar = 600): Record<string, unknown> {
  const description = stripHtml(row?.description ?? row?.long_description ?? row?.body ?? '');
  return {
    conference_id: row?.id ?? row?.conference_id ?? null,
    title: row?.title ?? row?.name ?? null,
    conference_type: row?.conference_type ?? row?.type ?? null,
    context_type: row?.context_type ?? null,
    context_id: row?.context_id ?? null,
    user_id: row?.user_id ?? row?.creator_id ?? null,
    start_at: row?.start_at ?? row?.started_at ?? null,
    end_at: row?.end_at ?? row?.ended_at ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    duration_minute: row?.duration ?? row?.duration_minutes ?? null,
    is_live: !!(row?.started_at && !row?.ended_at) || row?.state === 'live' || row?.workflow_state === 'live',
    is_recorded: row?.recording ?? row?.recorded ?? row?.has_recording ?? null,
    url: row?.url ?? row?.html_url ?? row?.join_url ?? null,
    description_text: description.slice(0, maxChar),
    description_truncated: description.length > maxChar,
    source,
    key: keySample(row),
  };
}

function compactContentExport(row: any, source: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    export_id: row?.id ?? row?.content_export_id ?? null,
    export_type: row?.export_type ?? row?.migration_type ?? null,
    workflow_state: row?.workflow_state ?? row?.state ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    user_id: row?.user_id ?? null,
    progress_url: row?.progress_url ?? null,
    attachment_id: row?.attachment?.id ?? null,
    attachment_name: row?.attachment?.display_name ?? row?.attachment?.filename ?? null,
    attachment_url: row?.attachment?.url ?? null,
    source,
    key: keySample(row),
  };
}

function compactCourseReport(row: any, source: Record<string, unknown> = {}): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    report_id: row?.id ?? null,
    report_type: source.report_type ?? row?.report_type ?? null,
    status: row?.status ?? row?.workflow_state ?? null,
    progress_percent: row?.progress ?? null,
    created_at: row?.created_at ?? null,
    started_at: row?.started_at ?? null,
    ended_at: row?.ended_at ?? null,
    file_url: row?.file_url ?? null,
    attachment_id: row?.attachment?.id ?? null,
    attachment_name: row?.attachment?.display_name ?? row?.attachment?.filename ?? null,
    attachment_url: row?.attachment?.url ?? null,
    parameter_key: keySample(row?.parameters),
    source,
    key: keySample(row),
  };
}

function compactContentMigration(row: any, source: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    migration_id: row?.id ?? row?.content_migration_id ?? null,
    migration_type: row?.migration_type ?? null,
    migration_type_title: row?.migration_type_title ?? null,
    workflow_state: row?.workflow_state ?? row?.state ?? null,
    user_id: row?.user_id ?? null,
    started_at: row?.started_at ?? null,
    finished_at: row?.finished_at ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    progress_url: row?.progress_url ?? null,
    issue_url: row?.migration_issues_url ?? null,
    attachment_id: row?.attachment?.id ?? null,
    attachment_name: row?.attachment?.display_name ?? row?.attachment?.filename ?? null,
    attachment_url: row?.attachment?.url ?? null,
    setting_key: keySample(row?.settings),
    date_shift_key: keySample(row?.date_shift_options),
    source,
    key: keySample(row),
  };
}

function compactMigrationIssue(row: any, source: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    issue_id: row?.id ?? null,
    workflow_state: row?.workflow_state ?? null,
    issue_type: row?.issue_type ?? null,
    description: stripHtml(row?.description ?? '').slice(0, 500),
    fix_issue_html_url: row?.fix_issue_html_url ?? null,
    error_report_html_url: row?.error_report_html_url ?? null,
    content_migration_url: row?.content_migration_url ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    source,
    key: keySample(row),
  };
}

function compactMigrationMigrator(row: any): Record<string, unknown> {
  return {
    migration_type: row?.type ?? row?.migration_type ?? null,
    name: row?.name ?? null,
    is_file_upload_required: !!row?.requires_file_upload,
    required_setting_key: Array.isArray(row?.required_settings) ? row.required_settings.slice(0, 20) : [],
    key: keySample(row),
  };
}

function compactExternalFeed(row: any, source: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    external_feed_id: row?.id ?? null,
    display_name: row?.display_name ?? row?.title ?? row?.name ?? null,
    url: row?.url ?? null,
    header_match: row?.header_match ?? null,
    verbosity: row?.verbosity ?? null,
    created_at: row?.created_at ?? null,
    source,
    key: keySample(row),
  };
}

function compactSelectiveData(value: unknown): Record<string, unknown> {
  const row = Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : [];
  return {
    node_count: row.length,
    node: limitRow(row, 20).map((one: any) => ({
      type: one?.type ?? null,
      title: one?.title ?? one?.name ?? null,
      property: one?.property ?? null,
      sub_item_count: Array.isArray(one?.sub_items) ? one.sub_items.length : null,
      sub_items_url: one?.sub_items_url ?? null,
      key: keySample(one),
    })),
  };
}

function compactAssetIdMapping(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    asset_type_count: Object.keys(row).length,
    asset_type: Object.keys(row).slice(0, 20).map((key) => ({
      asset_type: key,
      mapping_count: row[key] && typeof row[key] === 'object' ? Object.keys(row[key] as Record<string, unknown>).length : 0,
    })),
  };
}

function compactEpubExport(row: any): Record<string, unknown> {
  const epub = row?.epub_export ?? row?.export ?? null;
  return {
    course_id: row?.id ?? row?.course_id ?? null,
    course_name: row?.name ?? row?.course_name ?? null,
    export_id: epub?.id ?? null,
    workflow_state: epub?.workflow_state ?? epub?.state ?? null,
    created_at: epub?.created_at ?? null,
    user_id: epub?.user_id ?? null,
    progress_url: epub?.progress_url ?? null,
    attachment_id: epub?.attachment?.id ?? null,
    attachment_name: epub?.attachment?.display_name ?? epub?.attachment?.filename ?? null,
    attachment_url: epub?.attachment?.url ?? null,
    key: keySample(row),
  };
}

type ProgressTarget = {
  kind: 'canvas' | 'lti';
  progress_id: string;
  course_id?: string | null;
  source_url?: string | null;
};

function progressTargetFromValue(value: unknown, courseIdValue?: string | null): ProgressTarget | null {
  if (value === undefined || value === null || value === '') return null;
  const raw = String(value);
  if (/^\d+$/.test(raw)) {
    return { kind: 'canvas', progress_id: raw, course_id: courseIdValue ?? null, source_url: null };
  }
  let path = raw;
  try {
    path = new URL(raw, BASE_URL).pathname;
  } catch {
    path = raw.split('?')[0] ?? raw;
  }
  const ltiMatch = path.match(/\/api\/lti\/courses\/([^/]+)\/progress\/([^/?#]+)/);
  if (ltiMatch) {
    return {
      kind: 'lti',
      course_id: ltiMatch[1],
      progress_id: decodeURIComponent(ltiMatch[2]),
      source_url: raw,
    };
  }
  const progressMatch = path.match(/\/(?:api\/v1\/)?progress\/([^/?#]+)/);
  if (progressMatch) {
    return {
      kind: 'canvas',
      progress_id: decodeURIComponent(progressMatch[1]),
      course_id: courseIdValue ?? null,
      source_url: raw,
    };
  }
  return null;
}

function compactProgress(row: any, source: Record<string, unknown> = {}): Record<string, unknown> {
  const completion = row?.completion ?? null;
  const workflowState = row?.workflow_state ?? row?.state ?? null;
  return {
    progress_id: row?.id ?? null,
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    user_id: row?.user_id ?? null,
    tag: row?.tag ?? null,
    completion,
    workflow_state: workflowState,
    message: row?.message ?? null,
    url: row?.url ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    is_complete: workflowState === 'completed' || Number(completion ?? 0) >= 100,
    source,
    key: keySample(row),
  };
}

function compactBlackoutDate(row: any): Record<string, unknown> {
  return {
    blackout_date_id: row?.id ?? null,
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    start_date: row?.start_date ?? null,
    end_date: row?.end_date ?? null,
    event_title: row?.event_title ?? row?.title ?? null,
    key: keySample(row),
  };
}

function compactCoursePaceItem(row: any): Record<string, unknown> {
  return {
    module_item_id: row?.module_item_id ?? row?.id ?? null,
    assignment_id: row?.assignment_id ?? null,
    content_id: row?.content_id ?? null,
    title: row?.title ?? row?.name ?? null,
    duration_day: row?.duration ?? row?.duration_days ?? null,
    due_at: row?.due_at ?? null,
    unlock_at: row?.unlock_at ?? null,
    module_item_type: row?.module_item_type ?? row?.type ?? null,
    key: keySample(row),
  };
}

function compactCoursePaceModule(row: any, maxItem: number): Record<string, unknown> {
  const item = Array.isArray(row?.items) ? row.items : Array.isArray(row?.module_items) ? row.module_items : [];
  return {
    module_id: row?.module_id ?? row?.id ?? null,
    title: row?.title ?? row?.name ?? null,
    position: row?.position ?? null,
    item_count: item.length,
    item: limitRow(item, maxItem).map(compactCoursePaceItem),
    key: keySample(row),
  };
}

function compactCoursePace(row: any, maxModule: number, maxItem: number): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  const module = Array.isArray(row?.modules) ? row.modules : [];
  return {
    course_pace_id: row?.id ?? null,
    course_id: row?.course_id ?? null,
    user_id: row?.user_id ?? null,
    workflow_state: row?.workflow_state ?? null,
    start_date: row?.start_date ?? null,
    end_date: row?.end_date ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    published_at: row?.published_at ?? null,
    exclude_weekend: row?.exclude_weekends ?? null,
    selected_day_to_skip: Array.isArray(row?.selected_days_to_skip) ? row.selected_days_to_skip : [],
    hard_end_date: row?.hard_end_dates ?? null,
    module_count: module.length,
    module: limitRow(module, maxModule).map((one: any) => compactCoursePaceModule(one, maxItem)),
    progress_key: keySample(row?.progress),
    key: keySample(row),
  };
}

function unwrapCanvasArray(value: unknown, key: string): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') {
    const inner = (value as any)[key];
    if (Array.isArray(inner)) return inner;
  }
  return [];
}

function compactAnalyticsActivity(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  const pageView = row?.page_views && typeof row.page_views === 'object' ? row.page_views : {};
  const participation = Array.isArray(row?.participations) ? row.participations : [];
  return {
    page_view_bucket_count: Object.keys(pageView).length,
    participation_count: participation.length,
    page_view_key: Object.keys(pageView).slice(0, 20),
    category_key: keySample(row?.by_category),
    key: keySample(row),
  };
}

function compactAnalyticsAssignment(row: any): Record<string, unknown> {
  const assignment = row?.assignment ?? row;
  return {
    assignment_id: assignment?.id ?? row?.assignment_id ?? null,
    title: assignment?.title ?? assignment?.name ?? row?.title ?? row?.name ?? null,
    due_at: assignment?.due_at ?? row?.due_at ?? null,
    points_possible: assignment?.points_possible ?? row?.points_possible ?? null,
    submission_count: row?.submissions ?? row?.submission_count ?? null,
    on_time_count: row?.on_time ?? row?.on_time_count ?? null,
    late_count: row?.late ?? row?.late_count ?? null,
    missing_count: row?.missing ?? row?.missing_count ?? null,
    key: keySample(row),
  };
}

function compactAnalyticsParticipation(row: any): Record<string, unknown> {
  return {
    date_at: row?.created_at ?? row?.date ?? row?.posted_at ?? null,
    url: row?.url ?? null,
    asset_type: row?.asset_type ?? row?.type ?? null,
    title: row?.title ?? null,
    key: keySample(row),
  };
}

function compactAnalyticsCommunication(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    message_bucket_count: Object.keys(row).length,
    date_key: Object.keys(row).slice(0, 20),
    key: keySample(row),
  };
}

function compactAnalyticsStudentSummary(row: any): Record<string, unknown> {
  return {
    user_id: row?.id ?? row?.user_id ?? null,
    page_view_count: row?.page_views ?? row?.page_view_count ?? null,
    participation_count: row?.participations ?? row?.participation_count ?? null,
    tardiness_breakdown: row?.tardiness_breakdown ?? null,
    max_page_view_count: row?.max_page_views ?? null,
    max_participation_count: row?.max_participations ?? null,
    key: keySample(row),
  };
}

function compactPollSubmission(row: any): Record<string, unknown> {
  return {
    poll_submission_id: row?.id ?? null,
    poll_choice_id: row?.poll_choice_id ?? null,
    user_id: row?.user_id ?? null,
    created_at: row?.created_at ?? null,
    key: keySample(row),
  };
}

function compactPoll(row: any, maxChars: number): Record<string, unknown> {
  const totalResult = row?.total_results && typeof row.total_results === 'object' ? row.total_results : {};
  return {
    poll_id: row?.id ?? null,
    question: stripHtml(row?.question ?? row?.title ?? '').slice(0, maxChars),
    description: stripHtml(row?.description ?? '').slice(0, maxChars),
    created_at: row?.created_at ?? null,
    user_id: row?.user_id ?? null,
    total_result_count: Object.keys(totalResult).length,
    total_result: totalResult,
    key: keySample(row),
  };
}

function compactPollChoice(row: any, maxChars: number): Record<string, unknown> {
  return {
    poll_choice_id: row?.id ?? null,
    poll_id: row?.poll_id ?? null,
    text: stripHtml(row?.text ?? '').slice(0, maxChars),
    position: row?.position ?? null,
    key: keySample(row),
  };
}

function compactPollSession(row: any, maxSubmission: number): Record<string, unknown> {
  const result = row?.results && typeof row.results === 'object' ? row.results : {};
  const submission = limitRow(unwrapCanvasArray(row?.poll_submissions, 'poll_submissions'), maxSubmission);
  return {
    poll_session_id: row?.id ?? null,
    poll_id: row?.poll_id ?? null,
    course_id: row?.course_id ?? null,
    course_section_id: row?.course_section_id ?? null,
    is_published: row?.is_published ?? null,
    has_public_result: row?.has_public_results ?? null,
    created_at: row?.created_at ?? null,
    result_count: Object.keys(result).length,
    result,
    visible_submission_count: unwrapCanvasArray(row?.poll_submissions, 'poll_submissions').length,
    submission: submission.map(compactPollSubmission),
    key: keySample(row),
  };
}

function compactCommunicationChannel(row: any): Record<string, unknown> {
  return {
    communication_channel_id: row?.id ?? null,
    address: row?.address ?? null,
    type: row?.type ?? null,
    position: row?.position ?? null,
    user_id: row?.user_id ?? null,
    bounce_count: row?.bounce_count ?? null,
    last_bounce_at: row?.last_bounce_at ?? null,
    workflow_state: row?.workflow_state ?? null,
    key: keySample(row),
  };
}

function compactNotificationPreference(row: any): Record<string, unknown> {
  return {
    notification: row?.notification ?? null,
    category: row?.category ?? null,
    frequency: row?.frequency ?? null,
    href: row?.href ?? null,
    key: keySample(row),
  };
}

function compactNotificationCategory(row: any): Record<string, unknown> {
  if (typeof row === 'string') {
    return { category: row, key: [] };
  }
  return {
    category: row?.category ?? row?.name ?? row?.id ?? null,
    notification_count: Array.isArray(row?.notifications) ? row.notifications.length : null,
    key: keySample(row),
  };
}

function compactCommMessage(row: any, maxChar: number): Record<string, unknown> {
  const text = stripHtml(`${row?.subject ?? ''}\n${row?.body ?? ''}\n${row?.html_body ?? ''}`);
  const deadlineCandidate = evidenceMatch(text, [['deadline', DEADLINE_RE], ['device_or_onsite', DEVICE_RE]]);
  const firstEvidence = deadlineCandidate.find((one: any) => one?.evidence)?.evidence;
  return {
    comm_message_id: row?.id ?? null,
    created_at: row?.created_at ?? null,
    sent_at: row?.sent_at ?? null,
    workflow_state: row?.workflow_state ?? null,
    from_name: row?.from_name ?? null,
    subject: stripHtml(row?.subject).slice(0, Math.max(0, Math.min(maxChar, 240))),
    deadline_candidate: deadlineCandidate,
    excerpt: firstEvidence ? String(firstEvidence).slice(0, maxChar) : null,
    key: keySample(row),
  };
}

function compactLatePolicy(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  const policy = row?.late_policy ?? row;
  if (!policy || typeof policy !== 'object') return null;
  return {
    late_policy_id: policy?.id ?? null,
    course_id: policy?.course_id ?? null,
    is_missing_submission_deduction_enabled: policy?.missing_submission_deduction_enabled ?? null,
    missing_submission_deduction: policy?.missing_submission_deduction ?? null,
    is_late_submission_deduction_enabled: policy?.late_submission_deduction_enabled ?? null,
    late_submission_deduction: policy?.late_submission_deduction ?? null,
    late_submission_interval: policy?.late_submission_interval ?? null,
    is_late_submission_minimum_percent_enabled: policy?.late_submission_minimum_percent_enabled ?? null,
    late_submission_minimum_percent: policy?.late_submission_minimum_percent ?? null,
    created_at: policy?.created_at ?? null,
    updated_at: policy?.updated_at ?? null,
    key: keySample(policy),
  };
}

function compactFeature(row: any): Record<string, unknown> {
  return {
    feature: row?.feature ?? null,
    display_name: row?.display_name ?? null,
    applies_to: row?.applies_to ?? null,
    state: row?.feature_flag?.state ?? row?.state ?? null,
    context_id: row?.feature_flag?.context_id ?? row?.context_id ?? null,
    context_type: row?.feature_flag?.context_type ?? row?.context_type ?? null,
    is_locked: row?.feature_flag?.locked ?? row?.locked ?? null,
    is_beta: row?.beta ?? null,
    is_early_access_program: row?.early_access_program ?? null,
    is_root_opt_in: row?.root_opt_in ?? null,
    release_notes_url: row?.release_notes_url ?? null,
    key: keySample(row),
  };
}

function compactCspToolDomain(row: any): Record<string, unknown> {
  const tool = row?.tool ?? row?.external_tool ?? row;
  return {
    domain: row?.domain ?? row?.host ?? null,
    tool_id: tool?.id ?? row?.tool_id ?? null,
    tool_name: tool?.name ?? row?.tool_name ?? null,
    tool_domain: tool?.domain ?? null,
    context_id: tool?.context_id ?? null,
    context_type: tool?.context_type ?? null,
  };
}

function compactCspSetting(row: any, maxDomain = 80): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  const effectiveDomain = limitRow(Array.isArray(row?.effective_whitelist) ? row.effective_whitelist : [], maxDomain)
    .map((domain: any) => String(domain));
  const currentAccountDomain = limitRow(Array.isArray(row?.current_account_whitelist) ? row.current_account_whitelist : [], maxDomain)
    .map((domain: any) => String(domain));
  const toolDomain = limitRow(Array.isArray(row?.tools_whitelist) ? row.tools_whitelist : [], maxDomain);
  return {
    is_enabled: row?.enabled ?? null,
    is_inherited: row?.inherited ?? null,
    is_setting_locked: row?.settings_locked ?? null,
    effective_domain_count: Array.isArray(row?.effective_whitelist) ? row.effective_whitelist.length : 0,
    effective_domain: effectiveDomain,
    current_account_domain_count: Array.isArray(row?.current_account_whitelist) ? row.current_account_whitelist.length : 0,
    current_account_domain: currentAccountDomain,
    tool_domain_count: Array.isArray(row?.tools_whitelist) ? row.tools_whitelist.length : 0,
    tool_domain: toolDomain.map(compactCspToolDomain),
    key: keySample(row),
  };
}

function compactModuleGate(module: any, item: any): Record<string, unknown> {
  return {
    module_id: module?.id ?? null,
    module_name: module?.name ?? null,
    module_item_id: item?.id ?? null,
    assignment_id: item?.content_id ?? null,
    title: item?.title ?? null,
    position: item?.position ?? null,
    completion_requirement: item?.completion_requirement ?? null,
    is_locked: !!item?.locked_for_user,
  };
}

function compactModule(row: any): Record<string, unknown> {
  return {
    module_id: row?.id ?? null,
    name: row?.name ?? null,
    position: row?.position ?? null,
    workflow_state: row?.workflow_state ?? null,
    unlock_at: row?.unlock_at ?? null,
    requirement_type: row?.requirement_type ?? null,
    prerequisite_module_id: Array.isArray(row?.prerequisite_module_ids) ? row.prerequisite_module_ids : [],
    prerequisite_module_count: Array.isArray(row?.prerequisite_module_ids) ? row.prerequisite_module_ids.length : 0,
    require_sequential_progress: !!row?.require_sequential_progress,
    item_count: row?.items_count ?? (Array.isArray(row?.items) ? row.items.length : null),
    state: row?.state ?? null,
    completed_at: row?.completed_at ?? null,
    is_published: row?.published ?? null,
    is_locked_for_user: !!row?.locked_for_user,
    items_url: row?.items_url ?? null,
  };
}

function compactModuleAssignmentOverride(row: any): Record<string, unknown> {
  const student = Array.isArray(row?.students) ? row.students : [];
  const courseSection = row?.course_section ?? null;
  const group = row?.group ?? null;
  return {
    assignment_override_id: row?.id ?? null,
    context_module_id: row?.context_module_id ?? null,
    title: row?.title ?? null,
    student_count: student.length,
    student: student.map((one: any) => ({
      user_id: one?.id ?? null,
      name: one?.name ?? null,
    })),
    course_section: courseSection ? {
      course_section_id: courseSection?.id ?? null,
      name: courseSection?.name ?? null,
    } : null,
    group: group ? {
      group_id: group?.id ?? null,
      name: group?.name ?? null,
    } : null,
    key: keySample(row),
  };
}

function compactModuleItem(row: any, module: any): Record<string, unknown> {
  const contentDetail = row?.content_details ?? {};
  return {
    module_id: module?.id ?? row?.module_id ?? null,
    module_name: module?.name ?? null,
    module_item_id: row?.id ?? null,
    title: row?.title ?? null,
    type: row?.type ?? null,
    content_id: row?.content_id ?? null,
    page_url: row?.page_url ?? null,
    position: row?.position ?? null,
    indent: row?.indent ?? null,
    html_url: row?.html_url ?? null,
    url: row?.url ?? null,
    external_url: row?.external_url ?? null,
    completion_requirement: row?.completion_requirement ?? null,
    content_detail: {
      due_at: contentDetail?.due_at ?? null,
      unlock_at: contentDetail?.unlock_at ?? null,
      lock_at: contentDetail?.lock_at ?? null,
      points_possible: contentDetail?.points_possible ?? null,
      locked_for_user: !!contentDetail?.locked_for_user,
      lock_explanation: contentDetail?.lock_explanation ?? null,
      lock_info_key: keySample(contentDetail?.lock_info),
      require_sequential_progress: !!contentDetail?.require_sequential_progress,
    },
    is_published: row?.published ?? null,
    is_locked_for_user: !!(row?.locked_for_user ?? contentDetail?.locked_for_user),
  };
}

function compactModuleSequenceNode(row: any): Record<string, unknown> | null {
  if (!row) return null;
  const item = row?.item ?? row?.module_item ?? row;
  return {
    module_id: row?.module_id ?? item?.module_id ?? null,
    module_item_id: item?.id ?? row?.id ?? null,
    title: item?.title ?? row?.title ?? null,
    type: item?.type ?? row?.type ?? null,
    content_id: item?.content_id ?? row?.content_id ?? null,
    page_url: item?.page_url ?? row?.page_url ?? null,
    html_url: item?.html_url ?? row?.html_url ?? null,
    url: item?.url ?? row?.url ?? null,
    position: item?.position ?? row?.position ?? null,
    is_locked_for_user: !!(item?.locked_for_user ?? row?.locked_for_user),
    key: keySample(row),
  };
}

function compactModuleItemSequence(row: any): Record<string, unknown> {
  return {
    previous_item: compactModuleSequenceNode(row?.prev ?? row?.previous ?? row?.previous_item),
    current_item: compactModuleSequenceNode(row?.current),
    next_item: compactModuleSequenceNode(row?.next ?? row?.next_item),
    mastery_path: row?.mastery_path ?? row?.mastery_paths ?? null,
    key: keySample(row),
  };
}

function compactRubric(row: any): Record<string, unknown>[] {
  return (Array.isArray(row) ? row : []).map((one: any) => ({
    rubric_id: one?.id ?? null,
    description: one?.description ?? null,
    point: one?.points ?? null,
    rating_count: Array.isArray(one?.ratings) ? one.ratings.length : 0,
  }));
}

function compactRubricCatalog(row: any): Record<string, unknown> {
  const criterion = Array.isArray(row?.data) ? row.data : Array.isArray(row?.criteria) ? row.criteria : [];
  return {
    rubric_id: row?.id ?? null,
    title: row?.title ?? null,
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    points_possible: row?.points_possible ?? null,
    is_reusable: row?.reusable ?? null,
    is_read_only: row?.read_only ?? null,
    is_free_form_criterion_comment: row?.free_form_criterion_comments ?? null,
    is_hide_score_total: row?.hide_score_total ?? null,
    criterion_count: criterion.length,
    assessment_count: Array.isArray(row?.assessments) ? row.assessments.length : null,
    association_count: Array.isArray(row?.associations) ? row.associations.length : null,
    key: keySample(row),
  };
}

function compactRubricUsedLocation(row: any): Record<string, unknown> {
  if (!row || typeof row !== 'object') return {};
  const course = Array.isArray(row?.courses) ? row.courses : [];
  const assignment = Array.isArray(row?.assignments) ? row.assignments : [];
  return {
    course_count: course.length,
    course: limitRow(course, 20).map((one: any) => ({
      course_id: one?.id ?? one?.course_id ?? null,
      name: one?.name ?? null,
      course_code: one?.course_code ?? null,
      workflow_state: one?.workflow_state ?? null,
      key: keySample(one),
    })),
    assignment_count: assignment.length,
    assignment: limitRow(assignment, 40).map((one: any) => ({
      assignment_id: one?.id ?? one?.assignment_id ?? null,
      name: one?.name ?? null,
      due_at: one?.due_at ?? null,
      points_possible: one?.points_possible ?? null,
      workflow_state: one?.workflow_state ?? null,
      key: keySample(one),
    })),
    key: keySample(row),
  };
}

function compactLiveAssessment(row: any, maxChar = 400): Record<string, unknown> {
  return {
    live_assessment_id: row?.id ?? null,
    key: row?.key ? String(row.key).slice(0, maxChar) : null,
    title: row?.title ? String(row.title).slice(0, maxChar) : null,
    outcome_id: row?.links?.outcome ?? row?.outcome_id ?? null,
    result_url: row?.links?.results ?? null,
    row_key: keySample(row),
  };
}

function compactLiveAssessmentResult(row: any): Record<string, unknown> {
  return {
    live_assessment_result_id: row?.id ?? null,
    is_passed: row?.passed ?? null,
    assessed_at: row?.assessed_at ?? null,
    user_id: row?.links?.user ?? row?.user_id ?? null,
    assessor_id: row?.links?.assessor ?? row?.assessor_id ?? null,
    live_assessment_id: row?.links?.assessment ?? row?.assessment_id ?? null,
    key: keySample(row),
  };
}

function compactLearningObjectDate(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    assignment_id: row?.assignment_id ?? row?.id ?? null,
    due_at: row?.due_at ?? null,
    unlock_at: row?.unlock_at ?? null,
    lock_at: row?.lock_at ?? null,
    peer_review_due_at: row?.peer_review_due_at ?? null,
    only_visible_to_overrides: row?.only_visible_to_overrides ?? null,
    all_date_count: Array.isArray(row?.all_dates) ? row.all_dates.length : null,
    override_count: Array.isArray(row?.overrides) ? row.overrides.length : null,
    peer_review_count: Array.isArray(row?.peer_reviews) ? row.peer_reviews.length : null,
    key: keySample(row),
  };
}

function compactAssessmentQuestionBank(row: any): Record<string, unknown> {
  return {
    question_bank_id: row?.id ?? null,
    title: row?.title ?? null,
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    assessment_question_count: row?.assessment_question_count ?? row?.question_count ?? null,
    workflow_state: row?.workflow_state ?? null,
    migration_id: row?.migration_id ?? null,
    key: keySample(row),
  };
}

function compactAssessmentQuestion(row: any, maxChar = 600): Record<string, unknown> {
  const answer = Array.isArray(row?.answers) ? row.answers : [];
  const answerFieldKey = answer.flatMap((one: any) => keySample(one)).filter(Boolean);
  return {
    question_id: row?.id ?? row?.question_id ?? null,
    assessment_question_id: row?.assessment_question_id ?? null,
    question_name: row?.question_name ?? row?.name ?? null,
    question_type: row?.question_type ?? null,
    question_text: stripHtml(row?.question_text ?? '').slice(0, maxChar),
    point: row?.points_possible ?? row?.points ?? null,
    position: row?.position ?? null,
    answer_count: answer.length,
    answer_field_key: [...new Set(answerFieldKey)].slice(0, 30),
    key: keySample(row),
  };
}

function compactOutcomeAlignment(row: any): Record<string, unknown>[] {
  return (Array.isArray(row) ? row : []).map((one: any) => ({
    outcome_id: one?.id ?? one?.outcome?.id ?? null,
    title: one?.title ?? one?.outcome?.title ?? null,
    assignment_id: one?.assignment_id ?? null,
    assessment_id: one?.assessment_id ?? null,
    submission_type: one?.submission_types ?? null,
    url: one?.url ?? null,
  }));
}

function compactOutcomeGroup(row: any, maxChar = 600): Record<string, unknown> {
  const parent = row?.parent_outcome_group ?? {};
  return {
    outcome_group_id: row?.id ?? null,
    title: row?.title ?? null,
    description_text: stripHtml(row?.description ?? '').slice(0, maxChar),
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    parent_outcome_group_id: parent?.id ?? null,
    parent_title: parent?.title ?? null,
    vendor_guid: row?.vendor_guid ?? null,
    can_edit: row?.can_edit ?? null,
    subgroup_url: row?.subgroups_url ?? null,
    outcome_url: row?.outcomes_url ?? null,
  };
}

function compactOutcome(row: any, maxChar = 600): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    outcome_id: row?.id ?? null,
    title: row?.title ?? null,
    description_text: stripHtml(row?.description ?? '').slice(0, maxChar),
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    vendor_guid: row?.vendor_guid ?? null,
    points_possible: row?.points_possible ?? null,
    rating_count: Array.isArray(row?.ratings) ? row.ratings.length : 0,
    can_edit: row?.can_edit ?? null,
    url: row?.url ?? null,
  };
}

function compactOutcomeLink(row: any, maxChar = 600): Record<string, unknown> {
  const outcomeGroup = row?.outcome_group ?? row?.context ?? {};
  return {
    outcome_link_id: row?.id ?? row?.url ?? null,
    url: row?.url ?? null,
    outcome_group_id: outcomeGroup?.id ?? row?.outcome_group_id ?? null,
    outcome_group_title: outcomeGroup?.title ?? null,
    context_id: row?.context_id ?? null,
    context_type: row?.context_type ?? null,
    outcome: compactOutcome(row?.outcome, maxChar),
  };
}

function compactOutcomeResultContainer(value: any): Record<string, unknown> {
  if (!value || typeof value !== 'object') return {};
  const outcomeResult = Array.isArray(value?.outcome_results) ? value.outcome_results : [];
  const linked = value?.linked && typeof value.linked === 'object' ? value.linked : {};
  return {
    outcome_result_count: outcomeResult.length,
    outcome_result: limitRow(outcomeResult.map((one: any) => ({
      outcome_result_id: one?.id ?? null,
      user_id: one?.user_id ?? one?.links?.user ?? null,
      outcome_id: one?.outcome_id ?? one?.links?.learning_outcome ?? null,
      assignment_id: one?.assignment_id ?? one?.links?.assignment ?? null,
      score: one?.score ?? null,
      percent: one?.percent ?? null,
      possible: one?.possible ?? null,
      submitted_or_assessed_at: one?.submitted_or_assessed_at ?? one?.assessed_at ?? null,
      title: one?.title ?? null,
    })), 80),
    linked_key: keySample(linked),
  };
}

function compactOutcomeRollupContainer(value: any): Record<string, unknown> {
  if (!value || typeof value !== 'object') return {};
  const rollup = Array.isArray(value?.rollups) ? value.rollups : [];
  return {
    rollup_count: rollup.length,
    rollup: limitRow(rollup.map((one: any) => ({
      user_id: one?.user_id ?? one?.links?.user ?? null,
      outcome_id: one?.outcome_id ?? one?.links?.outcome ?? one?.links?.learning_outcome ?? null,
      score: one?.score ?? null,
      count: one?.count ?? null,
      mastery_count: one?.mastery_count ?? null,
      mastery: one?.mastery ?? null,
    })), 80),
    meta_key: keySample(value?.meta),
  };
}

function compactOutcomeProficiency(value: any): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null;
  const rating = Array.isArray(value?.ratings) ? value.ratings : [];
  return {
    rating_count: rating.length,
    rating: rating.map((one: any) => ({
      description: one?.description ?? null,
      points: one?.points ?? null,
      is_mastery: !!one?.mastery,
      color: one?.color ?? null,
    })),
  };
}

function compactSubmissionComment(row: any, maxChar = 300): Record<string, unknown> {
  return {
    comment_id: row?.id ?? null,
    author_id: row?.author_id ?? row?.author?.id ?? null,
    author_name: row?.author_name ?? row?.author?.display_name ?? row?.author?.name ?? null,
    created_at: row?.created_at ?? null,
    edited_at: row?.edited_at ?? null,
    media_comment_id: row?.media_comment_id ?? null,
    media_comment_type: row?.media_comment_type ?? null,
    attachment_count: Array.isArray(row?.attachments) ? row.attachments.length : 0,
    comment_text: stripHtml(row?.comment ?? row?.body ?? '').slice(0, maxChar),
  };
}

function compactRubricAssessment(row: any): Record<string, unknown>[] {
  if (!row || typeof row !== 'object') return [];
  return Object.entries(row).map(([criterionId, value]: [string, any]) => ({
    criterion_id: criterionId,
    point: value?.points ?? null,
    rating_id: value?.rating_id ?? null,
    assessor_id: value?.assessor_id ?? null,
    comments: value?.comments ?? null,
    comments_enabled: value?.comments_enabled ?? null,
  }));
}

function compactModeratedStudent(row: any): Record<string, unknown> {
  return {
    user_id: row?.id ?? row?.user_id ?? row?.student_id ?? null,
    display_name: row?.display_name ?? row?.name ?? null,
    sortable_name: row?.sortable_name ?? null,
    avatar_url: row?.avatar_url ?? null,
    html_url: row?.html_url ?? null,
    pronoun: row?.pronouns ?? null,
    key: keySample(row),
  };
}

function compactProvisionalGradeStatus(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    assignment_id: row?.assignment_id ?? null,
    student_id: row?.student_id ?? row?.user_id ?? null,
    anonymous_id: row?.anonymous_id ?? null,
    selected_provisional_grade_id: row?.selected_provisional_grade_id ?? null,
    needs_provisional_grade: row?.needs_provisional_grade ?? null,
    key: keySample(row),
  };
}

function compactSubmissionHistory(row: any): Record<string, unknown> {
  return {
    submission_id: row?.id ?? null,
    attempt: row?.attempt ?? null,
    workflow_state: row?.workflow_state ?? null,
    submitted_at: row?.submitted_at ?? null,
    late: !!row?.late,
    missing: !!row?.missing,
    grade: row?.grade ?? null,
    score: row?.score ?? null,
    submission_type: row?.submission_type ?? null,
    attachment_count: Array.isArray(row?.attachments) ? row.attachments.length : 0,
  };
}

function compactPeerReview(row: any, maxCommentChar = 240): Record<string, unknown> {
  const comment = Array.isArray(row?.submission_comments)
    ? row.submission_comments
    : Array.isArray(row?.submission_comment)
      ? row.submission_comment
      : [];
  return {
    peer_review_id: row?.id ?? null,
    assessor_id: row?.assessor_id ?? null,
    user_id: row?.user_id ?? null,
    asset_id: row?.asset_id ?? null,
    asset_type: row?.asset_type ?? null,
    workflow_state: row?.workflow_state ?? null,
    is_completed: row?.workflow_state === 'completed',
    user: row?.user ? {
      user_id: row.user?.id ?? null,
      display_name: row.user?.display_name ?? row.user?.name ?? null,
      html_url: row.user?.html_url ?? null,
    } : null,
    assessor: row?.assessor ? {
      user_id: row.assessor?.id ?? null,
      display_name: row.assessor?.display_name ?? row.assessor?.name ?? null,
      html_url: row.assessor?.html_url ?? null,
    } : null,
    comment_count: comment.length,
    comment: comment.map((one: any) => ({
      comment_id: one?.id ?? null,
      author_id: one?.author_id ?? null,
      created_at: one?.created_at ?? null,
      edited_at: one?.edited_at ?? null,
      comment_text: stripHtml(one?.comment ?? one?.body ?? '').slice(0, maxCommentChar),
    })),
  };
}

function compactQuizSubmission(row: any): Record<string, unknown> | null {
  const submission = Array.isArray(row?.quiz_submissions) ? row.quiz_submissions[0] : row?.quiz_submission ?? row;
  if (!submission || typeof submission !== 'object') return null;
  return {
    quiz_submission_id: submission.id ?? null,
    quiz_id: submission.quiz_id ?? null,
    submission_id: submission.submission_id ?? null,
    workflow_state: submission.workflow_state ?? null,
    started_at: submission.started_at ?? null,
    finished_at: submission.finished_at ?? null,
    end_at: submission.end_at ?? null,
    attempt: submission.attempt ?? null,
    score: submission.score ?? null,
    kept_score: submission.kept_score ?? null,
    is_overdue_and_needs_submission: !!submission.overdue_and_needs_submission,
  };
}

function quizSubmissionList(row: any): any[] {
  if (Array.isArray(row)) return row;
  if (Array.isArray(row?.quiz_submissions)) return row.quiz_submissions;
  if (row?.quiz_submission) return [row.quiz_submission];
  if (row && typeof row === 'object') return [row];
  return [];
}

function compactQuiz(row: any): Record<string, unknown> | null {
  if (!row || typeof row !== 'object') return null;
  return {
    quiz_id: row?.id ?? null,
    title: row?.title ?? null,
    quiz_type: row?.quiz_type ?? null,
    assignment_id: row?.assignment_id ?? null,
    html_url: row?.html_url ?? null,
    mobile_url: row?.mobile_url ?? null,
    due_at: row?.due_at ?? null,
    unlock_at: row?.unlock_at ?? null,
    lock_at: row?.lock_at ?? null,
    points_possible: row?.points_possible ?? null,
    question_count: row?.question_count ?? null,
    time_limit_minute: row?.time_limit ?? null,
    allowed_attempt_count: row?.allowed_attempts ?? null,
    is_published: !!row?.published,
    is_locked_for_user: !!row?.locked_for_user,
    workflow_state: row?.workflow_state ?? null,
    lock_info: row?.lock_info ?? null,
  };
}

function compactNewQuiz(row: any, maxChar = 500): Record<string, unknown> {
  return {
    new_quiz_id: row?.id ?? null,
    assignment_id: row?.assignment_id ?? row?.id ?? null,
    title: row?.title ?? row?.name ?? null,
    instructions_text: stripHtml(row?.instructions ?? row?.description ?? '').slice(0, maxChar),
    assignment_group_id: row?.assignment_group_id ?? null,
    points_possible: row?.points_possible ?? null,
    grading_type: row?.grading_type ?? null,
    due_at: row?.due_at ?? null,
    unlock_at: row?.unlock_at ?? null,
    lock_at: row?.lock_at ?? null,
    is_published: row?.published ?? null,
    quiz_setting_key: keySample(row?.quiz_settings),
    link: extractEmbeds(row?.instructions ?? row?.description, { type: 'new-quiz', id: row?.id, title: row?.title ?? row?.name }),
  };
}

function compactNewQuizItem(row: any, maxChar = 500): Record<string, unknown> {
  const entry = row?.entry ?? row?.item_body ?? row?.body ?? {};
  const content = row?.content ?? entry?.content ?? row?.prompt ?? row?.stimulus ?? row?.title ?? '';
  return {
    item_id: row?.id ?? null,
    position: row?.position ?? null,
    item_type: row?.item_type ?? row?.type ?? null,
    title: row?.title ?? entry?.title ?? null,
    points_possible: row?.points_possible ?? entry?.points_possible ?? null,
    entry_type: entry?.type ?? null,
    content_text: stripHtml(content).slice(0, maxChar),
    answer_count: Array.isArray(row?.answers) ? row.answers.length : Array.isArray(entry?.answers) ? entry.answers.length : null,
    link: extractEmbeds(content, { type: 'new-quiz-item', id: row?.id, title: row?.title ?? entry?.title }),
    key: keySample(row),
  };
}

function compactLtiLineItem(row: any, maxChar = 500): Record<string, unknown> {
  return {
    line_item_id: row?.id ?? null,
    label: row?.label ?? null,
    resource_id: row?.resourceId ?? row?.resource_id ?? null,
    resource_link_id: row?.resourceLinkId ?? row?.resource_link_id ?? null,
    tag: row?.tag ?? null,
    score_maximum: row?.scoreMaximum ?? row?.score_maximum ?? null,
    start_date_time: row?.startDateTime ?? row?.start_date_time ?? null,
    end_date_time: row?.endDateTime ?? row?.end_date_time ?? null,
    submission_review_url: row?.submissionReview?.url ?? row?.submission_review_url ?? null,
    launch_url: row?.['https://purl.imsglobal.org/spec/lti/claim/target_link_uri'] ?? row?.url ?? null,
    description_text: stripHtml(row?.description ?? '').slice(0, maxChar),
    key: keySample(row),
  };
}

function compactQuizQuestion(row: any): Record<string, unknown> {
  return {
    question_id: row?.id ?? null,
    question_name: row?.question_name ?? null,
    question_type: row?.question_type ?? null,
    position: row?.position ?? null,
    point: row?.points_possible ?? null,
    answer_count: Array.isArray(row?.answers) ? row.answers.length : null,
    has_question_text: !!stripHtml(row?.question_text),
    link: extractEmbeds(row?.question_text, { type: 'quiz-question', id: row?.id, title: row?.question_name }),
  };
}

function compactQuizQuestionGroup(row: any): Record<string, unknown> {
  return {
    quiz_question_group_id: row?.id ?? null,
    quiz_id: row?.quiz_id ?? null,
    name: row?.name ?? null,
    pick_count: row?.pick_count ?? null,
    question_point: row?.question_points ?? null,
    assessment_question_bank_id: row?.assessment_question_bank_id ?? null,
    position: row?.position ?? null,
    key: keySample(row),
  };
}

function compactQuizAssignmentOverride(row: any): Record<string, unknown> {
  const dueDate = Array.isArray(row?.due_dates) ? row.due_dates : [];
  const allDate = Array.isArray(row?.all_dates) ? row.all_dates : [];
  return {
    quiz_id: row?.quiz_id ?? null,
    due_date_count: dueDate.length,
    all_date_count: allDate.length,
    due_date: dueDate.map((one: any) => ({
      override_id: one?.id ?? null,
      due_at: one?.due_at ?? null,
      unlock_at: one?.unlock_at ?? null,
      lock_at: one?.lock_at ?? null,
      title: one?.title ?? null,
      is_base: !!one?.base,
    })),
    all_date: allDate.map((one: any) => ({
      override_id: one?.id ?? null,
      due_at: one?.due_at ?? null,
      unlock_at: one?.unlock_at ?? null,
      lock_at: one?.lock_at ?? null,
      title: one?.title ?? null,
      is_base: !!one?.base,
    })),
  };
}

function compactQuizIpFilter(row: any): Record<string, unknown> {
  return {
    name: row?.name ?? null,
    account: row?.account ?? null,
    has_filter: !!row?.filter,
    key: keySample(row),
  };
}

function compactQuizReport(row: any): Record<string, unknown> {
  return {
    report_id: row?.id ?? null,
    quiz_id: row?.quiz_id ?? null,
    report_type: row?.report_type ?? null,
    readable_type: row?.readable_type ?? null,
    is_all_version_included: row?.includes_all_versions ?? null,
    is_anonymous: row?.anonymous ?? null,
    is_generatable: row?.generatable ?? null,
    created_at: row?.created_at ?? null,
    updated_at: row?.updated_at ?? null,
    has_file: !!row?.file,
    has_progress: !!row?.progress || !!row?.progress_url,
    workflow_state: row?.progress?.workflow_state ?? null,
    key: keySample(row),
  };
}

function compactQuizStatistic(row: any): Record<string, unknown> {
  const statistic = Array.isArray(row?.quiz_statistics) ? row.quiz_statistics[0] : row;
  const submissionStatistic = statistic?.submission_statistics ?? null;
  return {
    statistic_id: statistic?.id ?? null,
    quiz_id: statistic?.quiz_id ?? null,
    generated_at: statistic?.generated_at ?? null,
    is_all_version_included: statistic?.includes_all_versions ?? null,
    is_multiple_attempt_exist: statistic?.multiple_attempts_exist ?? null,
    question_statistic_count: Array.isArray(statistic?.question_statistics) ? statistic.question_statistics.length : null,
    submission_statistic_key: keySample(submissionStatistic),
    unique_count: submissionStatistic?.unique_count ?? null,
    score_average: submissionStatistic?.score_average ?? null,
    score_high: submissionStatistic?.score_high ?? null,
    score_low: submissionStatistic?.score_low ?? null,
    duration_average: submissionStatistic?.duration_average ?? null,
    key: keySample(statistic),
  };
}

function compactQuizSubmissionQuestion(row: any): Record<string, unknown> {
  return {
    question_id: row?.id ?? row?.quiz_question_id ?? null,
    is_flagged: row?.flagged ?? null,
    has_answer: row?.answer !== undefined && row?.answer !== null && row?.answer !== '',
    answer_kind: Array.isArray(row?.answer) ? 'array' : row?.answer && typeof row.answer === 'object' ? 'object' : typeof row?.answer,
    answer_key_count: row?.answer && typeof row.answer === 'object' && !Array.isArray(row.answer) ? Object.keys(row.answer).length : null,
    possible_answer_count: Array.isArray(row?.answers) ? row.answers.length : null,
    quiz_question: row?.quiz_question ? compactQuizQuestion(row.quiz_question) : null,
    key: keySample(row),
  };
}

const READING_RE = /\b(read(?:ing)?|article|chapter|pages?|pp\.|watch|view|review|slides?|handout|pdf|docx|document|material|reference|resource|module|lesson)\b/i;
const REPLY_RE = /\b(reply|respond|comment|discussion|forum|peer response|reaction|post(?:ing)?|thread)\b/i;
const GROUP_WORK_RE = /\b(group|team|partner|collaborat(?:e|ion|ive)|peer|member)\b/i;
const INITIAL_POST_RE = /\b(initial post|first post|post first|before seeing replies|must post before|reply before viewing)\b/i;
const PEER_REPLY_RE = /\b(peer (?:reply|response|comment)|reply to (?:at least )?\d+|respond to (?:at least )?\d+|comment on (?:at least )?\d+|classmate|groupmate)\b/i;
const SUBMIT_RE = /\b(submit|upload|turn in|attach|submission|deliverable|final output|draft|outline|essay|reflection|worksheet|file)\b/i;
const DEVICE_RE = /\b(laptop|tablet|phone|device|onsite|in class|during class|canvas quiz)\b/i;
const FILE_EXPECTATION_RE: Array<[string, RegExp]> = [
  ['pdf', /\bpdf\b/i],
  ['docx', /\bdocx?|word document|ms word\b/i],
  ['presentation', /\bpptx?|slides?|presentation\b/i],
  ['spreadsheet', /\bxlsx?|spreadsheet|sheet\b/i],
  ['image', /\bphoto|picture|screenshot|image|jpeg|jpg|png\b/i],
  ['video', /\bvideo|mp4|recording\b/i],
  ['audio', /\baudio|mp3|voice recording\b/i],
  ['link', /\blink|url|google doc|google drive|gdocs|gdrive\b/i],
];
const REQUIREMENT_PATTERN: Array<[string, RegExp]> = [
  ['reading', READING_RE],
  ['reply', REPLY_RE],
  ['initial_post', INITIAL_POST_RE],
  ['peer_reply', PEER_REPLY_RE],
  ['group_work', GROUP_WORK_RE],
  ['submission', SUBMIT_RE],
  ['deadline', DEADLINE_RE],
  ['device_or_onsite', DEVICE_RE],
];

function fileType(row: any): string | null {
  const mime = String(row?.['content-type'] ?? row?.content_type ?? '').toLowerCase();
  const name = String(row?.display_name ?? row?.filename ?? row?.url ?? '').toLowerCase();
  if (mime.includes('pdf') || name.endsWith('.pdf')) return 'pdf';
  if (mime.includes('word') || name.endsWith('.docx') || name.endsWith('.doc')) return 'docx';
  if (mime.includes('presentation') || name.endsWith('.pptx') || name.endsWith('.ppt')) return 'presentation';
  if (mime.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg)$/i.test(name)) return 'image';
  if (mime.startsWith('video/') || /\.(mp4|mov|m4v|webm)$/i.test(name)) return 'video';
  if (mime.startsWith('audio/') || /\.(mp3|m4a|wav)$/i.test(name)) return 'audio';
  if (mime.includes('html') || /\.html?$/i.test(name)) return 'html';
  if (mime.includes('text') || /\.(txt|md)$/i.test(name)) return 'text';
  if (mime.includes('csv') || name.endsWith('.csv')) return 'csv';
  if (mime.includes('json') || name.endsWith('.json')) return 'json';
  if (mime) return mime;
  const extension = name.match(/\.([a-z0-9]+)(?:\?|$)/i)?.[1];
  return extension ?? null;
}

function uniqueText(value: Array<string | null | undefined>): string[] {
  return [...new Set(value.filter((one): one is string => !!one))];
}

function asArray(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function evidenceFor(text: string, regex: RegExp): string | null {
  return excerptAround(text, regex, 220);
}

function evidenceMatch(text: string, pattern: Array<[string, RegExp]>): Record<string, unknown>[] {
  return pattern.flatMap(([tag, regex]) => {
    const evidence = evidenceFor(text, regex);
    return evidence ? [{ tag, evidence }] : [];
  });
}

function submissionExpectation(text: string, submissionType: string[], link: any[], fileId: string[]): Record<string, unknown> {
  const expectedFileType = uniqueText(FILE_EXPECTATION_RE
    .filter(([, regex]) => regex.test(text))
    .map(([tag]) => tag));
  const onlineType = new Set(submissionType.map((one) => String(one)));
  return {
    submission_type: submissionType,
    expected_file_type: expectedFileType,
    is_upload_expected: onlineType.has('online_upload') || expectedFileType.length > 0 || fileId.length > 0,
    is_text_expected: onlineType.has('online_text_entry') || /\b(text entry|write in canvas|type your|short answer)\b/i.test(text),
    is_url_expected: onlineType.has('online_url') || expectedFileType.includes('link') || link.some((one) => ['gdocs', 'gdrive', 'gsheets', 'gslides'].includes(String(one?.kind))),
    is_quiz_like: onlineType.has('online_quiz') || /\bquiz|test|exam\b/i.test(text),
    evidence: evidenceFor(text, SUBMIT_RE),
  };
}

function materialSignal(text: string, link: any[], fileId: string[], explicit: {
  is_group?: boolean;
  is_discussion?: boolean;
  submission_type?: string[];
} = {}): Record<string, unknown> {
  const clean = stripHtml(text);
  const submissionType = explicit.submission_type ?? [];
  const requirementTag = evidenceMatch(clean, REQUIREMENT_PATTERN);
  const isReading = READING_RE.test(clean) || link.some((one) => (
    ['pdf', 'gdocs', 'gslides', 'youtube', 'canvas-file'].includes(String(one?.kind))
  )) || fileId.length > 0;
  const promptRequirement = requirementFromPrompt(clean);
  const isPeerReply = promptRequirement.some((one) => one.requirement_kind === 'peer_reply');
  const isInitialPost = promptRequirement.some((one) => one.requirement_kind === 'initial_post');
  const isReplyRequired = promptRequirement.some((one) => (
    one.requirement_kind === 'peer_reply'
    || one.requirement_kind === 'comment'
    || one.requirement_kind === 'feedback'
    || one.requirement_kind === 'initial_post'
  ));
  const isGroupWork = !!explicit.is_group || GROUP_WORK_RE.test(clean);
  return {
    requirement_tag: requirementTag,
    submission_expectation: submissionExpectation(clean, submissionType, link, fileId),
    reading: {
      is_reading: isReading,
      evidence: evidenceFor(clean, READING_RE),
      link_count: link.length,
      file_count: fileId.length,
    },
    reply_requirement: {
      is_required: isReplyRequired,
      evidence: promptRequirement.find((one) => (
        one.requirement_kind === 'peer_reply'
        || one.requirement_kind === 'comment'
        || one.requirement_kind === 'feedback'
        || one.requirement_kind === 'initial_post'
      ))?.evidence ?? null,
      kind: isPeerReply ? 'peer_reply' : isInitialPost ? 'initial_post' : isReplyRequired ? 'comment_or_feedback' : null,
      confidence: isReplyRequired ? 'prompt' : 'none',
      requirement: promptRequirement,
    },
    work_mode: {
      is_group: isGroupWork,
      evidence: evidenceFor(clean, GROUP_WORK_RE),
      confidence: explicit.is_group ? 'canvas_assignment' : GROUP_WORK_RE.test(clean) ? 'prompt' : 'none',
    },
    deadline: {
      evidence: evidenceFor(clean, DEADLINE_RE),
      tag: evidenceMatch(clean, [['deadline', DEADLINE_RE], ['device_or_onsite', DEVICE_RE]]),
    },
  };
}

function materialFileType(fileId: string[], fileById: Map<string, any>): string[] {
  return uniqueText(fileId.map((one) => fileType(fileById.get(String(one)))));
}

async function fillFileById(fileById: Map<string, any>, fileId: string[]): Promise<void> {
  const missingFileId = uniqueText(fileId.map((one) => String(one)))
    .filter((one) => !fileById.has(one));
  const fetchedFile = await pool(missingFileId, async (one) => {
    const result = await safe(() => canvasGet(`/files/${one}`));
    return { file_id: one, file: result.value, error: result.error };
  }, 4);
  for (const one of fetchedFile) {
    if (one.file) fileById.set(String(one.file_id), one.file);
  }
}

async function readingIndexForMaterial(material: Record<string, unknown>[], fileById: Map<string, any>, option: {
  extract_reading?: boolean;
  extract_material_id?: string[];
  max_extract_file?: number;
  max_chars?: number;
}): Promise<Record<string, unknown>[]> {
  const extractMaterialId = new Set((option.extract_material_id ?? []).map((one) => String(one)));
  const maxExtractFile = Math.max(0, Number(option.max_extract_file ?? 8));
  const maxChar = Number(option.max_chars ?? 1200);
  let extractedCount = 0;
  const row: Record<string, unknown>[] = [];
  const sortedMaterial = [...material].sort((a: any, b: any) => {
    const aPriority = extractMaterialId.has(String(a.material_id)) ? 0 : 1;
    const bPriority = extractMaterialId.has(String(b.material_id)) ? 0 : 1;
    return aPriority - bPriority;
  });

  for (const item of sortedMaterial as any[]) {
    if (!item?.reading?.is_reading) continue;
    for (const id of uniqueText(asArray(item.file_id).map((one: any) => String(one)))) {
      const file = fileById.get(String(id));
      const shouldExtract = !!option.extract_reading
        && extractedCount < maxExtractFile
        && (extractMaterialId.size === 0 || extractMaterialId.has(String(item.material_id)));
      if (shouldExtract) {
        const extracted = await safe(() => extractFileText({ file_id: id, max_chars: maxChar }));
        extractedCount += 1;
        row.push({
          material_id: item.material_id,
          source_surface: item.source_surface ?? item.item_type ?? null,
          source_title: item.title ?? null,
          reading_source_type: 'canvas-file',
          file_id: id,
          file_name: (extracted.value as any)?.file?.display_name ?? (extracted.value as any)?.file?.filename ?? file?.display_name ?? file?.filename ?? null,
          file_type: fileType((extracted.value as any)?.file ?? file),
          extraction_mode: (extracted.value as any)?.extraction ?? 'error',
          extracted_char_count: typeof (extracted.value as any)?.text === 'string' ? (extracted.value as any).text.length : 0,
          is_truncated: !!(extracted.value as any)?.truncated,
          error: extracted.error,
        });
        continue;
      }
      row.push({
        material_id: item.material_id,
        source_surface: item.source_surface ?? item.item_type ?? null,
        source_title: item.title ?? null,
        reading_source_type: 'canvas-file',
        file_id: id,
        file_name: file?.display_name ?? file?.filename ?? null,
        file_type: fileType(file),
        extraction_mode: option.extract_reading ? 'metadata-only' : 'not-requested',
        extracted_char_count: 0,
        is_truncated: false,
        error: file ? null : 'file metadata unavailable',
      });
    }
    for (const link of asArray(item.link) as any[]) {
      if (String(link?.kind) === 'canvas-file') continue;
      row.push({
        material_id: item.material_id,
        source_surface: item.source_surface ?? item.item_type ?? null,
        source_title: item.title ?? null,
        reading_source_type: 'external-link',
        kind: link?.kind ?? 'external',
        url: link?.url ?? null,
        extraction_mode: 'external-link',
        extracted_char_count: 0,
        is_truncated: false,
        error: null,
      });
    }
  }
  return row;
}

async function getCourseGroupContext(args: {
  course_id?: string | number;
  group_id?: string[];
  include_member?: boolean;
  include_workspace?: boolean;
  include_page_body?: boolean;
  extract_file?: boolean;
  max_group?: number;
  max_member?: number;
  max_file?: number;
  max_page?: number;
  max_discussion?: number;
  max_activity?: number;
  max_membership?: number;
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeMember = args.include_member !== false;
  const includeWorkspace = args.include_workspace !== false;
  const includePageBody = args.include_page_body !== false;
  const requestedGroupId = new Set((args.group_id ?? []).map((one) => String(one)));
  const maxGroup = Math.max(0, Number(args.max_group ?? 10));
  const maxMember = Math.max(0, Number(args.max_member ?? 20));
  const maxFile = Math.max(0, Number(args.max_file ?? 50));
  const maxPage = Math.max(0, Number(args.max_page ?? 30));
  const maxDiscussion = Math.max(0, Number(args.max_discussion ?? 30));
  const maxActivity = Math.max(0, Number(args.max_activity ?? 30));
  const maxMembership = Math.max(0, Number(args.max_membership ?? 40));
  const maxExtractFile = Math.max(0, Number(args.max_extract_file ?? 6));
  const maxChar = Number(args.max_chars ?? 1200);
  const [selfGroup, courseGroup] = await Promise.all([
    safe(() => canvasPaginate<any>('/users/self/groups', {
      context_type: 'Course',
      'include[]': 'tabs',
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/groups`, {
      only_own_groups: true,
      'include[]': 'tabs',
    })),
  ]);
  const ownGroupRaw = [
    ...((selfGroup.value as any[]) ?? []),
    ...((courseGroup.value as any[]) ?? []),
  ].filter((one: any) => String(one?.course_id ?? '') === String(id));
  const groupById = new Map<string, any>();
  for (const one of ownGroupRaw) {
    if (one?.id === undefined || one?.id === null) continue;
    groupById.set(String(one.id), { ...groupById.get(String(one.id)), ...one });
  }
  const selectedGroup = limitRow([...groupById.values()]
    .filter((one: any) => requestedGroupId.size === 0 || requestedGroupId.has(String(one?.id))), maxGroup);

  const workspace = await pool(selectedGroup, async (one: any) => {
    const groupId = String(one.id);
    const [detail, tab, permission, membership, selfMembership, member, file, folder, pageStub, discussionStub, activity, activitySummary] = await Promise.all([
      safe(() => canvasGet(`/groups/${groupId}`, { 'include[]': 'permissions' })),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/tabs`))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasGet(`/groups/${groupId}/permissions`, {
          'permissions[]': ['read_roster', 'send_messages_all', 'create_discussion_topic', 'create_announcement'],
        }))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/memberships`))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasGet(`/groups/${groupId}/users/self`))
        : Promise.resolve({ value: null, error: null }),
      includeMember
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/users`, { 'include[]': 'avatar_url' }))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/files`, { 'include[]': 'usage_rights' }))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/folders`))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/pages`))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/discussion_topics`))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/activity_stream`))
        : Promise.resolve({ value: null, error: null }),
      includeWorkspace
        ? safe(() => canvasPaginate<any>(`/groups/${groupId}/activity_stream/summary`))
        : Promise.resolve({ value: null, error: null }),
    ]);
    const pageStubValue = limitRow((pageStub.value as any[]) ?? [], maxPage);
    const pageBody = includeWorkspace && includePageBody
      ? await pool(pageStubValue, async (page: any) => {
        const url = page?.url ?? page?.page_url;
        if (!url) return { page, error: 'page url unavailable' };
        const result = await safe(() => canvasGet(`/groups/${groupId}/pages/${encodeURIComponent(String(url))}`));
        return { page: result.value ?? page, error: result.error };
      }, 4)
      : pageStubValue.map((page: any) => ({ page, error: null }));
    const discussionValue = limitRow((discussionStub.value as any[]) ?? [], maxDiscussion);
    const fileValue = limitRow((file.value as any[]) ?? [], maxFile);
    const tabValue = limitRow((tab.value as any[]) ?? [], 40);
    const membershipValue = limitRow((membership.value as any[]) ?? [], maxMembership);
    const activityValue = limitRow((activity.value as any[]) ?? [], maxActivity);
    const folderValue = (folder.value as any[]) ?? [];
    const folderById = new Map(folderValue.map((folderRow: any) => [String(folderRow?.id), folderRow]));
    const groupDescription = String((detail.value as any)?.description ?? one?.description ?? '');
    const groupLink = extractEmbeds(groupDescription, { type: 'group', id: groupId, title: one?.name });
    const groupFileId = extractFileId(groupDescription);
    const groupSignal = materialSignal(groupDescription, groupLink, groupFileId, { is_group: true });
    const page = pageBody.map((pageResult: any) => {
      const row = pageResult.page ?? {};
      const text = stripHtml(row?.body ?? '');
      const link = extractEmbeds(row?.body, { type: 'group-page', id: row?.url ?? row?.page_id, title: row?.title });
      const fileId = extractFileId(row?.body);
      const signal = materialSignal(text, link, fileId, { is_group: true });
      return {
        ...compactPage(row),
        status: pageResult.error ? endpointStatus(pageResult.error) : 'ok',
        error: pageResult.error,
        file_id: fileId,
        link,
        requirement_tag: signal.requirement_tag,
        submission_expectation: signal.submission_expectation,
        reading: signal.reading,
        reply_requirement: signal.reply_requirement,
        work_mode: signal.work_mode,
        deadline: signal.deadline,
        body_text: includePageBody ? text.slice(0, maxChar) : null,
        body_truncated: includePageBody ? text.length > maxChar : null,
      };
    });
    const discussion = discussionValue.map((row: any) => {
      const text = stripHtml(row?.message ?? '');
      const link = extractEmbeds(row?.message, { type: 'group-discussion', id: row?.id, title: row?.title });
      const fileId = extractFileId(row?.message);
      const signal = materialSignal(text, link, fileId, { is_group: true, is_discussion: true });
      return {
        ...compactGroupDiscussion(row),
        file_id: fileId,
        link,
        requirement_tag: signal.requirement_tag,
        submission_expectation: signal.submission_expectation,
        reading: signal.reading,
        reply_requirement: signal.reply_requirement,
        work_mode: signal.work_mode,
        deadline: signal.deadline,
        message_text: text.slice(0, maxChar),
        message_truncated: text.length > maxChar,
      };
    });
    const fileId = uniqueText([
      ...groupFileId,
      ...page.flatMap((row: any) => row.file_id ?? []),
      ...discussion.flatMap((row: any) => row.file_id ?? []),
      ...fileValue.map((row: any) => row?.id ? String(row.id) : null),
    ]);
    return {
      group: {
        ...compactGroup({ ...one, ...((detail.value as any) ?? {}) }),
        description_text: stripHtml(groupDescription).slice(0, maxChar),
        description_truncated: stripHtml(groupDescription).length > maxChar,
        requirement_tag: groupSignal.requirement_tag,
        reading: groupSignal.reading,
        reply_requirement: groupSignal.reply_requirement,
        work_mode: groupSignal.work_mode,
        deadline: groupSignal.deadline,
      },
      endpoint: [
        ['detail', detail],
        ['tab', tab],
        ['permission', permission],
        ['membership', membership],
        ['self_membership', selfMembership],
        ['member', member],
        ['file', file],
        ['folder', folder],
        ['page', pageStub],
        ['discussion', discussionStub],
        ['activity', activity],
        ['activity_summary', activitySummary],
      ].map(([name, result]) => {
        const item = result as { value: unknown; error: string | null };
        return {
          name,
          status: item.error ? endpointStatus(item.error) : 'ok',
          count: rowCount(item.value),
          key: keySample(item.value),
          error: item.error,
        };
      }),
      tab_status: tab.error ? endpointStatus(tab.error) : includeWorkspace ? 'ok' : 'skipped',
      tab_count: rowCount(tab.value),
      tab: tabValue.map(compactTab),
      permission_status: permission.error ? endpointStatus(permission.error) : includeWorkspace ? 'ok' : 'skipped',
      permission: compactGroupPermission(permission.value),
      membership_status: membership.error ? endpointStatus(membership.error) : includeWorkspace ? 'ok' : 'skipped',
      membership_count: rowCount(membership.value),
      membership: membershipValue.map(compactGroupMembership),
      self_membership_status: selfMembership.error ? endpointStatus(selfMembership.error) : includeWorkspace ? 'ok' : 'skipped',
      self_membership: selfMembership.value ? compactGroupMembership(selfMembership.value) : null,
      member_status: member.error ? endpointStatus(member.error) : includeMember ? 'ok' : 'skipped',
      member_count: rowCount(member.value),
      member: limitRow(((member.value as any[]) ?? []).map(compactGroupMember), maxMember),
      file_count: rowCount(file.value),
      file: fileValue.map((fileRow: any) => compactFile(fileRow, folderById)),
      folder_count: rowCount(folder.value),
      folder: limitRow(folderValue.map(compactFolder), maxFile),
      page_count: rowCount(pageStub.value),
      page,
      discussion_count: rowCount(discussionStub.value),
      discussion,
      activity_status: activity.error ? endpointStatus(activity.error) : includeWorkspace ? 'ok' : 'skipped',
      activity_count: rowCount(activity.value),
      activity: activityValue.map(compactActivity),
      activity_summary_status: activitySummary.error ? endpointStatus(activitySummary.error) : includeWorkspace ? 'ok' : 'skipped',
      activity_summary_count: rowCount(activitySummary.value),
      activity_summary: limitRow((activitySummary.value as any[]) ?? [], 20),
      file_id: fileId,
      reading_count: [
        groupSignal.reading,
        ...page.map((row: any) => row.reading),
        ...discussion.map((row: any) => row.reading),
      ].filter((row: any) => row?.is_reading).length,
      reply_requirement_count: [
        groupSignal.reply_requirement,
        ...page.map((row: any) => row.reply_requirement),
        ...discussion.map((row: any) => row.reply_requirement),
      ].filter((row: any) => row?.is_required).length,
    };
  }, 3);

  const allFileId = uniqueText(workspace.flatMap((one: any) => one.file_id ?? []));
  const extractionTarget = limitRow(allFileId, maxExtractFile);
  const extraction = args.extract_file
    ? await pool(extractionTarget, async (one) => {
      const result = await safe(() => extractFileText({ file_id: one, max_chars: maxChar }));
      return {
        file_id: one,
        extraction_mode: (result.value as any)?.extraction ?? (result.error ? 'error' : 'metadata-only'),
        text: (result.value as any)?.text ?? null,
        link: (result.value as any)?.link ?? [],
        error: result.error,
      };
    }, 3)
    : extractionTarget.map((one) => ({
      file_id: one,
      extraction_mode: 'not-requested',
      text: null,
      link: [],
      error: null,
    }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      ['self_group', selfGroup],
      ['course_group', courseGroup],
    ].map(([name, result]) => {
      const item = result as { value: unknown; error: string | null };
      return {
        name,
        status: item.error ? endpointStatus(item.error) : 'ok',
        count: rowCount(item.value),
        key: keySample(item.value),
        error: item.error,
      };
    }),
    own_group_status: selfGroup.error || courseGroup.error ? endpointStatus(selfGroup.error ?? courseGroup.error) : 'ok',
    own_group_count: selectedGroup.length,
    workspace_group_count: workspace.length,
    tab_count: workspace.reduce((sum: number, one: any) => sum + Number(one.tab_count ?? 0), 0),
    membership_count: workspace.reduce((sum: number, one: any) => sum + Number(one.membership_count ?? 0), 0),
    member_count: workspace.reduce((sum: number, one: any) => sum + Number(one.member_count ?? 0), 0),
    file_count: workspace.reduce((sum: number, one: any) => sum + Number(one.file_count ?? 0), 0),
    folder_count: workspace.reduce((sum: number, one: any) => sum + Number(one.folder_count ?? 0), 0),
    page_count: workspace.reduce((sum: number, one: any) => sum + Number(one.page_count ?? 0), 0),
    discussion_count: workspace.reduce((sum: number, one: any) => sum + Number(one.discussion_count ?? 0), 0),
    activity_count: workspace.reduce((sum: number, one: any) => sum + Number(one.activity_count ?? 0), 0),
    activity_summary_count: workspace.reduce((sum: number, one: any) => sum + Number(one.activity_summary_count ?? 0), 0),
    reading_count: workspace.reduce((sum: number, one: any) => sum + Number(one.reading_count ?? 0), 0),
    reply_requirement_count: workspace.reduce((sum: number, one: any) => sum + Number(one.reply_requirement_count ?? 0), 0),
    file_id: allFileId,
    extracted_file_count: extraction.filter((one: any) => !['metadata-only', 'not-requested', 'error'].includes(String(one?.extraction_mode))).length,
    extraction,
    workspace,
  };
}

async function getCourseCalendarContext(args: {
  course_id?: string | number;
  start_date?: string;
  end_date?: string;
  include_event_detail?: boolean;
  include_group_calendar?: boolean;
  extract_file?: boolean;
  max_event?: number;
  max_detail?: number;
  max_appointment_group?: number;
  max_appointment_user?: number;
  max_appointment_group_participant?: number;
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const now = new Date();
  const startDate = args.start_date ?? dateOffset(now, -30);
  const endDate = args.end_date ?? dateOffset(now, 60);
  const includeEventDetail = args.include_event_detail !== false;
  const includeGroupCalendar = args.include_group_calendar !== false;
  const maxEvent = Math.max(0, Number(args.max_event ?? 80));
  const maxDetail = Math.max(0, Number(args.max_detail ?? 20));
  const maxAppointmentGroup = Math.max(0, Number(args.max_appointment_group ?? 30));
  const maxAppointmentUser = Math.max(0, Number(args.max_appointment_user ?? 40));
  const maxAppointmentGroupParticipant = Math.max(0, Number(args.max_appointment_group_participant ?? 40));
  const maxExtractFile = Math.max(0, Number(args.max_extract_file ?? 6));
  const maxChar = Number(args.max_chars ?? 1200);
  const courseContext = `course_${id}`;
  const ownGroup = includeGroupCalendar
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/groups`, {
      only_own_groups: true,
      'include[]': 'tabs',
    }))
    : { value: null, error: null };
  const groupContext = ((ownGroup.value as any[]) ?? [])
    .map((one: any) => one?.id ? `group_${one.id}` : null)
    .filter(Boolean);
  const contextCode = limitRow(uniqueText([courseContext, ...groupContext]), 10);
  const [courseEvent, assignmentEvent, appointmentGroup, timetable] = await Promise.all([
    safe(() => canvasPaginate<any>('/calendar_events', {
      type: 'event',
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': contextCode,
      'includes[]': ['web_conference', 'series_natural_language'],
    })),
    safe(() => canvasPaginate<any>('/calendar_events', {
      type: 'assignment',
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': contextCode,
      'includes[]': ['web_conference', 'series_natural_language'],
    })),
    safe(() => canvasPaginate<any>('/appointment_groups', {
      scope: 'reservable',
      'context_codes[]': courseContext,
      'include[]': ['appointments', 'reserved_times', 'participant_count'],
    })),
    safe(() => canvasGet(`/courses/${id}/calendar_events/timetable`)),
  ]);
  const eventSource = limitRow([
    ...((courseEvent.value as any[]) ?? []),
    ...((assignmentEvent.value as any[]) ?? []),
  ], maxEvent);
  const detailTarget = includeEventDetail
    ? limitRow(eventSource.filter((one: any) => /^\d+$/.test(String(one?.id ?? ''))), maxDetail)
    : [];
  const detail = includeEventDetail
    ? await pool(detailTarget, async (one: any) => {
      const result = await safe(() => canvasGet(`/calendar_events/${one.id}`));
      return { event_id: one?.id ?? null, value: result.value, error: result.error };
    }, 4)
    : [];
  const detailById = new Map(detail.map((one: any) => [String(one.event_id), one]));
  const event = eventSource.map((source: any) => {
    const detailRow = detailById.get(String(source?.id));
    const row = (detailRow?.value as any) ?? source;
    const text = stripHtml(row?.description ?? row?.assignment?.description ?? '');
    const link = extractEmbeds(row?.description ?? row?.assignment?.description, { type: 'calendar-event', id: row?.id, title: row?.title });
    const fileId = extractFileId(row?.description ?? row?.assignment?.description);
    const signal = materialSignal([
      row?.title,
      row?.location_name,
      row?.location_address,
      row?.series_natural_language,
      text,
    ].filter(Boolean).join(' '), link, fileId, {
      submission_type: Array.isArray(row?.assignment?.submission_types) ? row.assignment.submission_types : [],
    });
    return {
      ...compactCalendarEvent(row),
      status: detailRow?.error ? endpointStatus(detailRow.error) : 'ok',
      detail_error: detailRow?.error ?? null,
      file_id: fileId,
      link,
      requirement_tag: signal.requirement_tag,
      submission_expectation: signal.submission_expectation,
      reading: signal.reading,
      reply_requirement: signal.reply_requirement,
      work_mode: signal.work_mode,
      deadline: signal.deadline,
      description_text: text.slice(0, maxChar),
      description_truncated: text.length > maxChar,
    };
  });
  const appointment = limitRow(((appointmentGroup.value as any[]) ?? []), maxAppointmentGroup).map((row: any) => {
    const text = stripHtml(row?.description ?? row?.comments ?? '');
    const link = extractEmbeds(row?.description ?? row?.comments, { type: 'appointment-group', id: row?.id, title: row?.title });
    const fileId = extractFileId(row?.description ?? row?.comments);
    const signal = materialSignal([
      row?.title,
      row?.location_name,
      row?.location_address,
      text,
    ].filter(Boolean).join(' '), link, fileId);
    return {
      ...compactAppointmentGroup(row),
      file_id: fileId,
      link,
      requirement_tag: signal.requirement_tag,
      reading: signal.reading,
      reply_requirement: signal.reply_requirement,
      deadline: signal.deadline,
      description_text: text.slice(0, maxChar),
      description_truncated: text.length > maxChar,
    };
  });
  const selectedAppointmentGroupRow = (appointment as any[]).find((one: any) => one.appointment_group_id);
  const selectedAppointmentGroupId = selectedAppointmentGroupRow?.appointment_group_id
    ? String(selectedAppointmentGroupRow.appointment_group_id)
    : null;
  const [appointmentGroupDetail, appointmentUser, appointmentGroupParticipant, nextAppointment] = selectedAppointmentGroupId
    ? await Promise.all([
      safe(() => canvasGet(`/appointment_groups/${selectedAppointmentGroupId}`, {
        'include[]': ['appointments', 'child_events', 'all_context_codes'],
      })),
      safe(() => canvasPaginate<any>(`/appointment_groups/${selectedAppointmentGroupId}/users`, {
        registration_status: 'all',
      })),
      safe(() => canvasPaginate<any>(`/appointment_groups/${selectedAppointmentGroupId}/groups`, {
        registration_status: 'all',
      })),
      safe(() => canvasPaginate<any>('/appointment_groups/next_appointment', {
        'appointment_group_ids[]': selectedAppointmentGroupId,
      })),
    ])
    : [
      { value: null, error: 'no appointment group visible for selected course' },
      { value: null, error: 'no appointment group visible for selected course' },
      { value: null, error: 'no appointment group visible for selected course' },
      { value: null, error: 'no appointment group visible for selected course' },
    ];
  const appointmentUserValue = limitRow((appointmentUser.value as any[]) ?? [], maxAppointmentUser);
  const appointmentGroupParticipantValue = limitRow((appointmentGroupParticipant.value as any[]) ?? [], maxAppointmentGroupParticipant);
  const nextAppointmentValue = limitRow((nextAppointment.value as any[]) ?? [], 10);
  const fileId = uniqueText([
    ...event.flatMap((one: any) => one.file_id ?? []),
    ...appointment.flatMap((one: any) => one.file_id ?? []),
  ]);
  const extractionTarget = limitRow(fileId, maxExtractFile);
  const extraction = args.extract_file
    ? await pool(extractionTarget, async (one) => {
      const result = await safe(() => extractFileText({ file_id: one, max_chars: maxChar }));
      return {
        file_id: one,
        extraction_mode: (result.value as any)?.extraction ?? (result.error ? 'error' : 'metadata-only'),
        text: (result.value as any)?.text ?? null,
        link: (result.value as any)?.link ?? [],
        error: result.error,
      };
    }, 3)
    : extractionTarget.map((one) => ({
      file_id: one,
      extraction_mode: 'not-requested',
      text: null,
      link: [],
      error: null,
    }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    date_window: { start_date: startDate, end_date: endDate },
    context_code: contextCode,
    endpoint: [
      ['own_group', ownGroup],
      ['course_event', courseEvent],
      ['assignment_event', assignmentEvent],
      ['appointment_group', appointmentGroup],
      ['appointment_group_detail', appointmentGroupDetail],
      ['appointment_user', appointmentUser],
      ['appointment_group_participant', appointmentGroupParticipant],
      ['next_appointment', nextAppointment],
      ['timetable', timetable],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('no appointment group visible') ? 'skipped' : (one.error ? endpointStatus(one.error) : 'ok'),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    calendar_status: courseEvent.error || assignmentEvent.error ? endpointStatus(courseEvent.error ?? assignmentEvent.error) : 'ok',
    event_count: event.length,
    course_event_count: rowCount(courseEvent.value),
    assignment_event_count: rowCount(assignmentEvent.value),
    detail_count: detail.length,
    appointment_group_status: appointmentGroup.error ? endpointStatus(appointmentGroup.error) : 'ok',
    appointment_group_count: appointment.length,
    requiring_action_appointment_count: appointment.filter((one: any) => one.is_requiring_action).length,
    appointment_group_detail_status: appointmentGroupDetail.error?.includes('no appointment group visible') ? 'skipped' : (appointmentGroupDetail.error ? endpointStatus(appointmentGroupDetail.error) : 'ok'),
    appointment_group_detail: appointmentGroupDetail.error ? null : compactAppointmentGroup(appointmentGroupDetail.value),
    appointment_user_status: appointmentUser.error?.includes('no appointment group visible') ? 'skipped' : (appointmentUser.error ? endpointStatus(appointmentUser.error) : 'ok'),
    appointment_user_count: rowCount(appointmentUser.value),
    returned_appointment_user_count: appointmentUserValue.length,
    appointment_user: appointmentUserValue.map(compactUser),
    appointment_group_participant_status: appointmentGroupParticipant.error?.includes('no appointment group visible') ? 'skipped' : (appointmentGroupParticipant.error ? endpointStatus(appointmentGroupParticipant.error) : 'ok'),
    appointment_group_participant_count: rowCount(appointmentGroupParticipant.value),
    returned_appointment_group_participant_count: appointmentGroupParticipantValue.length,
    appointment_group_participant: appointmentGroupParticipantValue.map(compactGroup),
    next_appointment_status: nextAppointment.error?.includes('no appointment group visible') ? 'skipped' : (nextAppointment.error ? endpointStatus(nextAppointment.error) : 'ok'),
    next_appointment_count: rowCount(nextAppointment.value),
    next_appointment: nextAppointmentValue.map(compactCalendarEvent),
    important_date_count: event.filter((one: any) => one.is_important_date).length,
    blackout_date_count: event.filter((one: any) => one.is_blackout_date).length,
    reservation_count: event.filter((one: any) => one.is_reserved || one.is_own_reservation).length,
    reading_event_count: event.filter((one: any) => one?.reading?.is_reading).length,
    reply_requirement_count: event.filter((one: any) => one?.reply_requirement?.is_required).length,
    deadline_signal_count: event.filter((one: any) => Array.isArray(one?.requirement_tag) && one.requirement_tag.some((tag: any) => tag?.tag === 'deadline')).length,
    device_signal_count: event.filter((one: any) => Array.isArray(one?.requirement_tag) && one.requirement_tag.some((tag: any) => tag?.tag === 'device_or_onsite')).length,
    file_count: fileId.length,
    extracted_file_count: extraction.filter((one: any) => !['metadata-only', 'not-requested', 'error'].includes(String(one?.extraction_mode))).length,
    timetable_status: timetable.error ? endpointStatus(timetable.error) : 'ok',
    timetable_key: keySample(timetable.value),
    extraction,
    event,
    appointment_group: appointment,
  };
}

async function getCourseFileContext(args: {
  course_id?: string | number;
  include_folder_file?: boolean;
  max_folder?: number;
  max_file?: number;
  extract_file?: boolean;
  extract_file_id?: string[];
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxFolder = Math.max(0, Number(args.max_folder ?? 100));
  const maxFile = Math.max(0, Number(args.max_file ?? 200));
  const includeFolderFile = args.include_folder_file !== false;
  const extractFileId = new Set((args.extract_file_id ?? []).map((one) => String(one)));
  const maxExtractFile = Math.max(0, Number(args.max_extract_file ?? 6));
  const maxChar = Number(args.max_chars ?? 1200);

  const [rootFolder, folder, file, license] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/folders/root`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/folders`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/files`, { 'include[]': ['user', 'usage_rights'] })),
    safe(() => canvasPaginate<any>(`/courses/${id}/content_licenses`)),
  ]);

  const folderValue = limitRow((folder.value as any[]) ?? [], maxFolder);
  const folderById = new Map(folderValue.map((one: any) => [String(one?.id), one]));
  if ((rootFolder.value as any)?.id) folderById.set(String((rootFolder.value as any).id), rootFolder.value);
  const fileValue = limitRow((file.value as any[]) ?? [], maxFile);
  const fileId = new Set(fileValue.map((one: any) => String(one?.id)).filter(Boolean));
  const requestedFile = await pool([...extractFileId].filter((one) => !fileId.has(one)), async (one) => {
    const result = await safe(() => canvasGet(`/files/${one}`));
    return result.value;
  }, 4);
  const combinedFile = [
    ...fileValue,
    ...requestedFile.filter((one: any) => one?.id),
  ];
  const selectedFile = combinedFile.find((one: any) => one?.id) ?? null;
  const selectedFileId = selectedFile?.id ? String(selectedFile.id) : null;
  const [fileDetail, filePublicUrl, fileIconMetadata] = selectedFileId
    ? await Promise.all([
      safe(() => canvasGet(`/courses/${id}/files/${selectedFileId}`, { 'include[]': ['user', 'usage_rights'] })),
      safe(() => canvasGet(`/files/${selectedFileId}/public_url`)),
      safe(() => canvasGet(`/files/${selectedFileId}/icon_metadata`)),
    ])
    : [
      { value: null, error: 'no course file visible in selected course' },
      { value: null, error: 'no course file visible in selected course' },
      { value: null, error: 'no course file visible in selected course' },
    ];
  const readingFile = combinedFile
    .map((one: any) => compactFile(one, folderById))
    .filter((one: any) => one.is_reading_like);

  const sortedFile = [...combinedFile].sort((a: any, b: any) => {
    const aPriority = extractFileId.has(String(a?.id)) ? 0 : 1;
    const bPriority = extractFileId.has(String(b?.id)) ? 0 : 1;
    return aPriority - bPriority;
  });
  let extractedCount = 0;
  const extraction = [];
  for (const one of sortedFile) {
    const compact = compactFile(one, folderById) as any;
    const shouldExtract = !!args.extract_file
      && compact.is_reading_like
      && extractedCount < maxExtractFile
      && (extractFileId.size === 0 || extractFileId.has(String(one?.id)));
    if (!shouldExtract) continue;
    const extracted = await safe(() => extractFileText({ file_id: one.id, max_chars: maxChar }));
    extractedCount += 1;
    extraction.push({
      file_id: one?.id ?? null,
      display_name: one?.display_name ?? one?.filename ?? null,
      file_type: compact.file_type,
      folder_id: compact.folder_id,
      folder_name: compact.folder_name,
      extraction_mode: (extracted.value as any)?.extraction ?? 'error',
      extracted_char_count: typeof (extracted.value as any)?.text === 'string' ? (extracted.value as any).text.length : 0,
      is_truncated: !!(extracted.value as any)?.truncated,
      link: (extracted.value as any)?.link ?? [],
      error: extracted.error,
    });
  }

  const folderFile = includeFolderFile
    ? await pool(folderValue.slice(0, Math.min(folderValue.length, 25)), async (one: any) => {
      const result = await safe(() => canvasPaginate<any>(`/folders/${one.id}/files`, { 'include[]': 'usage_rights' }));
      return {
        folder_id: one?.id ?? null,
        folder_name: one?.full_name ?? one?.name ?? null,
        status: result.error ? endpointStatus(result.error) : 'ok',
        file_count: rowCount(result.value),
        file: limitRow(((result.value as any[]) ?? []).map((item: any) => compactFile(item, folderById)), 20),
        error: result.error,
      };
    }, 4)
    : [];

  const endpoint = [
    ['root_folder', rootFolder],
    ['folder', folder],
    ['file', file],
    ['file_detail', fileDetail],
    ['file_public_url', filePublicUrl],
    ['file_icon_metadata', fileIconMetadata],
    ['content_license', license],
  ].map(([name, result]) => {
    const one = result as { value: unknown; error: string | null };
    return {
      name,
      status: one.error?.includes('no course file visible') ? 'skipped' : endpointStatus(one.error),
      count: rowCount(one.value),
      key: keySample(one.value),
      error: one.error,
    };
  });

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint,
    root_folder: rootFolder.value ? compactFolder(rootFolder.value) : null,
    folder_count: rowCount(folder.value),
    returned_folder_count: folderValue.length,
    file_count: rowCount(file.value),
    returned_file_count: fileValue.length,
    reading_file_count: readingFile.length,
    extracted_file_count: extraction.length,
    file_detail_status: fileDetail.error?.includes('no course file visible') ? 'skipped' : (fileDetail.error ? endpointStatus(fileDetail.error) : 'ok'),
    file_detail: fileDetail.error ? null : compactFile(fileDetail.value, folderById),
    file_public_url_status: filePublicUrl.error?.includes('no course file visible') ? 'skipped' : (filePublicUrl.error ? endpointStatus(filePublicUrl.error) : 'ok'),
    file_public_url: filePublicUrl.error ? null : compactFilePublicUrl(filePublicUrl.value),
    file_icon_metadata_status: fileIconMetadata.error?.includes('no course file visible') ? 'skipped' : (fileIconMetadata.error ? endpointStatus(fileIconMetadata.error) : 'ok'),
    file_icon_metadata_key: keySample(fileIconMetadata.value),
    folder: folderValue.map(compactFolder),
    file: combinedFile.map((one: any) => compactFile(one, folderById)),
    reading_file: readingFile,
    extraction,
    folder_file: folderFile,
    license_status: license.error ? endpointStatus(license.error) : 'ok',
    license_count: rowCount(license.value),
    license: limitRow(((license.value as any[]) ?? []).map((one: any) => ({
      license_id: one?.id ?? null,
      name: one?.name ?? null,
      url: one?.url ?? null,
    })), 50),
  };
}

async function getCourseModuleContext(args: {
  course_id?: string | number;
  include_student_progress?: boolean;
  include_item_detail?: boolean;
  include_override?: boolean;
  extract_file?: boolean;
  max_module?: number;
  max_item?: number;
  max_override?: number;
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeStudentProgress = args.include_student_progress !== false;
  const includeItemDetail = args.include_item_detail !== false;
  const includeOverride = args.include_override !== false;
  const maxModule = Math.max(0, Number(args.max_module ?? 80));
  const maxItem = Math.max(0, Number(args.max_item ?? 250));
  const maxOverride = Math.max(0, Number(args.max_override ?? 80));
  const maxExtractFile = Math.max(0, Number(args.max_extract_file ?? 6));
  const maxChar = Number(args.max_chars ?? 1200);
  const self = includeStudentProgress
    ? await safe(() => canvasGet('/users/self'))
    : { value: null, error: null };
  const userId = (self.value as any)?.id ?? null;
  const module = await safe(() => canvasPaginate<any>(`/courses/${id}/modules`, {
    'include[]': ['items', 'content_details'],
    ...(includeStudentProgress && userId ? { student_id: userId } : {}),
  }));
  const moduleValue = limitRow((module.value as any[]) ?? [], maxModule);
  const inlineItem = moduleValue.flatMap((one: any) => (
    Array.isArray(one?.items)
      ? one.items.map((item: any) => ({ module: one, item }))
      : []
  ));
  const moduleWithoutInlineItem = moduleValue.filter((one: any) => !Array.isArray(one?.items));
  const fetchedItem = includeItemDetail
    ? await pool(moduleWithoutInlineItem, async (one: any) => {
      const result = await safe(() => canvasPaginate<any>(`/courses/${id}/modules/${one.id}/items`, {
        'include[]': 'content_details',
        ...(includeStudentProgress && userId ? { student_id: userId } : {}),
      }));
      return {
        module: one,
        status: result.error ? endpointStatus(result.error) : 'ok',
        error: result.error,
        item: ((result.value as any[]) ?? []).map((item: any) => ({ module: one, item })),
      };
    }, 4)
    : [];
  const moduleOverrideResult = includeOverride
    ? await pool(moduleValue, async (one: any) => {
      const result = await safe(() => canvasPaginate<any>(`/courses/${id}/modules/${one.id}/assignment_overrides`));
      return {
        module: one,
        status: result.error ? endpointStatus(result.error) : 'ok',
        error: result.error,
        override: ((result.value as any[]) ?? []).map((override: any) => ({ module: one, override })),
      };
    }, 4)
    : [];
  const itemPair = limitRow([
    ...inlineItem,
    ...fetchedItem.flatMap((one: any) => one.item),
  ], maxItem);
  const moduleOverridePair = limitRow(moduleOverrideResult.flatMap((one: any) => one.override), maxOverride);
  const moduleOverride = moduleOverridePair.map(({ module: rowModule, override }: any) => ({
    module_id: rowModule?.id ?? override?.context_module_id ?? null,
    module_name: rowModule?.name ?? null,
    ...compactModuleAssignmentOverride(override),
  }));
  const item = itemPair.map(({ module: itemModule, item: row }: any) => {
    const text = [
      row?.title,
      row?.content_details?.description,
      row?.content_details?.lock_explanation,
      row?.completion_requirement?.type,
      row?.html_url,
      row?.url,
      row?.external_url,
    ].filter(Boolean).join(' ');
    const link = [row?.html_url, row?.url, row?.external_url].filter(Boolean).map((url: string) => ({
      kind: classify(url),
      url,
      source: { type: 'module_item', id: row?.id, title: row?.title },
    }));
    const fileId = row?.type === 'File' && row?.content_id ? [String(row.content_id)] : extractFileId(text);
    const signal = materialSignal(text, link, fileId, {
      is_discussion: row?.type === 'Discussion',
      submission_type: row?.type === 'Quiz' ? ['online_quiz'] : row?.type === 'Assignment' ? ['assignment'] : [],
    });
    return {
      ...compactModuleItem(row, itemModule),
      file_id: fileId,
      link,
      requirement_tag: signal.requirement_tag,
      submission_expectation: signal.submission_expectation,
      reading: signal.reading,
      reply_requirement: signal.reply_requirement,
      work_mode: signal.work_mode,
      deadline: signal.deadline,
      item_text: stripHtml(text).slice(0, maxChar),
      item_text_truncated: stripHtml(text).length > maxChar,
    };
  });
  const fileId = uniqueText(item.flatMap((one: any) => one.file_id ?? []));
  const extractionTarget = limitRow(fileId, maxExtractFile);
  const extraction = args.extract_file
    ? await pool(extractionTarget, async (one) => {
      const result = await safe(() => extractFileText({ file_id: one, max_chars: maxChar }));
      return {
        file_id: one,
        extraction_mode: (result.value as any)?.extraction ?? (result.error ? 'error' : 'metadata-only'),
        text: (result.value as any)?.text ?? null,
        link: (result.value as any)?.link ?? [],
        error: result.error,
      };
    }, 3)
    : extractionTarget.map((one) => ({
      file_id: one,
      extraction_mode: 'not-requested',
      text: null,
      link: [],
      error: null,
    }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId ? String(userId) : null,
    endpoint: [
      {
        name: 'self',
        status: self.error ? endpointStatus(self.error) : includeStudentProgress ? 'ok' : 'skipped',
        count: rowCount(self.value),
        key: keySample(self.value),
        error: self.error,
      },
      {
        name: 'module',
        status: module.error ? endpointStatus(module.error) : 'ok',
        count: rowCount(module.value),
        key: keySample(module.value),
        error: module.error,
      },
      ...fetchedItem.map((one: any) => ({
        name: `module_item:${one.module?.id ?? 'unknown'}`,
        status: one.status,
        count: one.item.length,
        key: one.item.length > 0 ? keySample(one.item[0]?.item) : [],
        error: one.error,
      })),
      ...moduleOverrideResult.map((one: any) => ({
        name: `module_override:${one.module?.id ?? 'unknown'}`,
        status: one.status,
        count: one.override.length,
        key: one.override.length > 0 ? keySample(one.override[0]?.override) : [],
        error: one.error,
      })),
    ],
    module_status: module.error ? endpointStatus(module.error) : 'ok',
    module_count: moduleValue.length,
    returned_item_count: item.length,
    item_count: inlineItem.length + fetchedItem.reduce((sum: number, one: any) => sum + one.item.length, 0),
    module_override_status: !includeOverride
      ? 'skipped'
      : moduleOverrideResult.some((one: any) => one.status === 'error')
        ? 'error'
        : moduleOverrideResult.some((one: any) => one.status === 'ok')
          ? 'ok'
          : moduleOverrideResult.some((one: any) => one.status === 'blocked_or_absent')
            ? 'blocked_or_absent'
            : 'skipped',
    module_override_count: moduleOverrideResult.reduce((sum: number, one: any) => sum + one.override.length, 0),
    returned_module_override_count: moduleOverride.length,
    locked_module_count: moduleValue.filter((one: any) => one?.state === 'locked' || one?.locked_for_user).length,
    completed_module_count: moduleValue.filter((one: any) => one?.state === 'completed' || one?.completed_at).length,
    sequential_module_count: moduleValue.filter((one: any) => one?.require_sequential_progress).length,
    prerequisite_module_count: moduleValue.filter((one: any) => Array.isArray(one?.prerequisite_module_ids) && one.prerequisite_module_ids.length > 0).length,
    requirement_item_count: item.filter((one: any) => one?.completion_requirement).length,
    locked_item_count: item.filter((one: any) => one?.is_locked_for_user || one?.content_detail?.locked_for_user).length,
    reading_item_count: item.filter((one: any) => one?.reading?.is_reading).length,
    reply_requirement_count: item.filter((one: any) => one?.reply_requirement?.is_required).length,
    deadline_signal_count: item.filter((one: any) => Array.isArray(one?.requirement_tag) && one.requirement_tag.some((tag: any) => tag?.tag === 'deadline')).length,
    device_signal_count: item.filter((one: any) => Array.isArray(one?.requirement_tag) && one.requirement_tag.some((tag: any) => tag?.tag === 'device_or_onsite')).length,
    file_count: fileId.length,
    extracted_file_count: extraction.filter((one: any) => !['metadata-only', 'not-requested', 'error'].includes(String(one?.extraction_mode))).length,
    extraction,
    module: moduleValue.map(compactModule),
    module_override: moduleOverride,
    item,
  };
}

async function getUserFileContext(args: {
  include_folder_file?: boolean;
  max_folder?: number;
  max_file?: number;
  extract_file?: boolean;
  extract_file_id?: string[];
  max_extract_file?: number;
  max_chars?: number;
} = {}): Promise<unknown> {
  const maxFolder = Math.max(0, Number(args.max_folder ?? 100));
  const maxFile = Math.max(0, Number(args.max_file ?? 200));
  const includeFolderFile = args.include_folder_file !== false;
  const extractFileId = new Set((args.extract_file_id ?? []).map((one) => String(one)));
  const maxExtractFile = Math.max(0, Number(args.max_extract_file ?? 3));
  const maxChar = Number(args.max_chars ?? 1200);

  const [rootFolder, folder, file, quota] = await Promise.all([
    safe(() => canvasGet('/users/self/folders/root')),
    safe(() => canvasPaginate<any>('/users/self/folders')),
    safe(() => canvasPaginate<any>('/users/self/files', { 'include[]': ['user', 'usage_rights'] })),
    safe(() => canvasGet('/users/self/files/quota')),
  ]);

  const folderValue = limitRow((folder.value as any[]) ?? [], maxFolder);
  const folderById = new Map(folderValue.map((one: any) => [String(one?.id), one]));
  if ((rootFolder.value as any)?.id) folderById.set(String((rootFolder.value as any).id), rootFolder.value);
  const fileValue = limitRow((file.value as any[]) ?? [], maxFile);
  const fileId = new Set(fileValue.map((one: any) => String(one?.id)).filter(Boolean));
  const requestedFile = await pool([...extractFileId].filter((one) => !fileId.has(one)), async (one) => {
    const result = await safe(() => canvasGet(`/files/${one}`));
    return result.value;
  }, 4);
  const combinedFile = [
    ...fileValue,
    ...requestedFile.filter((one: any) => one?.id),
  ];
  const readingFile = combinedFile
    .map((one: any) => compactFile(one, folderById))
    .filter((one: any) => one.is_reading_like);

  const sortedFile = [...combinedFile].sort((a: any, b: any) => {
    const aPriority = extractFileId.has(String(a?.id)) ? 0 : 1;
    const bPriority = extractFileId.has(String(b?.id)) ? 0 : 1;
    return aPriority - bPriority;
  });
  let extractedCount = 0;
  const extraction = [];
  for (const one of sortedFile) {
    const compact = compactFile(one, folderById) as any;
    const shouldExtract = !!args.extract_file
      && compact.is_reading_like
      && extractedCount < maxExtractFile
      && (extractFileId.size === 0 || extractFileId.has(String(one?.id)));
    if (!shouldExtract) continue;
    const extracted = await safe(() => extractFileText({ file_id: one.id, max_chars: maxChar }));
    extractedCount += 1;
    extraction.push({
      file_id: one?.id ?? null,
      display_name: one?.display_name ?? one?.filename ?? null,
      file_type: compact.file_type,
      folder_id: compact.folder_id,
      folder_name: compact.folder_name,
      extraction_mode: (extracted.value as any)?.extraction ?? 'error',
      extracted_char_count: typeof (extracted.value as any)?.text === 'string' ? (extracted.value as any).text.length : 0,
      is_truncated: !!(extracted.value as any)?.truncated,
      link: (extracted.value as any)?.link ?? [],
      error: extracted.error,
    });
  }

  const folderFile = includeFolderFile
    ? await pool(folderValue.slice(0, Math.min(folderValue.length, 15)), async (one: any) => {
      const result = await safe(() => canvasPaginate<any>(`/folders/${one.id}/files`, { 'include[]': 'usage_rights' }));
      return {
        folder_id: one?.id ?? null,
        folder_name: one?.full_name ?? one?.name ?? null,
        status: result.error ? endpointStatus(result.error) : 'ok',
        file_count: rowCount(result.value),
        file: limitRow(((result.value as any[]) ?? []).map((item: any) => compactFile(item, folderById)), 20),
        error: result.error,
      };
    }, 4)
    : [];

  const endpoint = [
    ['user_root_folder', rootFolder],
    ['user_folder', folder],
    ['user_file', file],
    ['user_file_quota', quota],
  ].map(([name, result]) => {
    const one = result as { value: unknown; error: string | null };
    return {
      name,
      status: endpointStatus(one.error),
      count: rowCount(one.value),
      key: keySample(one.value),
      error: one.error,
    };
  });

  return {
    generated_at: new Date().toISOString(),
    endpoint,
    root_folder_status: rootFolder.error ? endpointStatus(rootFolder.error) : 'ok',
    root_folder: rootFolder.value ? compactFolder(rootFolder.value) : null,
    folder_status: folder.error ? endpointStatus(folder.error) : 'ok',
    folder_count: rowCount(folder.value),
    returned_folder_count: folderValue.length,
    file_status: file.error ? endpointStatus(file.error) : 'ok',
    file_count: rowCount(file.value),
    returned_file_count: fileValue.length,
    reading_file_count: readingFile.length,
    extracted_file_count: extraction.length,
    quota_status: quota.error ? endpointStatus(quota.error) : 'ok',
    quota: compactFileQuota(quota.value),
    folder: folderValue.map(compactFolder),
    file: combinedFile.map((one: any) => compactFile(one, folderById)),
    reading_file: readingFile,
    extraction,
    folder_file: folderFile,
    note: 'Current-user file context is read-only. It lists user-owned Canvas files/folders/quota and never creates folders, uploads files, copies files, deletes files, or changes usage rights.',
  };
}

async function getUserEportfolioContext(args: {
  eportfolio_id?: string | number;
  include_page?: boolean;
  max_eportfolio?: number;
  max_page?: number;
  max_chars?: number;
} = {}): Promise<unknown> {
  const includePage = args.include_page !== false;
  const maxEportfolio = Math.max(0, Number(args.max_eportfolio ?? 20));
  const maxPage = Math.max(0, Number(args.max_page ?? 50));
  const maxChar = Number(args.max_chars ?? 1000);
  const user = await safe(() => canvasGet('/users/self'));
  const userId = user.error ? 'self' : String((user.value as any)?.id ?? 'self');
  const eportfolio = await safe(() => canvasPaginate<any>(`/users/${userId}/eportfolios`));
  const eportfolioValue = limitRow((eportfolio.value as any[]) ?? [], maxEportfolio);
  const requestedEportfolio = args.eportfolio_id
    && !eportfolioValue.some((one: any) => String(one?.id) === String(args.eportfolio_id))
    ? await safe(() => canvasGet(`/eportfolios/${args.eportfolio_id}`))
    : { value: null, error: null };
  const eportfolioSource = [
    ...eportfolioValue,
    ...((requestedEportfolio.value as any)?.id ? [requestedEportfolio.value] : []),
  ];
  const pageResult = includePage
    ? await pool(eportfolioSource, async (one: any) => {
      const eportfolioId = one?.id ?? null;
      if (!eportfolioId) return { eportfolio: one, value: null, error: 'eportfolio id unavailable' };
      const result = await safe(() => canvasPaginate<any>(`/eportfolios/${eportfolioId}/pages`));
      return { eportfolio: one, value: result.value, error: result.error };
    }, 4)
    : [];
  const pageByEportfolioId = new Map(pageResult.map((one: any) => [String(one.eportfolio?.id ?? ''), one]));
  const row = eportfolioSource.map((one: any) => {
    const page = pageByEportfolioId.get(String(one?.id ?? ''));
    const pageValue = limitRow((page?.value as any[]) ?? [], maxPage);
    return {
      ...compactEportfolio(one),
      eportfolio_page_status: page?.error ? endpointStatus(page.error) : includePage ? 'ok' : 'skipped',
      eportfolio_page_count: rowCount(page?.value),
      returned_eportfolio_page_count: pageValue.length,
      eportfolio_page: pageValue.map((item: any) => compactEportfolioPage(item, maxChar)),
    };
  });

  return {
    generated_at: new Date().toISOString(),
    user_id: userId,
    endpoint: [
      ['user', user],
      ['eportfolio', eportfolio],
      ['requested_eportfolio', requestedEportfolio],
      ...pageResult.map((one: any) => [`eportfolio_page:${one.eportfolio?.id ?? 'unknown'}`, { value: one.value, error: one.error }]),
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error ? endpointStatus(one.error) : 'ok',
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    eportfolio_status: eportfolio.error ? endpointStatus(eportfolio.error) : 'ok',
    eportfolio_count: rowCount(eportfolio.value),
    returned_eportfolio_count: row.length,
    eportfolio: row,
    eportfolio_page_endpoint_count: pageResult.length,
    eportfolio_page_count: pageResult.reduce((sum: number, one: any) => sum + rowCount(one?.value), 0),
    note: 'ePortfolio context is read-only and current-user scoped. It can surface portfolio material linked from Canvas, but it is not assignment submission proof.',
  };
}

async function getUserContentShareContext(args: {
  content_share_id?: string | number;
  max_content_share?: number;
} = {}): Promise<unknown> {
  const maxContentShare = Math.max(0, Number(args.max_content_share ?? 50));
  const [sent, received, unreadCount] = await Promise.all([
    safe(() => canvasPaginate<any>('/users/self/content_shares/sent')),
    safe(() => canvasPaginate<any>('/users/self/content_shares/received')),
    safe(() => canvasGet('/users/self/content_shares/unread_count')),
  ]);
  const sentValue = limitRow((sent.value as any[]) ?? [], maxContentShare);
  const receivedValue = limitRow((received.value as any[]) ?? [], maxContentShare);
  const selectedContentShareId = args.content_share_id
    ? String(args.content_share_id)
    : String(receivedValue[0]?.id ?? sentValue[0]?.id ?? '');
  const detail = selectedContentShareId
    ? await safe(() => canvasGet(`/users/self/content_shares/${selectedContentShareId}`))
    : { value: null, error: 'no visible content share to fetch in detail' };

  const endpoint = [
    ['content_share_sent', sent],
    ['content_share_received', received],
    ['content_share_unread_count', unreadCount],
    ['content_share_detail', detail],
  ].map(([name, result]) => {
    const one = result as { value: unknown; error: string | null };
    return {
      name,
      status: name === 'content_share_detail' && !selectedContentShareId ? 'skipped' : endpointStatus(one.error),
      count: rowCount(one.value),
      key: keySample(one.value),
      error: one.error,
    };
  });

  return {
    generated_at: new Date().toISOString(),
    endpoint,
    sent_content_share_status: sent.error ? endpointStatus(sent.error) : 'ok',
    sent_content_share_count: rowCount(sent.value),
    returned_sent_content_share_count: sentValue.length,
    sent_content_share: sentValue.map(compactContentShare),
    received_content_share_status: received.error ? endpointStatus(received.error) : 'ok',
    received_content_share_count: rowCount(received.value),
    returned_received_content_share_count: receivedValue.length,
    received_content_share: receivedValue.map(compactContentShare),
    unread_count_status: unreadCount.error ? endpointStatus(unreadCount.error) : 'ok',
    unread_count: (unreadCount.value as any)?.unread_count ?? (unreadCount.value as any)?.count ?? null,
    content_share_detail_status: !selectedContentShareId ? 'skipped' : (detail.error ? endpointStatus(detail.error) : 'ok'),
    content_share_detail: detail.value ? compactContentShare(detail.value) : null,
    note: 'Content Share context is read-only. This tool lists current-user sent/received shares and unread count, but never creates shares, adds receivers, deletes shares, or marks shares read/unread.',
  };
}

async function getCoursePageContext(args: {
  course_id?: string | number;
  page_url?: string[];
  include_body?: boolean;
  extract_file?: boolean;
  max_page?: number;
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeBody = args.include_body !== false;
  const maxPage = Number(args.max_page ?? 80);
  const maxChar = Number(args.max_chars ?? 1200);
  const [pageStub, frontPage, module] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/pages`)),
    safe(() => canvasGet(`/courses/${id}/front_page`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/modules`, { 'include[]': 'items' })),
  ]);
  const pageStubValue = (pageStub.value as any[]) ?? [];
  const moduleValue = (module.value as any[]) ?? [];
  const modulePageUrl = moduleValue.flatMap((one: any) => (
    Array.isArray(one?.items)
      ? one.items
        .filter((item: any) => item?.type === 'Page' && item?.page_url)
        .map((item: any) => String(item.page_url))
      : []
  ));
  const requestedPageUrl = Array.isArray(args.page_url) ? args.page_url.map(String) : [];
  const selectedPageUrl = limitRow(uniqueText([
    ...requestedPageUrl,
    ...pageStubValue.map((one: any) => one?.url).filter(Boolean).map(String),
    ...modulePageUrl,
    (frontPage.value as any)?.url ? String((frontPage.value as any).url) : null,
  ]), maxPage);
  const pageBody = includeBody
    ? await pool(selectedPageUrl, async (url) => {
      const result = await safe(() => canvasGet(`/courses/${id}/pages/${encodeURIComponent(url)}`));
      return {
        page_url: url,
        page: result.value,
        error: result.error,
      };
    }, 6)
    : selectedPageUrl.map((url) => ({
      page_url: url,
      page: pageStubValue.find((one: any) => String(one?.url ?? '') === url) ?? null,
      error: null,
    }));
  const page = pageBody.map((one: any) => {
    const row = one.page ?? { url: one.page_url };
    const text = stripHtml(row?.body ?? '');
    const link = extractEmbeds(row?.body, { type: 'page', id: row?.url ?? one.page_url, title: row?.title });
    const fileId = extractFileId(row?.body);
    const signal = materialSignal(text, link, fileId);
    return {
      ...compactPage(row),
      page_url: row?.url ?? one.page_url,
      status: one.error ? endpointStatus(one.error) : 'ok',
      error: one.error,
      module: moduleForPage(moduleValue, row?.url ?? one.page_url),
      file_id: fileId,
      link,
      requirement_tag: signal.requirement_tag,
      submission_expectation: signal.submission_expectation,
      reading: signal.reading,
      reply_requirement: signal.reply_requirement,
      work_mode: signal.work_mode,
      deadline: signal.deadline,
      body_text: includeBody ? text.slice(0, maxChar) : null,
      body_truncated: includeBody ? text.length > maxChar : null,
    };
  });
  const fileId = uniqueText(page.flatMap((one: any) => one.file_id ?? []));
  const extractionTarget = limitRow(fileId, Number(args.max_extract_file ?? 6));
  const extraction = args.extract_file
    ? await pool(extractionTarget, async (one) => {
      const result = await safe(() => extractFileText({ file_id: one, max_chars: maxChar }));
      return {
        file_id: one,
        extraction_mode: (result.value as any)?.extraction ?? (result.error ? 'error' : 'metadata-only'),
        text: (result.value as any)?.text ?? null,
        link: (result.value as any)?.link ?? [],
        error: result.error,
      };
    }, 3)
    : extractionTarget.map((one) => ({
      file_id: one,
      extraction_mode: 'not-requested',
      text: null,
      link: [],
      error: null,
    }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      ['page', pageStub],
      ['front_page', frontPage],
      ['module', module],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('not requested') || one.error?.includes('no custom gradebook column')
          ? 'skipped'
          : endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    page_count: page.length,
    page_index_count: pageStubValue.length,
    module_page_count: modulePageUrl.length,
    front_page_status: frontPage.error ? endpointStatus(frontPage.error) : 'ok',
    front_page: frontPage.value ? compactPage(frontPage.value) : null,
    reading_page_count: page.filter((one: any) => one?.reading?.is_reading).length,
    reply_requirement_count: page.filter((one: any) => one?.reply_requirement?.is_required).length,
    file_count: fileId.length,
    extracted_file_count: extraction.filter((one: any) => !['metadata-only', 'not-requested', 'error'].includes(String(one?.extraction_mode))).length,
    extraction,
    page,
  };
}

async function getCourseAnnouncementContext(args: {
  course_id?: string | number;
  start_date?: string;
  end_date?: string;
  active_only?: boolean;
  extract_file?: boolean;
  max_announcement?: number;
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const now = new Date();
  const startDate = args.start_date ?? dateOffset(now, -30);
  const endDate = args.end_date ?? dateOffset(now, 60);
  const maxAnnouncement = Number(args.max_announcement ?? 80);
  const maxChar = Number(args.max_chars ?? 1200);
  const announcement = await safe(() => canvasPaginate<any>('/announcements', {
    'context_codes[]': `course_${id}`,
    start_date: startDate,
    end_date: endDate,
    ...(args.active_only === undefined ? {} : { active_only: !!args.active_only }),
  }));
  const announcementValue = limitRow((announcement.value as any[]) ?? [], maxAnnouncement);
  const row = announcementValue.map((one: any) => {
    const text = stripHtml(one?.message ?? '');
    const link = extractEmbeds(one?.message, { type: 'announcement', id: one?.id, title: one?.title });
    const fileId = extractFileId(one?.message);
    const signal = materialSignal(text, link, fileId, { is_discussion: false });
    return {
      ...compactAnnouncement(one),
      file_id: fileId,
      link,
      requirement_tag: signal.requirement_tag,
      submission_expectation: signal.submission_expectation,
      reading: signal.reading,
      reply_requirement: signal.reply_requirement,
      work_mode: signal.work_mode,
      deadline: signal.deadline,
      message_text: text.slice(0, maxChar),
      message_truncated: text.length > maxChar,
    };
  });
  const fileId = uniqueText(row.flatMap((one: any) => one.file_id ?? []));
  const extractionTarget = limitRow(fileId, Number(args.max_extract_file ?? 6));
  const extraction = args.extract_file
    ? await pool(extractionTarget, async (one) => {
      const result = await safe(() => extractFileText({ file_id: one, max_chars: maxChar }));
      return {
        file_id: one,
        extraction_mode: (result.value as any)?.extraction ?? (result.error ? 'error' : 'metadata-only'),
        text: (result.value as any)?.text ?? null,
        link: (result.value as any)?.link ?? [],
        error: result.error,
      };
    }, 3)
    : extractionTarget.map((one) => ({
      file_id: one,
      extraction_mode: 'not-requested',
      text: null,
      link: [],
      error: null,
    }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    date_window: { start_date: startDate, end_date: endDate },
    endpoint: [{
      name: 'announcement',
      status: announcement.error ? endpointStatus(announcement.error) : 'ok',
      count: rowCount(announcement.value),
      key: keySample(announcement.value),
      error: announcement.error,
    }],
    announcement_status: announcement.error ? endpointStatus(announcement.error) : 'ok',
    announcement_count: row.length,
    reading_announcement_count: row.filter((one: any) => one?.reading?.is_reading).length,
    reply_requirement_count: row.filter((one: any) => one?.reply_requirement?.is_required).length,
    deadline_signal_count: row.filter((one: any) => Array.isArray(one?.requirement_tag) && one.requirement_tag.some((tag: any) => tag?.tag === 'deadline')).length,
    device_signal_count: row.filter((one: any) => Array.isArray(one?.requirement_tag) && one.requirement_tag.some((tag: any) => tag?.tag === 'device_or_onsite')).length,
    file_count: fileId.length,
    extracted_file_count: extraction.filter((one: any) => !['metadata-only', 'not-requested', 'error'].includes(String(one?.extraction_mode))).length,
    extraction,
    announcement: row,
  };
}

async function getCourseFeedContext(args: {
  course_id?: string | number;
  include_group_feed?: boolean;
  max_feed?: number;
  max_group?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeGroupFeed = args.include_group_feed !== false;
  const maxFeed = Math.max(0, Number(args.max_feed ?? 40));
  const maxGroup = Math.max(0, Number(args.max_group ?? 10));
  const [courseFeed, selfGroup, courseGroup] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/external_feeds`)),
    includeGroupFeed
      ? safe(() => canvasPaginate<any>('/users/self/groups', {
        context_type: 'Course',
        'include[]': 'tabs',
      }))
      : Promise.resolve({ value: null, error: 'include_group_feed false; group feed skipped' }),
    includeGroupFeed
      ? safe(() => canvasPaginate<any>(`/courses/${id}/groups`, {
        only_own_groups: true,
        'include[]': 'tabs',
      }))
      : Promise.resolve({ value: null, error: 'include_group_feed false; group feed skipped' }),
  ]);

  const ownGroupRaw = includeGroupFeed ? [
    ...((selfGroup.value as any[]) ?? []),
    ...((courseGroup.value as any[]) ?? []),
  ].filter((one: any) => String(one?.course_id ?? '') === String(id)) : [];
  const groupById = new Map<string, any>();
  for (const one of ownGroupRaw) {
    if (one?.id === undefined || one?.id === null) continue;
    groupById.set(String(one.id), { ...groupById.get(String(one.id)), ...one });
  }
  const group = limitRow([...groupById.values()], maxGroup);

  const groupFeedResult = includeGroupFeed
    ? await pool(group, async (one: any) => {
      const groupId = String(one.id);
      const result = await safe(() => canvasPaginate<any>(`/groups/${groupId}/external_feeds`));
      const feedValue = limitRow((result.value as any[]) ?? [], maxFeed);
      return {
        group: one,
        status: result.error ? endpointStatus(result.error) : 'ok',
        error: result.error,
        feed_count: rowCount(result.value),
        returned_feed_count: feedValue.length,
        feed: feedValue.map((feed: any) => compactExternalFeed(feed, {
          context_type: 'group',
          group_id: one?.id ?? null,
          group_name: one?.name ?? null,
        })),
      };
    }, 4)
    : [];

  const courseFeedValue = limitRow((courseFeed.value as any[]) ?? [], maxFeed);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      {
        name: 'course_external_feed',
        status: courseFeed.error ? endpointStatus(courseFeed.error) : 'ok',
        count: rowCount(courseFeed.value),
        key: keySample(courseFeed.value),
        error: courseFeed.error,
      },
      {
        name: 'self_group',
        status: selfGroup.error?.includes('false;') ? 'skipped' : endpointStatus(selfGroup.error),
        count: rowCount(selfGroup.value),
        key: keySample(selfGroup.value),
        error: selfGroup.error,
      },
      {
        name: 'course_group',
        status: courseGroup.error?.includes('false;') ? 'skipped' : endpointStatus(courseGroup.error),
        count: rowCount(courseGroup.value),
        key: keySample(courseGroup.value),
        error: courseGroup.error,
      },
      ...groupFeedResult.map((one: any) => ({
        name: `group_external_feed:${one.group?.id ?? 'unknown'}`,
        status: one.status,
        count: one.feed_count,
        key: one.feed.length > 0 ? keySample(one.feed[0]) : [],
        error: one.error,
      })),
    ],
    course_feed_status: courseFeed.error ? endpointStatus(courseFeed.error) : 'ok',
    course_feed_count: rowCount(courseFeed.value),
    returned_course_feed_count: courseFeedValue.length,
    course_feed: courseFeedValue.map((one: any) => compactExternalFeed(one, {
      context_type: 'course',
      course_id: id,
    })),
    own_group_status: !includeGroupFeed
      ? 'skipped'
      : selfGroup.error && courseGroup.error
        ? endpointStatus(`${selfGroup.error}; ${courseGroup.error}`)
        : 'ok',
    own_group_count: group.length,
    group_feed_status: !includeGroupFeed
      ? 'skipped'
      : groupFeedResult.some((one: any) => one.status === 'error')
        ? 'error'
        : groupFeedResult.some((one: any) => one.status === 'ok')
          ? 'ok'
          : groupFeedResult.some((one: any) => one.status === 'blocked_or_absent')
            ? 'blocked_or_absent'
            : 'skipped',
    group_feed_endpoint_count: groupFeedResult.length,
    group_feed_count: groupFeedResult.reduce((sum: number, one: any) => sum + Number(one.feed_count ?? 0), 0),
    returned_group_feed_count: groupFeedResult.reduce((sum: number, one: any) => sum + Number(one.returned_feed_count ?? 0), 0),
    group_feed: groupFeedResult.map((one: any) => ({
      group: compactGroup(one.group),
      status: one.status,
      error: one.error,
      feed_count: one.feed_count,
      returned_feed_count: one.returned_feed_count,
      feed: one.feed,
    })),
    note: 'Announcement External Feed context is read-only. This tool lists RSS/Atom feeds that can auto-create course or own-group announcements, but never creates or deletes feeds.',
  };
}

async function getCourseTermContext(args: {
  course_id?: string | number;
  account_id?: string | number;
  enrollment_term_id?: string | number;
  include_completed?: boolean;
  include_account_term?: boolean;
  max_term?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const enrollmentState = args.include_completed ? ['active', 'completed'] : ['active'];
  const includeAccountTerm = args.include_account_term !== false;
  const maxTerm = Math.max(1, Math.min(Number(args.max_term ?? 40), 100));
  const [course, section, enrollment, selfEnrollment] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}`, {
      'include[]': [
        'term',
        'sections',
        'grading_periods',
        'current_grading_period_scores',
        'total_scores',
        'concluded',
        'course_progress',
        'teachers',
      ],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/sections`, {
      'include[]': ['total_students', 'passback_status'],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/enrollments`, {
      user_id: 'self',
      'state[]': enrollmentState,
      'include[]': ['current_grading_period_scores'],
    })),
    safe(() => canvasPaginate<any>('/users/self/enrollments', {
      'state[]': enrollmentState,
      'include[]': ['current_grading_period_scores'],
    })),
  ]);
  const courseValue = course.value as any;
  const accountId = args.account_id
    ? String(args.account_id)
    : courseValue?.root_account_id
      ? String(courseValue.root_account_id)
      : courseValue?.account_id
        ? String(courseValue.account_id)
        : null;
  const selectedEnrollmentTermId = args.enrollment_term_id
    ? String(args.enrollment_term_id)
    : courseValue?.term?.id
      ? String(courseValue.term.id)
      : courseValue?.enrollment_term_id
        ? String(courseValue.enrollment_term_id)
        : null;
  const [accountTerm, accountTermDetail] = await Promise.all([
    includeAccountTerm && accountId
      ? safe(() => canvasGet(`/accounts/${accountId}/terms`, {
        'workflow_state[]': 'active',
        'include[]': ['overrides', 'course_count'],
      }))
      : { value: null, error: includeAccountTerm ? 'account id unavailable; account enrollment term skipped' : 'account enrollment term skipped by request' },
    includeAccountTerm && accountId && selectedEnrollmentTermId
      ? safe(() => canvasGet(`/accounts/${accountId}/terms/${selectedEnrollmentTermId}`))
      : { value: null, error: includeAccountTerm ? 'no enrollment term id visible for detail' : 'account enrollment term detail skipped by request' },
  ]);
  const sectionValue = (section.value as any[]) ?? [];
  const includedSection = Array.isArray(courseValue?.sections) ? courseValue.sections : [];
  const enrollmentValue = ((enrollment.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id));
  const selfEnrollmentValue = ((selfEnrollment.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id));
  const gradingPeriod = Array.isArray(courseValue?.grading_periods) ? courseValue.grading_periods : [];
  const accountTermValue = limitRow(unwrapCanvasArray(accountTerm.value, 'enrollment_terms'), maxTerm);
  const now = Date.now();
  const dateState = (startAt?: string | null, endAt?: string | null) => {
    const start = startAt ? new Date(startAt).getTime() : null;
    const end = endAt ? new Date(endAt).getTime() : null;
    if (end !== null && Number.isFinite(end) && end < now) return 'past';
    if (start !== null && Number.isFinite(start) && start > now) return 'future';
    if ((start === null || !Number.isFinite(start) || start <= now) && (end === null || !Number.isFinite(end) || end >= now)) return 'current_or_open';
    return 'unknown';
  };
  const term = compactCourseTerm(courseValue?.term);
  const courseStartAt = courseValue?.start_at ?? null;
  const courseEndAt = courseValue?.end_at ?? null;

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      ['course', course],
      ['account_enrollment_term', accountTerm],
      ['account_enrollment_term_detail', accountTermDetail],
      ['section', section],
      ['enrollment', enrollment],
      ['self_enrollment', selfEnrollment],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      account_id: courseValue?.account_id ?? null,
      root_account_id: courseValue?.root_account_id ?? null,
      workflow_state: courseValue?.workflow_state ?? null,
      start_at: courseStartAt,
      end_at: courseEndAt,
      is_concluded: !!courseValue?.concluded,
      is_public: !!courseValue?.is_public,
      is_restrict_enrollment_to_course_date: !!courseValue?.restrict_enrollments_to_course_dates,
      date_state: dateState(courseStartAt, courseEndAt),
      has_grading_period: !!courseValue?.has_grading_periods,
      course_progress: courseValue?.course_progress ?? null,
    } : null,
    term: {
      ...term,
      date_state: term ? dateState(String(term.start_at ?? ''), String(term.end_at ?? '')) : 'unknown',
    },
    account_id: accountId,
    account_enrollment_term_status: accountTerm.error
      ? accountTerm.error.includes('skipped by request')
        ? 'skipped'
        : endpointStatus(accountTerm.error)
      : includeAccountTerm && accountId ? 'ok' : 'skipped',
    account_enrollment_term_count: rowCount(accountTerm.value),
    returned_account_enrollment_term_count: accountTermValue.length,
    account_enrollment_term: accountTermValue.map(compactEnrollmentTerm),
    account_enrollment_term_detail_status: accountTermDetail.error
      ? accountTermDetail.error.includes('skipped by request') || accountTermDetail.error.includes('no enrollment term id visible')
        ? 'skipped'
        : endpointStatus(accountTermDetail.error)
      : 'ok',
    account_enrollment_term_detail: accountTermDetail.value ? compactEnrollmentTerm(accountTermDetail.value) : null,
    section_status: section.error ? endpointStatus(section.error) : 'ok',
    section_count: sectionValue.length,
    section: sectionValue.map(compactCourseSection),
    included_section_count: includedSection.length,
    included_section: includedSection.map(compactCourseSection),
    grading_period_count: gradingPeriod.length,
    grading_period: gradingPeriod.map(compactGradingPeriod),
    enrollment_status: enrollment.error ? endpointStatus(enrollment.error) : 'ok',
    enrollment_count: enrollmentValue.length,
    enrollment: enrollmentValue.map(compactEnrollment),
    self_enrollment_status: selfEnrollment.error ? endpointStatus(selfEnrollment.error) : 'ok',
    self_enrollment_count: selfEnrollmentValue.length,
    self_enrollment: selfEnrollmentValue.map(compactEnrollment),
    teacher_count: Array.isArray(courseValue?.teachers) ? courseValue.teachers.length : 0,
    teacher: (Array.isArray(courseValue?.teachers) ? courseValue.teachers : []).map((one: any) => ({
      user_id: one?.id ?? null,
      display_name: one?.display_name ?? one?.name ?? null,
      html_url: one?.html_url ?? null,
    })),
  };
}

async function getCourseRosterContext(args: {
  course_id?: string | number;
  include_user?: boolean;
  include_category_group?: boolean;
  include_category_user?: boolean;
  include_lti_name_role?: boolean;
  include_section_detail?: boolean;
  include_section_user?: boolean;
  max_user?: number;
  max_section_user?: number;
  max_group_category?: number;
  max_category_group?: number;
  max_category_user?: number;
  max_lti_name_role?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeUser = args.include_user !== false;
  const includeCategoryGroup = args.include_category_group !== false;
  const includeCategoryUser = args.include_category_user !== false;
  const includeLtiNameRole = args.include_lti_name_role !== false;
  const includeSectionDetail = args.include_section_detail !== false;
  const includeSectionUser = args.include_section_user !== false;
  const maxUser = Math.max(0, Number(args.max_user ?? 80));
  const maxSectionUser = Math.max(0, Number(args.max_section_user ?? 80));
  const maxGroupCategory = Math.max(0, Number(args.max_group_category ?? 40));
  const maxCategoryGroup = Math.max(0, Number(args.max_category_group ?? 40));
  const maxCategoryUser = Math.max(0, Number(args.max_category_user ?? 40));
  const maxLtiNameRole = Math.max(0, Number(args.max_lti_name_role ?? 80));

  const [user, course, section, enrollment, courseUser, groupCategory, ownGroup] = await Promise.all([
    safe(() => canvasGet('/users/self')),
    safe(() => canvasGet(`/courses/${id}`, {
      'include[]': ['term', 'sections', 'teachers', 'concluded', 'total_students'],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/sections`, {
      'include[]': ['total_students', 'passback_status'],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/enrollments`, {
      user_id: 'self',
      'state[]': ['active', 'completed'],
      'include[]': ['current_grading_period_scores'],
    })),
    includeUser
      ? safe(() => canvasPaginate<any>(`/courses/${id}/users`, {
        'include[]': ['enrollments', 'locked'],
        'enrollment_state[]': ['active', 'invited'],
      }))
      : Promise.resolve({ value: null, error: 'include_user false; course user skipped' }),
    safe(() => canvasPaginate<any>(`/courses/${id}/group_categories`, {
      collaboration_state: 'all',
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/groups`, {
      only_own_groups: true,
      'include[]': 'tabs',
    })),
  ]);

  const userId = user.error ? null : String((user.value as any)?.id ?? '');
  const courseValue = course.value as any;
  const sectionValue = (section.value as any[]) ?? [];
  const selectedSection = sectionValue.find((one: any) => one?.id) ?? null;
  const selectedSectionId = selectedSection?.id ? String(selectedSection.id) : null;
  const enrollmentValue = ((enrollment.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id));
  const courseUserValue = limitRow((courseUser.value as any[]) ?? [], maxUser);
  const groupCategoryValue = limitRow((groupCategory.value as any[]) ?? [], maxGroupCategory);
  const ownGroupValue = limitRow((ownGroup.value as any[]) ?? [], maxGroupCategory);
  const selectedGroup = ownGroupValue.find((one: any) => one?.id) ?? null;
  const selectedGroupId = selectedGroup?.id ?? null;

  const categoryGroupResult = includeCategoryGroup
    ? await pool(groupCategoryValue, async (category: any) => {
      const groupCategoryId = category?.id ?? null;
      if (!groupCategoryId) return { group_category: category, value: null, error: 'group category id unavailable' };
      const result = await safe(() => canvasPaginate<any>(`/group_categories/${groupCategoryId}/groups`));
      return { group_category: category, value: result.value, error: result.error };
    }, 4)
    : [];
  const categoryUserResult = includeCategoryUser
    ? await pool(groupCategoryValue, async (category: any) => {
      const groupCategoryId = category?.id ?? null;
      if (!groupCategoryId) return { group_category: category, value: null, error: 'group category id unavailable' };
      const result = await safe(() => canvasPaginate<any>(`/group_categories/${groupCategoryId}/users`));
      return { group_category: category, value: result.value, error: result.error };
    }, 4)
    : [];

  const [ltiCourseNameRole, ltiGroupNameRole] = includeLtiNameRole
    ? await Promise.all([
      safe(() => canvasApiGet(`/api/lti/courses/${id}/names_and_roles`)),
      selectedGroupId
        ? safe(() => canvasApiGet(`/api/lti/groups/${selectedGroupId}/names_and_roles`))
        : Promise.resolve({ value: null, error: 'no own group visible for LTI Names and Role' }),
    ])
    : [
      { value: null, error: 'include_lti_name_role false; LTI Names and Role course skipped' },
      { value: null, error: 'include_lti_name_role false; LTI Names and Role group skipped' },
    ];
  const ltiCourseNameRoleValue = limitRow(nameRoleMember(ltiCourseNameRole.value), maxLtiNameRole);
  const ltiGroupNameRoleValue = limitRow(nameRoleMember(ltiGroupNameRole.value), maxLtiNameRole);
  const [sectionDetail, sectionUser] = selectedSectionId
    ? await Promise.all([
      includeSectionDetail
        ? safe(() => canvasGet(`/courses/${id}/sections/${selectedSectionId}`, {
          'include[]': ['total_students', 'passback_status', 'permissions'],
        }))
        : Promise.resolve({ value: null, error: 'include_section_detail false; section detail skipped' }),
      includeSectionUser
        ? safe(() => canvasPaginate<any>(`/sections/${selectedSectionId}/users`, {
          exclude_inactive: true,
          enrollment_type: 'student',
        }))
        : Promise.resolve({ value: null, error: 'include_section_user false; section user skipped' }),
    ])
    : [
      { value: null, error: 'no section visible for selected course; section detail skipped' },
      { value: null, error: 'no section visible for selected course; section user skipped' },
    ];
  const sectionUserValue = limitRow((sectionUser.value as any[]) ?? [], maxSectionUser);

  const categoryGroupById = new Map(categoryGroupResult.map((one: any) => [String(one.group_category?.id ?? ''), one]));
  const categoryUserById = new Map(categoryUserResult.map((one: any) => [String(one.group_category?.id ?? ''), one]));
  const groupCategoryRow = groupCategoryValue.map((category: any) => {
    const categoryId = String(category?.id ?? '');
    const categoryGroup = categoryGroupById.get(categoryId);
    const categoryUser = categoryUserById.get(categoryId);
    const categoryGroupValue = limitRow((categoryGroup?.value as any[]) ?? [], maxCategoryGroup);
    const categoryUserValue = limitRow((categoryUser?.value as any[]) ?? [], maxCategoryUser);
    return {
      ...compactGroupCategory(category),
      category_group_status: categoryGroup?.error
        ? endpointStatus(categoryGroup.error)
        : includeCategoryGroup ? 'ok' : 'skipped',
      category_group_count: rowCount(categoryGroup?.value),
      returned_category_group_count: categoryGroupValue.length,
      category_group: categoryGroupValue.map(compactGroup),
      category_user_status: categoryUser?.error
        ? endpointStatus(categoryUser.error)
        : includeCategoryUser ? 'ok' : 'skipped',
      category_user_count: rowCount(categoryUser?.value),
      returned_category_user_count: categoryUserValue.length,
      category_user: categoryUserValue.map(compactCourseUser),
    };
  });

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    endpoint: [
      ['user', user],
      ['course', course],
      ['section', section],
      ['section_detail', sectionDetail],
      ['section_user', sectionUser],
      ['enrollment', enrollment],
      ['course_user', courseUser],
      ['group_category', groupCategory],
      ['own_group', ownGroup],
      ['lti_course_name_role', ltiCourseNameRole],
      ['lti_group_name_role', ltiGroupNameRole],
      ...categoryGroupResult.map((one: any) => [`category_group:${one.group_category?.id ?? 'unknown'}`, { value: one.value, error: one.error }]),
      ...categoryUserResult.map((one: any) => [`category_user:${one.group_category?.id ?? 'unknown'}`, { value: one.value, error: one.error }]),
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('false;') || one.error?.includes('no section visible') || one.error?.startsWith('no own group visible') ? 'skipped' : endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      workflow_state: courseValue?.workflow_state ?? null,
      term: compactCourseTerm(courseValue?.term),
      is_concluded: !!courseValue?.concluded,
      total_student_count: courseValue?.total_students ?? null,
    } : null,
    section_status: section.error ? endpointStatus(section.error) : 'ok',
    section_count: sectionValue.length,
    section: sectionValue.map(compactCourseSection),
    selected_section_id: selectedSectionId,
    section_detail_status: sectionDetail.error?.includes('skipped')
      ? 'skipped'
      : sectionDetail.error ? endpointStatus(sectionDetail.error) : 'ok',
    section_detail: sectionDetail.value ? compactCourseSection(sectionDetail.value) : null,
    section_user_status: sectionUser.error?.includes('skipped')
      ? 'skipped'
      : sectionUser.error ? endpointStatus(sectionUser.error) : 'ok',
    section_user_count: rowCount(sectionUser.value),
    returned_section_user_count: sectionUserValue.length,
    section_user: sectionUserValue.map(compactCourseUser),
    enrollment_status: enrollment.error ? endpointStatus(enrollment.error) : 'ok',
    enrollment_count: enrollmentValue.length,
    enrollment: enrollmentValue.map(compactEnrollment),
    course_user_status: courseUser.error?.includes('include_user false')
      ? 'skipped'
      : courseUser.error ? endpointStatus(courseUser.error) : 'ok',
    course_user_count: rowCount(courseUser.value),
    returned_course_user_count: courseUserValue.length,
    course_user: courseUserValue.map(compactCourseUser),
    group_category_status: groupCategory.error ? endpointStatus(groupCategory.error) : 'ok',
    group_category_count: rowCount(groupCategory.value),
    returned_group_category_count: groupCategoryRow.length,
    group_category: groupCategoryRow,
    own_group_status: ownGroup.error ? endpointStatus(ownGroup.error) : 'ok',
    own_group_count: rowCount(ownGroup.value),
    returned_own_group_count: ownGroupValue.length,
    selected_group_id: selectedGroupId,
    own_group: ownGroupValue.map(compactGroup),
    lti_course_name_role_status: ltiCourseNameRole.error?.includes('include_lti_name_role false')
      ? 'skipped'
      : ltiCourseNameRole.error ? endpointStatus(ltiCourseNameRole.error) : 'ok',
    lti_course_name_role_count: rowCount(ltiCourseNameRole.value),
    returned_lti_course_name_role_count: ltiCourseNameRoleValue.length,
    lti_course_name_role: ltiCourseNameRoleValue.map(compactLtiNameRoleMember),
    lti_group_name_role_status: ltiGroupNameRole.error?.includes('include_lti_name_role false') || ltiGroupNameRole.error?.startsWith('no own group visible')
      ? 'skipped'
      : ltiGroupNameRole.error ? endpointStatus(ltiGroupNameRole.error) : 'ok',
    lti_group_name_role_count: rowCount(ltiGroupNameRole.value),
    returned_lti_group_name_role_count: ltiGroupNameRoleValue.length,
    lti_group_name_role: ltiGroupNameRoleValue.map(compactLtiNameRoleMember),
    category_group_endpoint_count: categoryGroupResult.length,
    category_group_count: categoryGroupRowCount(categoryGroupResult),
    category_user_endpoint_count: categoryUserResult.length,
    category_user_count: categoryUserRowCount(categoryUserResult),
    teacher_count: Array.isArray(courseValue?.teachers) ? courseValue.teachers.length : 0,
    teacher: (Array.isArray(courseValue?.teachers) ? courseValue.teachers : []).map(compactUser),
    note: 'Roster context is read-only and bounded. Use it for section/group/category/LTI Names and Role scope evidence; submissions/self remains the authoritative assignment completion source. Section detail and section-user reads never create, edit, delete, cross-list, or de-cross-list sections.',
  };
}

function categoryGroupRowCount(result: any[]): number {
  return result.reduce((sum, one) => sum + rowCount(one?.value), 0);
}

function categoryUserRowCount(result: any[]): number {
  return result.reduce((sum, one) => sum + rowCount(one?.value), 0);
}

async function getCourseGradeContext(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  max_assignment_group?: number;
  max_grading_standard?: number;
  max_gradebook_history_feed?: number;
  max_grade_change_event?: number;
  start_time?: string;
  end_time?: string;
  include_custom_gradebook_column_data?: boolean;
  max_custom_gradebook_column?: number;
  max_custom_gradebook_column_datum?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxAssignmentGroup = Math.max(0, Number(args.max_assignment_group ?? 80));
  const maxGradingStandard = Math.max(0, Number(args.max_grading_standard ?? 40));
  const maxGradebookHistoryFeed = Math.max(0, Number(args.max_gradebook_history_feed ?? 20));
  const maxGradeChangeEvent = Math.max(0, Number(args.max_grade_change_event ?? 20));
  const maxCustomGradebookColumn = Math.max(0, Number(args.max_custom_gradebook_column ?? 40));
  const maxCustomGradebookColumnDatum = Math.max(0, Number(args.max_custom_gradebook_column_datum ?? 20));
  const includeCustomGradebookColumnData = args.include_custom_gradebook_column_data === true;
  const now = new Date();
  const startTime = args.start_time ?? dateOffset(now, -30);
  const endTime = args.end_time ?? dateOffset(now, 0);
  const [user, course, enrollment, selfEnrollment, assignmentGroup, gradingStandard, customGradebookColumn] = await Promise.all([
    safe(() => canvasGet('/users/self')),
    safe(() => canvasGet(`/courses/${id}`, {
      'include[]': ['term', 'grading_periods', 'current_grading_period_scores', 'total_scores', 'concluded'],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/enrollments`, {
      user_id: 'self',
      'include[]': ['current_points', 'current_grading_period_scores'],
    })),
    safe(() => canvasPaginate<any>('/users/self/enrollments', {
      'state[]': ['active', 'completed'],
      'include[]': ['current_points', 'current_grading_period_scores'],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/assignment_groups`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/grading_standards`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/custom_gradebook_columns`)),
  ]);
  const courseValue = course.value as any;
  const userId = user.error ? null : String((user.value as any)?.id ?? '');
  const gradebookHistoryParam: Record<string, CanvasParamValue> = {};
  if (userId) gradebookHistoryParam.user_id = userId;
  if (args.assignment_id) gradebookHistoryParam.assignment_id = String(args.assignment_id);
  const gradebookHistoryFeed = userId
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/gradebook_history/feed`, gradebookHistoryParam))
    : { value: null, error: 'users/self unavailable; gradebook history feed skipped' };
  const gradeChangeParam = {
    start_time: startTime,
    end_time: endTime,
    per_page: maxGradeChangeEvent,
  };
  const courseGradeChangeEvent = await safe(() => canvasGet(`/audit/grade_change/courses/${id}`, gradeChangeParam));
  const assignmentGradeChangeEvent = args.assignment_id
    ? await safe(() => canvasGet(`/audit/grade_change/assignments/${String(args.assignment_id)}`, gradeChangeParam))
    : { value: null, error: 'assignment id unavailable; assignment grade change event skipped' };
  const customGradebookColumnValue = limitRow((customGradebookColumn.value as any[]) ?? [], maxCustomGradebookColumn);
  const selectedCustomGradebookColumn = customGradebookColumnValue.find((one: any) => one?.id) ?? null;
  const rawCustomGradebookColumnDatum = includeCustomGradebookColumnData && selectedCustomGradebookColumn?.id
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/custom_gradebook_columns/${selectedCustomGradebookColumn.id}/data`))
    : { value: null, error: includeCustomGradebookColumnData ? 'no custom gradebook column visible in selected course' : 'custom gradebook column data not requested' };
  const customGradebookColumnDatumValue = limitRow(((rawCustomGradebookColumnDatum.value as any[]) ?? [])
    .map((one: any) => compactCustomGradebookColumnDatum(one, userId))
    .filter((one: Record<string, unknown> | null): one is Record<string, unknown> => Boolean(one)), maxCustomGradebookColumnDatum);
  const customGradebookColumnDatum = {
    value: rawCustomGradebookColumnDatum.error ? rawCustomGradebookColumnDatum.value : customGradebookColumnDatumValue,
    error: rawCustomGradebookColumnDatum.error,
  };
  const enrollmentValue = ((enrollment.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id));
  const selfEnrollmentValue = ((selfEnrollment.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id));
  const assignmentGroupValue = limitRow((assignmentGroup.value as any[]) ?? [], maxAssignmentGroup);
  const gradingStandardValue = limitRow((gradingStandard.value as any[]) ?? [], maxGradingStandard);
  const gradebookHistoryFeedValue = limitRow((gradebookHistoryFeed.value as any[]) ?? [], maxGradebookHistoryFeed);
  const courseGradeChangeEventValue = limitRow(gradeChangeEventList(courseGradeChangeEvent.value), maxGradeChangeEvent);
  const assignmentGradeChangeEventValue = limitRow(gradeChangeEventList(assignmentGradeChangeEvent.value), maxGradeChangeEvent);
  const gradingPeriod = Array.isArray(courseValue?.grading_periods) ? courseValue.grading_periods : [];
  const enrollmentRow = enrollmentValue[0] ?? selfEnrollmentValue[0] ?? null;
  const grade = enrollmentRow?.grades ?? null;

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    assignment_id: args.assignment_id ? String(args.assignment_id) : null,
    endpoint: [
      ['user', user],
      ['course', course],
      ['enrollment', enrollment],
      ['self_enrollment', selfEnrollment],
      ['assignment_group', assignmentGroup],
      ['grading_standard', gradingStandard],
      ['gradebook_history_feed', gradebookHistoryFeed],
      ['course_grade_change_event', courseGradeChangeEvent],
      ['assignment_grade_change_event', assignmentGradeChangeEvent],
      ['custom_gradebook_column', customGradebookColumn],
      ['custom_gradebook_column_datum', customGradebookColumnDatum],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    course_status: course.error ? endpointStatus(course.error) : 'ok',
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      grading_standard_id: courseValue?.grading_standard_id ?? null,
      has_weighted_grading_period: !!courseValue?.weighted_grading_periods,
      has_grading_period: !!courseValue?.has_grading_periods,
      is_concluded: !!courseValue?.concluded,
    } : null,
    enrollment_status: enrollment.error ? endpointStatus(enrollment.error) : 'ok',
    enrollment_count: enrollmentValue.length,
    enrollment_key: keySample(enrollmentRow),
    enrollment: enrollmentValue.map(compactEnrollment),
    self_enrollment_status: selfEnrollment.error ? endpointStatus(selfEnrollment.error) : 'ok',
    self_enrollment_count: selfEnrollmentValue.length,
    self_enrollment: selfEnrollmentValue.map(compactEnrollment),
    grade_key: keySample(grade),
    grade: grade ? {
      current_score: grade.current_score ?? null,
      final_score: grade.final_score ?? null,
      current_grade: grade.current_grade ?? null,
      final_grade: grade.final_grade ?? null,
      current_period_score: grade.current_period_score ?? null,
      current_period_grade: grade.current_period_grade ?? null,
      html_url: grade.html_url ?? null,
    } : null,
    grading_period_count: gradingPeriod.length,
    grading_period: gradingPeriod.map(compactGradingPeriod),
    assignment_group_status: assignmentGroup.error ? endpointStatus(assignmentGroup.error) : 'ok',
    assignment_group_count: rowCount(assignmentGroup.value),
    returned_assignment_group_count: assignmentGroupValue.length,
    assignment_group: assignmentGroupValue.map(compactAssignmentGroup),
    grading_standard_status: gradingStandard.error ? endpointStatus(gradingStandard.error) : 'ok',
    grading_standard_count: rowCount(gradingStandard.value),
    returned_grading_standard_count: gradingStandardValue.length,
    grading_standard: gradingStandardValue.map(compactGradingStandard),
    gradebook_history_feed_status: gradebookHistoryFeed.error ? endpointStatus(gradebookHistoryFeed.error) : 'ok',
    gradebook_history_feed_count: rowCount(gradebookHistoryFeed.value),
    returned_gradebook_history_feed_count: gradebookHistoryFeedValue.length,
    gradebook_history_feed: gradebookHistoryFeedValue.map(compactGradebookHistoryFeed),
    grade_change_event_window: { start_time: startTime, end_time: endTime },
    course_grade_change_event_status: courseGradeChangeEvent.error ? endpointStatus(courseGradeChangeEvent.error) : 'ok',
    course_grade_change_event_count: rowCount(courseGradeChangeEvent.value),
    returned_course_grade_change_event_count: courseGradeChangeEventValue.length,
    course_grade_change_event: courseGradeChangeEventValue.map(compactGradeChangeEvent),
    assignment_grade_change_event_status: assignmentGradeChangeEvent.error?.includes('assignment id unavailable')
      ? 'skipped'
      : assignmentGradeChangeEvent.error ? endpointStatus(assignmentGradeChangeEvent.error) : 'ok',
    assignment_grade_change_event_count: rowCount(assignmentGradeChangeEvent.value),
    returned_assignment_grade_change_event_count: assignmentGradeChangeEventValue.length,
    assignment_grade_change_event: assignmentGradeChangeEventValue.map(compactGradeChangeEvent),
    custom_gradebook_column_status: customGradebookColumn.error ? endpointStatus(customGradebookColumn.error) : 'ok',
    custom_gradebook_column_count: rowCount(customGradebookColumn.value),
    returned_custom_gradebook_column_count: customGradebookColumnValue.length,
    custom_gradebook_column: customGradebookColumnValue.map(compactCustomGradebookColumn),
    custom_gradebook_column_datum_status: rawCustomGradebookColumnDatum.error?.includes('not requested')
      || rawCustomGradebookColumnDatum.error?.includes('no custom gradebook column')
      ? 'skipped'
      : rawCustomGradebookColumnDatum.error ? endpointStatus(rawCustomGradebookColumnDatum.error) : 'ok',
    custom_gradebook_column_datum_count: customGradebookColumnDatumValue.length,
    returned_custom_gradebook_column_datum_count: customGradebookColumnDatumValue.length,
    custom_gradebook_column_datum: customGradebookColumnDatumValue,
    note: 'Canvas grade context is read-only and cross-check-only. Gradebook History is filtered to users/self and the selected assignment when provided. Grade Change Log rows are bounded audit context and may be permission-bound under a student PAT. Custom gradebook column data is opt-in and filtered to users/self before return. Submission endpoints remain authoritative for done/missing/late classification.',
  };
}

function moduleForContent(module: any[], type: string, contentId: string | number | null | undefined): Record<string, unknown>[] {
  if (contentId === undefined || contentId === null) return [];
  return module.flatMap((one: any) => (
    Array.isArray(one?.items)
      ? one.items
        .filter((item: any) => String(item?.type ?? '').toLowerCase() === type.toLowerCase()
          && String(item?.content_id ?? '') === String(contentId))
        .map((item: any) => ({
          module_id: one?.id ?? null,
          module_name: one?.name ?? null,
          module_item_id: item?.id ?? null,
          position: item?.position ?? null,
          title: item?.title ?? null,
          html_url: item?.html_url ?? item?.url ?? null,
          completion_requirement: item?.completion_requirement ?? null,
          is_locked: !!item?.locked_for_user,
        }))
      : []
  ));
}

function moduleForPage(module: any[], pageUrl: string | number | null | undefined): Record<string, unknown>[] {
  if (pageUrl === undefined || pageUrl === null) return [];
  return module.flatMap((one: any) => (
    Array.isArray(one?.items)
      ? one.items
        .filter((item: any) => item?.type === 'Page' && String(item?.page_url ?? item?.url ?? '') === String(pageUrl))
        .map((item: any) => ({
          module_id: one?.id ?? null,
          module_name: one?.name ?? null,
          module_item_id: item?.id ?? null,
          position: item?.position ?? null,
          title: item?.title ?? null,
          html_url: item?.html_url ?? item?.url ?? null,
          completion_requirement: item?.completion_requirement ?? null,
          is_locked: !!item?.locked_for_user,
        }))
      : []
  ));
}

function queueSignal(assignmentId: string | number | null | undefined, queue: {
  planner_item: any[];
  todo_item: any[];
  missing_submission: any[];
  calendar_item: any[];
}): Record<string, unknown> {
  const id = assignmentId === undefined || assignmentId === null ? null : String(assignmentId);
  if (!id) {
    return {
      planner_count: 0,
      todo_count: 0,
      missing_count: 0,
      calendar_count: 0,
      calendar_at: [],
    };
  }
  const plannerItem = queue.planner_item.filter((one) => String(one?.plannable?.assignment_id ?? one?.assignment_id ?? one?.plannable_id ?? '') === id);
  const todoItem = queue.todo_item.filter((one) => String(one?.assignment?.id ?? one?.assignment_id ?? '') === id);
  const missingItem = queue.missing_submission.filter((one) => String(one?.id ?? one?.assignment_id ?? '') === id);
  const calendarItem = queue.calendar_item.filter((one) => String(one?.assignment?.id ?? one?.assignment_id ?? '') === id);
  return {
    planner_count: plannerItem.length,
    todo_count: todoItem.length,
    missing_count: missingItem.length,
    calendar_count: calendarItem.length,
    calendar_at: uniqueText(calendarItem.map((one) => one?.start_at ?? one?.all_day_date ?? one?.assignment?.due_at)),
  };
}

function compactMaterialSource(sourceSurface: string, row: any, titleFallback?: string): Record<string, unknown> {
  return {
    source_surface: sourceSurface,
    canvas_id: row?.id ?? row?.url ?? row?.page_url ?? null,
    title: row?.name ?? row?.title ?? row?.display_name ?? row?.filename ?? titleFallback ?? null,
    html_url: row?.html_url ?? row?.url ?? null,
  };
}

async function getCourseSyllabusContext(args: {
  course_id?: string | number;
  extract_file?: boolean;
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxExtractFile = Math.max(0, Number(args.max_extract_file ?? 4));
  const maxChar = Math.max(0, Number(args.max_chars ?? 1200));
  const [course, file] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}`, {
      'include[]': ['syllabus_body', 'term', 'sections', 'public_description', 'course_progress', 'teachers', 'concluded'],
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/files`, { 'include[]': ['usage_rights'] })),
  ]);

  const courseValue = course.value as any;
  const syllabusHtml = String(courseValue?.syllabus_body ?? '');
  const syllabusText = stripHtml(syllabusHtml);
  const link = extractEmbeds(syllabusHtml, { type: 'syllabus', id, title: courseValue?.name });
  const fileId = extractFileId(syllabusHtml);
  const fileValue = (file.value as any[]) ?? [];
  const fileById = new Map(fileValue.map((one: any) => [String(one?.id), one]));
  await fillFileById(fileById, fileId);
  const signal = materialSignal(syllabusHtml, link, fileId);
  const extraction = [];
  if (args.extract_file) {
    for (const one of fileId.slice(0, maxExtractFile)) {
      const fileRow = fileById.get(String(one));
      const extracted = await safe(() => extractFileText({ file_id: one, max_chars: maxChar }));
      extraction.push({
        file_id: one,
        display_name: fileRow?.display_name ?? fileRow?.filename ?? null,
        file_type: fileType(fileRow),
        extraction_mode: (extracted.value as any)?.extraction ?? 'error',
        extracted_char_count: typeof (extracted.value as any)?.text === 'string' ? (extracted.value as any).text.length : 0,
        is_truncated: !!(extracted.value as any)?.truncated,
        link: (extracted.value as any)?.link ?? [],
        error: extracted.error,
      });
    }
  }

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      ['course_syllabus', course],
      ['course_file', file],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    course_syllabus_status: course.error ? endpointStatus(course.error) : 'ok',
    course_file_status: file.error ? endpointStatus(file.error) : 'ok',
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      workflow_state: courseValue?.workflow_state ?? null,
      term: compactCourseTerm(courseValue?.term),
      section_count: Array.isArray(courseValue?.sections) ? courseValue.sections.length : null,
      teacher_count: Array.isArray(courseValue?.teachers) ? courseValue.teachers.length : null,
      is_concluded: !!courseValue?.concluded,
      progress: compactCourseProgress(courseValue),
    } : null,
    has_syllabus: syllabusText.length > 0,
    syllabus_char_count: syllabusText.length,
    syllabus_text: syllabusText.slice(0, maxChar),
    link_count: link.length,
    link: limitRow(link, 50),
    file_id: fileId,
    file_type: materialFileType(fileId, fileById),
    reading: (signal as any).reading,
    reply_requirement: (signal as any).reply_requirement,
    work_mode: (signal as any).work_mode,
    deadline: (signal as any).deadline,
    requirement_tag: (signal as any).requirement_tag,
    submission_expectation: (signal as any).submission_expectation,
    extraction,
    note: 'Syllabus context is read-only course-scope evidence for readings, links, dates, and course expectations. It is not submission proof and never updates the syllabus or course settings.',
  };
}

async function getCourseMaterialContext(args: {
  course_id?: string | number;
  start_date?: string;
  end_date?: string;
  include_page_body?: boolean;
  max_item?: number;
  extract_reading?: boolean;
  extract_material_id?: string[];
  max_extract_file?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const now = new Date();
  const startDate = args.start_date ?? dateOffset(now, -14);
  const endDate = args.end_date ?? dateOffset(now, 45);
  const maxItem = Number(args.max_item ?? 150);
  const includePageBody = args.include_page_body !== false;
  const user = await canvasGet('/users/self') as any;
  const userId = String(user.id);

  const [
    course,
    module,
    assignment,
    discussionStub,
    announcement,
    file,
    pageStub,
    plannerItem,
    todoItem,
    missingSubmission,
    calendarItem,
  ] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'syllabus_body' })),
    safe(() => canvasPaginate<any>(`/courses/${id}/modules`, { 'include[]': 'items' })),
    safe(() => canvasPaginate<any>(`/courses/${id}/assignments`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/discussion_topics`)),
    safe(() => canvasPaginate<any>(`/announcements`, { 'context_codes[]': `course_${id}` })),
    safe(() => canvasPaginate<any>(`/courses/${id}/files`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/pages`)),
    safe(() => canvasPaginate<any>('/planner/items', {
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': `course_${id}`,
      filter: 'incomplete_items',
    })),
    safe(() => canvasPaginate<any>('/users/self/todo', { 'include[]': 'ungraded_quizzes' })),
    safe(() => canvasPaginate<any>(`/users/${userId}/missing_submissions`, {
      'course_ids[]': id,
      'include[]': ['planner_overrides', 'course'],
      'filter[]': ['submittable', 'current_grading_period'],
    })),
    safe(() => canvasPaginate<any>('/users/self/calendar_events', {
      type: 'assignment',
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': `course_${id}`,
    })),
  ]);

  const moduleValue = (module.value as any[]) ?? [];
  const assignmentValue = limitRow((assignment.value as any[]) ?? [], maxItem);
  const fileValue = (file.value as any[]) ?? [];
  const fileById = new Map(fileValue.map((one: any) => [String(one?.id), one]));
  const courseValue = course.value as any;
  const queue = {
    planner_item: (plannerItem.value as any[]) ?? [],
    todo_item: ((todoItem.value as any[]) ?? [])
      .filter((one: any) => String(one?.assignment?.course_id ?? one?.course_id ?? '') === String(id)),
    missing_submission: (missingSubmission.value as any[]) ?? [],
    calendar_item: (calendarItem.value as any[]) ?? [],
  };

  const pageUrl = new Set<string>([
    ...(((pageStub.value as any[]) ?? []).map((one: any) => one?.url).filter(Boolean)),
    ...moduleValue.flatMap((one: any) => (
      Array.isArray(one?.items)
        ? one.items.filter((item: any) => item?.type === 'Page' && item?.page_url).map((item: any) => item.page_url)
        : []
    )),
  ]);
  const page = includePageBody
    ? await pool(limitRow([...pageUrl], maxItem), async (url) => {
      const result = await safe(() => canvasGet(`/courses/${id}/pages/${url}`));
      return result.value ?? { url, error: result.error };
    }, 6)
    : limitRow((pageStub.value as any[]) ?? [], maxItem);
  const discussion = await pool(limitRow((discussionStub.value as any[]) ?? [], maxItem), async (one: any) => {
    const result = await safe(() => canvasGet(`/courses/${id}/discussion_topics/${one.id}`));
    return result.value ?? one;
  }, 6);

  const referencedFileId = uniqueText([
    ...extractFileId(courseValue?.syllabus_body),
    ...assignmentValue.flatMap((one: any) => extractFileId(one?.description)),
    ...(discussion as any[]).flatMap((one: any) => extractFileId(one?.message)),
    ...(page as any[]).flatMap((one: any) => extractFileId(one?.body)),
    ...(((announcement.value as any[]) ?? [])).flatMap((one: any) => extractFileId(one?.message)),
  ]);
  await fillFileById(fileById, referencedFileId);

  const material: Record<string, unknown>[] = [];
  const pushMaterial = (row: Record<string, unknown>) => {
    material.push(row);
  };

  const syllabusText = courseValue?.syllabus_body ?? '';
  const syllabusLink = extractEmbeds(syllabusText, { type: 'syllabus', id, title: courseValue?.name });
  const syllabusFileId = extractFileId(syllabusText);
  if (syllabusText || syllabusLink.length > 0) {
    const signal = materialSignal(syllabusText, syllabusLink, syllabusFileId);
    pushMaterial({
      material_id: `syllabus:${id}`,
      ...compactMaterialSource('syllabus', courseValue, 'Syllabus'),
      item_type: 'syllabus',
      timeline: { due_at: null, unlock_at: null, lock_at: null, peer_review_due_at: null },
      submission_type: [],
      file_id: syllabusFileId,
      file_type: materialFileType(syllabusFileId, fileById),
      module: [],
      queue_signal: queueSignal(null, queue),
      link: syllabusLink,
      ...signal,
    });
  }

  for (const one of assignmentValue) {
    const text = String(one?.description ?? '');
    const link = extractEmbeds(text, { type: 'assignment', id: one?.id, title: one?.name });
    const fileId = extractFileId(text);
    const isGroup = !!one?.group_category_id || !!one?.grade_group_students_individually;
    const submissionType = Array.isArray(one?.submission_types) ? one.submission_types : [];
    const signal = materialSignal(text, link, fileId, { is_group: isGroup, submission_type: submissionType });
    pushMaterial({
      material_id: `assignment:${one?.id}`,
      ...compactMaterialSource('assignment', one),
      item_type: 'assignment',
      timeline: {
        due_at: one?.due_at ?? null,
        unlock_at: one?.unlock_at ?? null,
        lock_at: one?.lock_at ?? null,
        peer_review_due_at: one?.peer_reviews_due_at ?? null,
      },
      submission_type: submissionType,
      file_id: fileId,
      file_type: materialFileType(fileId, fileById),
      module: moduleForContent(moduleValue, 'Assignment', one?.id),
      queue_signal: queueSignal(one?.id, queue),
      group_context: {
        group_category_id: one?.group_category_id ?? null,
        is_grade_group_student_individually: !!one?.grade_group_students_individually,
      },
      link,
      ...signal,
    });
  }

  for (const one of discussion as any[]) {
    const text = String(one?.message ?? '');
    const link = extractEmbeds(text, { type: 'discussion', id: one?.id, title: one?.title });
    const fileId = extractFileId(text);
    const submissionType = Array.isArray(one?.assignment?.submission_types) ? one.assignment.submission_types : [];
    const signal = materialSignal(text, link, fileId, { is_discussion: true, submission_type: submissionType });
    pushMaterial({
      material_id: `discussion:${one?.id}`,
      ...compactMaterialSource('discussion', one),
      item_type: 'discussion',
      timeline: {
        due_at: one?.assignment?.due_at ?? one?.todo_date ?? null,
        unlock_at: one?.delayed_post_at ?? null,
        lock_at: one?.lock_at ?? null,
        peer_review_due_at: null,
      },
      submission_type: submissionType,
      file_id: fileId,
      file_type: materialFileType(fileId, fileById),
      module: moduleForContent(moduleValue, 'Discussion', one?.id),
      queue_signal: queueSignal(one?.assignment_id ?? one?.assignment?.id, queue),
      discussion_context: {
        discussion_type: one?.discussion_type ?? null,
        posted_at: one?.posted_at ?? null,
        reply_count: one?.discussion_subentry_count ?? null,
        is_require_initial_post: !!one?.require_initial_post,
      },
      link,
      ...signal,
    });
  }

  for (const one of limitRow(page as any[], maxItem)) {
    const text = String(one?.body ?? '');
    const link = extractEmbeds(text, { type: 'page', id: one?.url, title: one?.title });
    const fileId = extractFileId(text);
    const signal = materialSignal(text, link, fileId);
    pushMaterial({
      material_id: `page:${one?.url ?? one?.page_id ?? one?.id}`,
      ...compactMaterialSource('page', one),
      item_type: 'page',
      timeline: { due_at: null, unlock_at: null, lock_at: null, peer_review_due_at: null },
      submission_type: [],
      file_id: fileId,
      file_type: materialFileType(fileId, fileById),
      module: moduleForPage(moduleValue, one?.url),
      queue_signal: queueSignal(null, queue),
      link,
      ...signal,
    });
  }

  for (const one of limitRow((announcement.value as any[]) ?? [], maxItem)) {
    const text = String(one?.message ?? '');
    const link = extractEmbeds(text, { type: 'announcement', id: one?.id, title: one?.title });
    const fileId = extractFileId(text);
    const signal = materialSignal(text, link, fileId);
    pushMaterial({
      material_id: `announcement:${one?.id}`,
      ...compactMaterialSource('announcement', one),
      item_type: 'announcement',
      timeline: { due_at: null, unlock_at: one?.posted_at ?? one?.delayed_post_at ?? null, lock_at: null, peer_review_due_at: null },
      submission_type: [],
      file_id: fileId,
      file_type: materialFileType(fileId, fileById),
      module: [],
      queue_signal: queueSignal(null, queue),
      link,
      ...signal,
    });
  }

  for (const one of limitRow(fileValue, maxItem)) {
    const link = one?.url ? [{ kind: classify(String(one.url)), url: one.url, source: { type: 'file', id: one?.id, title: one?.display_name ?? one?.filename } }] : [];
    const type = fileType(one);
    pushMaterial({
      material_id: `file:${one?.id}`,
      ...compactMaterialSource('file', one),
      item_type: 'file',
      timeline: { due_at: null, unlock_at: one?.unlock_at ?? null, lock_at: one?.locked_at ?? null, peer_review_due_at: null },
      submission_type: [],
      file_id: one?.id ? [String(one.id)] : [],
      file_type: type ? [type] : [],
      module: moduleForContent(moduleValue, 'File', one?.id),
      queue_signal: queueSignal(null, queue),
      link,
      reading: {
        is_reading: ['pdf', 'docx', 'presentation', 'html', 'text'].includes(String(type)),
        evidence: null,
        link_count: link.length,
        file_count: one?.id ? 1 : 0,
      },
      reply_requirement: { is_required: false, evidence: null },
      work_mode: { is_group: false, evidence: null },
      deadline: { evidence: null },
    });
  }

  const readingIndex = await readingIndexForMaterial(material, fileById, {
    extract_reading: args.extract_reading,
    extract_material_id: args.extract_material_id,
    max_extract_file: args.max_extract_file,
    max_chars: args.max_chars,
  });

  const endpoint = [
    ['course', course],
    ['module', module],
    ['assignment', assignment],
    ['discussion', discussionStub],
    ['announcement', announcement],
    ['file', file],
    ['page', pageStub],
    ['planner_item', plannerItem],
    ['todo_item', todoItem],
    ['missing_submission', missingSubmission],
    ['calendar_item', calendarItem],
  ].map(([name, result]) => {
    const one = result as { value: unknown; error: string | null };
    return {
      name,
      status: endpointStatus(one.error),
      count: rowCount(one.value),
      key: keySample(one.value),
      error: one.error,
    };
  });

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    date_window: { start_date: startDate, end_date: endDate },
    endpoint,
    material_count: material.length,
    reading_count: material.filter((one: any) => one?.reading?.is_reading).length,
    reading_source_count: readingIndex.length,
    extracted_reading_count: readingIndex.filter((one: any) => !['metadata-only', 'not-requested', 'external-link', 'error'].includes(String(one?.extraction_mode))).length,
    reply_requirement_count: material.filter((one: any) => one?.reply_requirement?.is_required).length,
    group_work_count: material.filter((one: any) => one?.work_mode?.is_group).length,
    source_count: {
      assignment_count: assignmentValue.length,
      discussion_count: discussion.length,
      page_count: page.length,
      announcement_count: ((announcement.value as any[]) ?? []).length,
      file_count: fileValue.length,
      module_count: moduleValue.length,
    },
    reading_index: readingIndex,
    material: limitRow(material, maxItem * 5),
  };
}

async function getCourseSearchContext(args: {
  course_id?: string | number;
  query?: unknown;
  filter?: unknown;
  include_module?: boolean;
  include_status?: boolean;
  include_recipient_search?: boolean;
  include_public_course_search?: boolean;
  max_query?: number;
  max_result?: number;
  max_recipient?: number;
  max_public_course?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxQuery = Math.max(0, Number(args.max_query ?? 5));
  const maxResult = Math.max(0, Number(args.max_result ?? 20));
  const maxRecipient = Math.max(0, Number(args.max_recipient ?? 20));
  const maxPublicCourse = Math.max(0, Number(args.max_public_course ?? 10));
  const maxChar = Number(args.max_chars ?? 500);
  const query = limitRow(normalizeMaybeStringArray(args.query, 'query'), maxQuery);
  const effectiveQuery = query.length > 0
    ? query
    : ['reading', 'quiz', 'assignment', 'deadline', 'group'];
  const requestedFilter = normalizeMaybeStringArray(args.filter, 'filter')
    .filter((one) => ['pages', 'assignments', 'announcements', 'discussion_topics'].includes(one));
  const filter = requestedFilter.length > 0
    ? requestedFilter
    : ['pages', 'assignments', 'announcements', 'discussion_topics'];
  const include: string[] = [];
  if (args.include_status !== false) include.push('status');
  if (args.include_module !== false) include.push('modules');
  const course = await safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'term' }));
  const courseValue = course.value as any;
  const courseSearchTerm = courseValue?.course_code ?? courseValue?.name ?? String(id);

  const search = await pool(effectiveQuery, async (one) => {
    const param: Record<string, CanvasParamValue> = {
      q: one,
      'filter[]': filter,
      ...(include.length > 0 ? { 'include[]': include } : {}),
    };
    const result = await safe(() => canvasGet(`/courses/${id}/smartsearch`, param));
    const rawSearch = result.value as any;
    const resultSource = Array.isArray(rawSearch)
      ? rawSearch
      : Array.isArray(rawSearch?.results)
        ? rawSearch.results
        : rawSearch
          ? [rawSearch]
          : [];
    const resultValue = limitRow(resultSource, maxResult);
    return {
      query: one,
      status: result.error ? endpointStatus(result.error) : 'ok',
      result_count: resultSource.length,
      returned_result_count: resultValue.length,
      result: resultValue.map((row: any) => compactCourseSearchResult(row, maxChar)),
      key: keySample(rawSearch),
      error: result.error,
    };
  }, 3);
  const recipientSearch = args.include_recipient_search === false
    ? { value: null, error: 'recipient search skipped by caller' }
    : await safe(() => canvasPaginate<any>('/search/recipients', {
      search: courseSearchTerm,
      context: `course_${id}`,
      type: 'context',
      'permissions[]': 'send_messages',
    }));
  const recipientSearchValue = limitRow((recipientSearch.value as any[]) ?? [], maxRecipient);
  const publicCourseSearch = args.include_public_course_search === false
    ? { value: null, error: 'public course search skipped by caller' }
    : await safe(() => canvasPaginate<any>('/search/all_courses', {
      search: courseSearchTerm,
      public_only: true,
    }));
  const publicCourseSearchValue = limitRow((publicCourseSearch.value as any[]) ?? [], maxPublicCourse);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      ...search.map((one: any) => ({
        name: `smart_search:${one.query}`,
        status: one.status,
        count: one.result_count,
        key: one.key,
        error: one.error,
      })),
      {
        name: 'search_recipient',
        status: recipientSearch.error?.includes('skipped by caller') ? 'skipped' : endpointStatus(recipientSearch.error),
        count: rowCount(recipientSearch.value),
        key: keySample(recipientSearch.value),
        error: recipientSearch.error,
      },
      {
        name: 'public_course_search',
        status: publicCourseSearch.error?.includes('skipped by caller') ? 'skipped' : endpointStatus(publicCourseSearch.error),
        count: rowCount(publicCourseSearch.value),
        key: keySample(publicCourseSearch.value),
        error: publicCourseSearch.error,
      },
    ],
    smart_search_status: search.some((one: any) => one.status === 'ok')
      ? 'ok'
      : search.some((one: any) => one.status === 'error')
        ? 'error'
        : 'blocked_or_absent',
    search_recipient_status: recipientSearch.error?.includes('skipped by caller') ? 'skipped' : endpointStatus(recipientSearch.error),
    search_recipient_count: rowCount(recipientSearch.value),
    returned_search_recipient_count: recipientSearchValue.length,
    public_course_search_status: publicCourseSearch.error?.includes('skipped by caller') ? 'skipped' : endpointStatus(publicCourseSearch.error),
    public_course_search_count: rowCount(publicCourseSearch.value),
    returned_public_course_search_count: publicCourseSearchValue.length,
    query_count: effectiveQuery.length,
    filter,
    include,
    search_recipient: recipientSearchValue.map(compactSearchRecipient),
    public_course_search: publicCourseSearchValue.map(compactPublicCourseSearch),
    result_count: search.reduce((sum: number, one: any) => sum + Number(one.result_count ?? 0), 0),
    returned_result_count: search.reduce((sum: number, one: any) => sum + Number(one.returned_result_count ?? 0), 0),
    search,
    note: 'Canvas Smart Search and Search API results are discovery context only. Recipient search is course-scoped and context-only by default; assignment submission and due-date tools remain authoritative.',
  };
}

async function getCourseMediaContext(args: {
  course_id?: string | number;
  include_group_media?: boolean;
  include_kaltura_config?: boolean;
  max_media?: number;
  max_group?: number;
  max_group_media?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeGroupMedia = args.include_group_media !== false;
  const includeKalturaConfig = args.include_kaltura_config !== false;
  const maxMedia = Math.max(0, Number(args.max_media ?? 80));
  const maxGroup = Math.max(0, Number(args.max_group ?? 10));
  const maxGroupMedia = Math.max(0, Number(args.max_group_media ?? 40));
  const [courseMedia, ownGroup, kalturaConfig] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/media_attachments`, { sort: 'title' })),
    includeGroupMedia
      ? safe(() => canvasPaginate<any>(`/courses/${id}/groups`, { only_own_groups: true }))
      : Promise.resolve({ value: [], error: null }),
    includeKalturaConfig
      ? safe(() => canvasGet('/services/kaltura'))
      : Promise.resolve({ value: null, error: 'include_kaltura_config false; Kaltura config skipped' }),
  ]);
  const groupValue = limitRow((ownGroup.value as any[]) ?? [], maxGroup);
  const groupMedia = includeGroupMedia
    ? await pool(groupValue, async (group) => {
      const result = await safe(() => canvasPaginate<any>(`/groups/${group?.id}/media_attachments`, { sort: 'title' }));
      const media = limitRow((result.value as any[]) ?? [], maxGroupMedia);
      return {
        group_id: group?.id ?? null,
        group_name: group?.name ?? null,
        status: result.error ? endpointStatus(result.error) : 'ok',
        media_count: rowCount(result.value),
        returned_media_count: media.length,
        media: media.map((one: any) => compactMediaAttachment(one, {
          source_type: 'group',
          group_id: group?.id ?? null,
          group_name: group?.name ?? null,
        })),
        key: keySample(result.value),
        error: result.error,
      };
    }, 4)
    : [];
  const courseMediaValue = limitRow((courseMedia.value as any[]) ?? [], maxMedia);
  const media = [
    ...courseMediaValue.map((one: any) => compactMediaAttachment(one, {
      source_type: 'course',
      course_id: id,
    })),
    ...groupMedia.flatMap((one: any) => one.media),
  ];

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      {
        name: 'course_media_attachment',
        status: courseMedia.error ? endpointStatus(courseMedia.error) : 'ok',
        count: rowCount(courseMedia.value),
        key: keySample(courseMedia.value),
        error: courseMedia.error,
      },
      {
        name: 'course_own_group',
        status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupMedia ? 'ok' : 'skipped'),
        count: rowCount(ownGroup.value),
        key: keySample(ownGroup.value),
        error: ownGroup.error,
      },
      {
        name: 'kaltura_config',
        status: kalturaConfig.error?.includes('false;') ? 'skipped' : endpointStatus(kalturaConfig.error),
        count: rowCount(kalturaConfig.value),
        key: keySample(kalturaConfig.value),
        error: kalturaConfig.error,
      },
      ...groupMedia.map((one: any) => ({
        name: `group_media_attachment:${one.group_id ?? 'unknown'}`,
        status: one.status,
        count: one.media_count,
        key: one.key,
        error: one.error,
      })),
    ],
    course_media_status: courseMedia.error ? endpointStatus(courseMedia.error) : 'ok',
    course_media_count: rowCount(courseMedia.value),
    returned_course_media_count: courseMediaValue.length,
    kaltura_config_status: kalturaConfig.error?.includes('false;')
      ? 'skipped'
      : kalturaConfig.error ? endpointStatus(kalturaConfig.error) : 'ok',
    has_kaltura_config: !!kalturaConfig.value,
    kaltura_config: compactKalturaConfig(kalturaConfig.value),
    group_status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupMedia ? 'ok' : 'skipped'),
    group_count: groupValue.length,
    group_media_status: groupMedia.some((one: any) => one.status === 'error')
      ? 'error'
      : groupMedia.some((one: any) => one.status === 'ok')
        ? 'ok'
        : includeGroupMedia
          ? 'blocked_or_absent'
          : 'skipped',
    group_media_count: groupMedia.reduce((sum: number, one: any) => sum + Number(one.media_count ?? 0), 0),
    returned_group_media_count: groupMedia.reduce((sum: number, one: any) => sum + Number(one.returned_media_count ?? 0), 0),
    media_count: media.length,
    audio_media_count: media.filter((one: any) => String(one?.media_type ?? one?.content_type ?? '').toLowerCase().includes('audio')).length,
    video_media_count: media.filter((one: any) => String(one?.media_type ?? one?.content_type ?? '').toLowerCase().includes('video')).length,
    group_media: groupMedia,
    media,
    note: 'Canvas media attachments and Kaltura plugin config are course/group material evidence for recordings or audio/video resources. They are not submission truth, do not prove completion, and never create Kaltura sessions or upload media.',
  };
}

async function getCourseConferenceContext(args: {
  course_id?: string | number;
  include_user_conference?: boolean;
  include_group_conference?: boolean;
  state?: string;
  max_conference?: number;
  max_group?: number;
  max_group_conference?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeUserConference = args.include_user_conference !== false;
  const includeGroupConference = args.include_group_conference !== false;
  const maxConference = Math.max(0, Number(args.max_conference ?? 80));
  const maxGroup = Math.max(0, Number(args.max_group ?? 10));
  const maxGroupConference = Math.max(0, Number(args.max_group_conference ?? 40));
  const maxChar = Number(args.max_chars ?? 600);
  const param: Record<string, CanvasParamValue> = args.state ? { state: args.state } : {};
  const [courseConference, userConference, ownGroup] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/conferences`, param)),
    includeUserConference
      ? safe(() => canvasGet('/conferences', param))
      : Promise.resolve({ value: null, error: null }),
    includeGroupConference
      ? safe(() => canvasPaginate<any>(`/courses/${id}/groups`, { only_own_groups: true }))
      : Promise.resolve({ value: [], error: null }),
  ]);
  const courseConferenceSource = conferenceList(courseConference.value);
  const userConferenceSource = conferenceList(userConference.value);
  const groupValue = limitRow((ownGroup.value as any[]) ?? [], maxGroup);
  const groupConference = includeGroupConference
    ? await pool(groupValue, async (group) => {
      const result = await safe(() => canvasGet(`/groups/${group?.id}/conferences`, param));
      const conferenceSource = conferenceList(result.value);
      const conference = limitRow(conferenceSource, maxGroupConference);
      return {
        group_id: group?.id ?? null,
        group_name: group?.name ?? null,
        status: result.error ? endpointStatus(result.error) : 'ok',
        conference_count: conferenceSource.length,
        returned_conference_count: conference.length,
        conference: conference.map((one: any) => compactConference(one, {
          source_type: 'group',
          group_id: group?.id ?? null,
          group_name: group?.name ?? null,
        }, maxChar)),
        key: keySample(result.value),
        error: result.error,
      };
    }, 4)
    : [];
  const courseConferenceValue = limitRow(courseConferenceSource, maxConference);
  const userConferenceValue = limitRow(userConferenceSource, maxConference);
  const conference = [
    ...courseConferenceValue.map((one: any) => compactConference(one, {
      source_type: 'course',
      course_id: id,
    }, maxChar)),
    ...userConferenceValue.map((one: any) => compactConference(one, {
      source_type: 'user',
    }, maxChar)),
    ...groupConference.flatMap((one: any) => one.conference),
  ];

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    state: args.state ?? null,
    endpoint: [
      {
        name: 'course_conference',
        status: courseConference.error ? endpointStatus(courseConference.error) : 'ok',
        count: courseConferenceSource.length,
        key: keySample(courseConference.value),
        error: courseConference.error,
      },
      {
        name: 'user_conference',
        status: userConference.error ? endpointStatus(userConference.error) : (includeUserConference ? 'ok' : 'skipped'),
        count: userConferenceSource.length,
        key: keySample(userConference.value),
        error: userConference.error,
      },
      {
        name: 'course_own_group',
        status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupConference ? 'ok' : 'skipped'),
        count: rowCount(ownGroup.value),
        key: keySample(ownGroup.value),
        error: ownGroup.error,
      },
      ...groupConference.map((one: any) => ({
        name: `group_conference:${one.group_id ?? 'unknown'}`,
        status: one.status,
        count: one.conference_count,
        key: one.key,
        error: one.error,
      })),
    ],
    course_conference_status: courseConference.error ? endpointStatus(courseConference.error) : 'ok',
    course_conference_count: courseConferenceSource.length,
    returned_course_conference_count: courseConferenceValue.length,
    user_conference_status: userConference.error ? endpointStatus(userConference.error) : (includeUserConference ? 'ok' : 'skipped'),
    user_conference_count: userConferenceSource.length,
    returned_user_conference_count: userConferenceValue.length,
    group_status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupConference ? 'ok' : 'skipped'),
    group_count: groupValue.length,
    group_conference_status: groupConference.some((one: any) => one.status === 'error')
      ? 'error'
      : groupConference.some((one: any) => one.status === 'ok')
        ? 'ok'
        : includeGroupConference
          ? 'blocked_or_absent'
          : 'skipped',
    group_conference_count: groupConference.reduce((sum: number, one: any) => sum + Number(one.conference_count ?? 0), 0),
    returned_group_conference_count: groupConference.reduce((sum: number, one: any) => sum + Number(one.returned_conference_count ?? 0), 0),
    conference_count: conference.length,
    live_conference_count: conference.filter((one: any) => one?.is_live).length,
    recorded_conference_count: conference.filter((one: any) => one?.is_recorded).length,
    group_conference: groupConference,
    conference,
    note: 'Canvas Conferences are class meeting or recording context. They are not submission truth and this tool does not start, join, create, edit, or delete conferences.',
  };
}

async function getCourseExportContext(args: {
  course_id?: string | number;
  include_user_export?: boolean;
  include_group_export?: boolean;
  include_epub_export?: boolean;
  include_progress?: boolean;
  course_report_type?: string;
  course_report_id?: string | number;
  content_migration_id?: string | number;
  migration_issue_id?: string | number;
  max_export?: number;
  max_group?: number;
  max_group_export?: number;
  max_epub_export?: number;
  max_migration?: number;
  max_migration_issue?: number;
  max_progress?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeUserExport = args.include_user_export !== false;
  const includeGroupExport = args.include_group_export !== false;
  const includeEpubExport = args.include_epub_export !== false;
  const includeProgress = args.include_progress !== false;
  const maxExport = Math.max(0, Number(args.max_export ?? 40));
  const maxGroup = Math.max(0, Number(args.max_group ?? 10));
  const maxGroupExport = Math.max(0, Number(args.max_group_export ?? 20));
  const maxEpubExport = Math.max(0, Number(args.max_epub_export ?? 80));
  const maxMigration = Math.max(0, Number(args.max_migration ?? 20));
  const maxMigrationIssue = Math.max(0, Number(args.max_migration_issue ?? 20));
  const maxProgress = Math.max(0, Number(args.max_progress ?? 20));
  const courseReportType = typeof args.course_report_type === 'string' && args.course_report_type.trim()
    ? args.course_report_type.trim()
    : null;
  const courseReportId = args.course_report_id ? String(args.course_report_id) : null;
  const requestedMigrationId = args.content_migration_id ? String(args.content_migration_id) : null;
  const migrationIssueId = args.migration_issue_id ? String(args.migration_issue_id) : null;
  const [courseExport, userExport, epubExport, ownGroup, courseReportLast, courseReportDetail, contentMigration, migrationMigrator] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/content_exports`)),
    includeUserExport
      ? safe(() => canvasPaginate<any>('/users/self/content_exports'))
      : Promise.resolve({ value: [], error: null }),
    includeEpubExport
      ? safe(() => canvasGet('/epub_exports'))
      : Promise.resolve({ value: [], error: null }),
    includeGroupExport
      ? safe(() => canvasPaginate<any>(`/courses/${id}/groups`, { only_own_groups: true }))
      : Promise.resolve({ value: [], error: null }),
    courseReportType
      ? safe(() => canvasGet(`/courses/${id}/reports/${encodeURIComponent(courseReportType)}`))
      : Promise.resolve({ value: null, error: null }),
    courseReportType && courseReportId
      ? safe(() => canvasGet(`/courses/${id}/reports/${encodeURIComponent(courseReportType)}/${encodeURIComponent(courseReportId)}`))
      : Promise.resolve({ value: null, error: null }),
    safe(() => canvasPaginate<any>(`/courses/${id}/content_migrations`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/content_migrations/migrators`)),
  ]);
  const groupValue = limitRow((ownGroup.value as any[]) ?? [], maxGroup);
  const groupExport = includeGroupExport
    ? await pool(groupValue, async (group) => {
      const result = await safe(() => canvasPaginate<any>(`/groups/${group?.id}/content_exports`));
      const contentExport = limitRow((result.value as any[]) ?? [], maxGroupExport);
      return {
        group_id: group?.id ?? null,
        group_name: group?.name ?? null,
        status: result.error ? endpointStatus(result.error) : 'ok',
        export_count: rowCount(result.value),
        returned_export_count: contentExport.length,
        export: contentExport.map((one: any) => compactContentExport(one, {
          source_type: 'group',
          group_id: group?.id ?? null,
          group_name: group?.name ?? null,
        })),
        key: keySample(result.value),
        error: result.error,
      };
    }, 4)
    : [];
  const courseExportValue = limitRow((courseExport.value as any[]) ?? [], maxExport);
  const userExportValue = limitRow((userExport.value as any[]) ?? [], maxExport);
  const rawEpubExport = epubExport.value as any;
  const epubExportSource = Array.isArray(rawEpubExport)
    ? rawEpubExport
    : Array.isArray(rawEpubExport?.courses)
      ? rawEpubExport.courses
      : rawEpubExport
        ? [rawEpubExport]
        : [];
  const epubExportValue = limitRow(epubExportSource, maxEpubExport);
  const selectedEpubExport = epubExportValue.find((one: any) => String(one?.id ?? one?.course_id ?? '') === id) ?? null;
  const contentMigrationValue = limitRow((contentMigration.value as any[]) ?? [], maxMigration);
  const selectedMigration = requestedMigrationId
    ? contentMigrationValue.find((one: any) => String(one?.id ?? '') === requestedMigrationId) ?? { id: requestedMigrationId }
    : contentMigrationValue.find((one: any) => one?.id) ?? null;
  const selectedMigrationId = selectedMigration?.id ? String(selectedMigration.id) : null;
  const [contentMigrationDetail, migrationIssue, selectiveData, assetIdMapping] = selectedMigrationId
    ? await Promise.all([
      safe(() => canvasGet(`/courses/${id}/content_migrations/${selectedMigrationId}`)),
      safe(() => canvasPaginate<any>(`/courses/${id}/content_migrations/${selectedMigrationId}/migration_issues`)),
      safe(() => canvasGet(`/courses/${id}/content_migrations/${selectedMigrationId}/selective_data`)),
      safe(() => canvasGet(`/courses/${id}/content_migrations/${selectedMigrationId}/asset_id_mapping`)),
    ])
    : [
      { value: null, error: null },
      { value: [], error: null },
      { value: null, error: null },
      { value: null, error: null },
    ];
  const migrationIssueValue = limitRow((migrationIssue.value as any[]) ?? [], maxMigrationIssue);
  const selectedMigrationIssue = migrationIssueId
    ? migrationIssueValue.find((one: any) => String(one?.id ?? '') === migrationIssueId) ?? { id: migrationIssueId }
    : migrationIssueValue.find((one: any) => one?.id) ?? null;
  const selectedMigrationIssueId = selectedMigrationIssue?.id ? String(selectedMigrationIssue.id) : null;
  const migrationIssueDetail = selectedMigrationId && selectedMigrationIssueId
    ? await safe(() => canvasGet(`/courses/${id}/content_migrations/${selectedMigrationId}/migration_issues/${selectedMigrationIssueId}`))
    : { value: null, error: null };
  const courseReportLastValue = compactCourseReport(courseReportLast.value, {
    source_type: 'course_report_last',
    course_id: id,
    report_type: courseReportType,
  });
  const courseReportDetailValue = compactCourseReport(courseReportDetail.value, {
    source_type: 'course_report_detail',
    course_id: id,
    report_type: courseReportType,
    report_id: courseReportId,
  });
  const courseReport = [
    ...(courseReportLastValue ? [courseReportLastValue] : []),
    ...(courseReportDetailValue ? [courseReportDetailValue] : []),
  ];
  const contentMigrationRow = contentMigrationValue.map((one: any) => compactContentMigration(one, {
    source_type: 'content_migration',
    course_id: id,
  }));
  const contentMigrationDetailValue = contentMigrationDetail.value
    ? compactContentMigration(contentMigrationDetail.value, {
      source_type: 'content_migration_detail',
      course_id: id,
      migration_id: selectedMigrationId,
    })
    : null;
  const migrationIssueRow = migrationIssueValue.map((one: any) => compactMigrationIssue(one, {
    source_type: 'migration_issue',
    course_id: id,
    migration_id: selectedMigrationId,
  }));
  const migrationIssueDetailValue = migrationIssueDetail.value
    ? compactMigrationIssue(migrationIssueDetail.value, {
      source_type: 'migration_issue_detail',
      course_id: id,
      migration_id: selectedMigrationId,
      issue_id: selectedMigrationIssueId,
    })
    : null;
  const migrationMigratorRow = ((migrationMigrator.value as any[]) ?? []).map(compactMigrationMigrator);
  const contentExport = [
    ...courseExportValue.map((one: any) => compactContentExport(one, {
      source_type: 'course',
      course_id: id,
    })),
    ...userExportValue.map((one: any) => compactContentExport(one, {
      source_type: 'user',
    })),
    ...groupExport.flatMap((one: any) => one.export),
  ];
  const epubExportRow = epubExportValue.map(compactEpubExport);
  const progressSource = limitRow([
    ...contentExport.map((one: any) => ({
      source_type: one?.source?.source_type ?? 'content_export',
      export_id: one?.export_id ?? null,
      progress_url: one?.progress_url ?? null,
      course_id: one?.source?.course_id ?? id,
      group_id: one?.source?.group_id ?? null,
    })),
    ...epubExportRow.map((one: any) => ({
      source_type: 'epub_export',
      export_id: one?.export_id ?? null,
      progress_url: one?.progress_url ?? null,
      course_id: one?.course_id ?? id,
    })),
    ...[
      ...contentMigrationRow,
      ...(contentMigrationDetailValue ? [contentMigrationDetailValue] : []),
    ].map((one: any) => ({
      source_type: one?.source?.source_type ?? 'content_migration',
      migration_id: one?.migration_id ?? null,
      progress_url: one?.progress_url ?? null,
      course_id: id,
    })),
  ].filter((one: any) => one.progress_url), maxProgress);
  const progress = includeProgress
    ? await pool(progressSource, async (source: any) => {
      const target = progressTargetFromValue(source.progress_url, id);
      if (!target) {
        return {
          source,
          status: 'skipped',
          progress: null,
          error: 'progress_url did not match a supported Canvas Progress endpoint',
        };
      }
      const result = await safe(() => target.kind === 'lti'
        ? canvasApiGet(`/api/lti/courses/${target.course_id ?? id}/progress/${target.progress_id}`)
        : canvasGet(`/progress/${target.progress_id}`));
      return {
        source,
        status: result.error ? endpointStatus(result.error) : 'ok',
        progress_id: target.progress_id,
        progress_kind: target.kind,
        progress: result.value ? compactProgress(result.value, source) : null,
        key: keySample(result.value),
        error: result.error,
      };
    }, 4)
    : [];
  const progressStatus = !includeProgress
    ? 'skipped'
    : progressSource.length === 0
      ? 'skipped'
      : progress.some((one: any) => one.status === 'error')
        ? 'error'
        : progress.some((one: any) => one.status === 'ok')
          ? 'ok'
          : progress.some((one: any) => one.status === 'blocked_or_absent')
            ? 'blocked_or_absent'
            : 'skipped';

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      {
        name: 'course_content_export',
        status: courseExport.error ? endpointStatus(courseExport.error) : 'ok',
        count: rowCount(courseExport.value),
        key: keySample(courseExport.value),
        error: courseExport.error,
      },
      {
        name: 'user_content_export',
        status: userExport.error ? endpointStatus(userExport.error) : (includeUserExport ? 'ok' : 'skipped'),
        count: rowCount(userExport.value),
        key: keySample(userExport.value),
        error: userExport.error,
      },
      {
        name: 'epub_export',
        status: epubExport.error ? endpointStatus(epubExport.error) : (includeEpubExport ? 'ok' : 'skipped'),
        count: rowCount(epubExport.value),
        key: keySample(epubExport.value),
        error: epubExport.error,
      },
      {
        name: 'course_report_last',
        status: courseReportLast.error ? endpointStatus(courseReportLast.error) : (courseReportType ? 'ok' : 'skipped'),
        count: rowCount(courseReportLast.value),
        key: keySample(courseReportLast.value),
        error: courseReportLast.error,
      },
      {
        name: 'course_report_detail',
        status: courseReportDetail.error ? endpointStatus(courseReportDetail.error) : (courseReportType && courseReportId ? 'ok' : 'skipped'),
        count: rowCount(courseReportDetail.value),
        key: keySample(courseReportDetail.value),
        error: courseReportDetail.error,
      },
      {
        name: 'content_migration',
        status: contentMigration.error ? endpointStatus(contentMigration.error) : 'ok',
        count: rowCount(contentMigration.value),
        key: keySample(contentMigration.value),
        error: contentMigration.error,
      },
      {
        name: 'content_migration_detail',
        status: contentMigrationDetail.error ? endpointStatus(contentMigrationDetail.error) : (selectedMigrationId ? 'ok' : 'skipped'),
        count: rowCount(contentMigrationDetail.value),
        key: keySample(contentMigrationDetail.value),
        error: contentMigrationDetail.error,
      },
      {
        name: 'migration_issue',
        status: migrationIssue.error ? endpointStatus(migrationIssue.error) : (selectedMigrationId ? 'ok' : 'skipped'),
        count: rowCount(migrationIssue.value),
        key: keySample(migrationIssue.value),
        error: migrationIssue.error,
      },
      {
        name: 'migration_issue_detail',
        status: migrationIssueDetail.error ? endpointStatus(migrationIssueDetail.error) : (selectedMigrationId && selectedMigrationIssueId ? 'ok' : 'skipped'),
        count: rowCount(migrationIssueDetail.value),
        key: keySample(migrationIssueDetail.value),
        error: migrationIssueDetail.error,
      },
      {
        name: 'migration_migrator',
        status: migrationMigrator.error ? endpointStatus(migrationMigrator.error) : 'ok',
        count: rowCount(migrationMigrator.value),
        key: keySample(migrationMigrator.value),
        error: migrationMigrator.error,
      },
      {
        name: 'migration_selective_data',
        status: selectiveData.error ? endpointStatus(selectiveData.error) : (selectedMigrationId ? 'ok' : 'skipped'),
        count: rowCount(selectiveData.value),
        key: keySample(selectiveData.value),
        error: selectiveData.error,
      },
      {
        name: 'migration_asset_id_mapping',
        status: assetIdMapping.error ? endpointStatus(assetIdMapping.error) : (selectedMigrationId ? 'ok' : 'skipped'),
        count: rowCount(assetIdMapping.value),
        key: keySample(assetIdMapping.value),
        error: assetIdMapping.error,
      },
      {
        name: 'course_own_group',
        status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupExport ? 'ok' : 'skipped'),
        count: rowCount(ownGroup.value),
        key: keySample(ownGroup.value),
        error: ownGroup.error,
      },
      ...groupExport.map((one: any) => ({
        name: `group_content_export:${one.group_id ?? 'unknown'}`,
        status: one.status,
        count: one.export_count,
        key: one.key,
        error: one.error,
      })),
      {
        name: 'progress',
        status: progressStatus,
        count: progressSource.length,
        key: progress.flatMap((one: any) => one.progress?.key ?? []).slice(0, 12),
        error: progress.find((one: any) => one.error)?.error ?? null,
      },
    ],
    course_content_export_status: courseExport.error ? endpointStatus(courseExport.error) : 'ok',
    course_content_export_count: rowCount(courseExport.value),
    returned_course_content_export_count: courseExportValue.length,
    user_content_export_status: userExport.error ? endpointStatus(userExport.error) : (includeUserExport ? 'ok' : 'skipped'),
    user_content_export_count: rowCount(userExport.value),
    returned_user_content_export_count: userExportValue.length,
    epub_export_status: epubExport.error ? endpointStatus(epubExport.error) : (includeEpubExport ? 'ok' : 'skipped'),
    epub_export_count: rowCount(epubExport.value),
    returned_epub_export_count: epubExportRow.length,
    selected_course_epub_export: selectedEpubExport ? compactEpubExport(selectedEpubExport) : null,
    course_report_last_status: courseReportLast.error ? endpointStatus(courseReportLast.error) : (courseReportType ? 'ok' : 'skipped'),
    course_report_last_count: rowCount(courseReportLast.value),
    course_report_detail_status: courseReportDetail.error ? endpointStatus(courseReportDetail.error) : (courseReportType && courseReportId ? 'ok' : 'skipped'),
    course_report_detail_count: rowCount(courseReportDetail.value),
    course_report_count: courseReport.length,
    content_migration_status: contentMigration.error ? endpointStatus(contentMigration.error) : 'ok',
    content_migration_count: rowCount(contentMigration.value),
    returned_content_migration_count: contentMigrationRow.length,
    content_migration_detail_status: contentMigrationDetail.error ? endpointStatus(contentMigrationDetail.error) : (selectedMigrationId ? 'ok' : 'skipped'),
    content_migration_detail_count: rowCount(contentMigrationDetail.value),
    migration_issue_status: migrationIssue.error ? endpointStatus(migrationIssue.error) : (selectedMigrationId ? 'ok' : 'skipped'),
    migration_issue_count: rowCount(migrationIssue.value),
    returned_migration_issue_count: migrationIssueRow.length,
    migration_issue_detail_status: migrationIssueDetail.error ? endpointStatus(migrationIssueDetail.error) : (selectedMigrationId && selectedMigrationIssueId ? 'ok' : 'skipped'),
    migration_issue_detail_count: rowCount(migrationIssueDetail.value),
    migration_migrator_status: migrationMigrator.error ? endpointStatus(migrationMigrator.error) : 'ok',
    migration_migrator_count: rowCount(migrationMigrator.value),
    migration_selective_data_status: selectiveData.error ? endpointStatus(selectiveData.error) : (selectedMigrationId ? 'ok' : 'skipped'),
    migration_selective_data_count: rowCount(selectiveData.value),
    migration_asset_id_mapping_status: assetIdMapping.error ? endpointStatus(assetIdMapping.error) : (selectedMigrationId ? 'ok' : 'skipped'),
    migration_asset_id_mapping_count: rowCount(assetIdMapping.value),
    group_status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupExport ? 'ok' : 'skipped'),
    group_count: groupValue.length,
    group_content_export_status: groupExport.some((one: any) => one.status === 'error')
      ? 'error'
      : groupExport.some((one: any) => one.status === 'ok')
        ? 'ok'
        : includeGroupExport
          ? 'blocked_or_absent'
          : 'skipped',
    group_content_export_count: groupExport.reduce((sum: number, one: any) => sum + Number(one.export_count ?? 0), 0),
    returned_group_content_export_count: groupExport.reduce((sum: number, one: any) => sum + Number(one.returned_export_count ?? 0), 0),
    content_export_count: contentExport.length,
    downloadable_content_export_count: contentExport.filter((one: any) => one?.attachment_url).length,
    downloadable_epub_export_count: epubExportRow.filter((one: any) => one?.attachment_url).length,
    progress_status: progressStatus,
    progress_count: progressSource.length,
    resolved_progress_count: progress.filter((one: any) => one.status === 'ok').length,
    group_content_export: groupExport,
    content_export: contentExport,
    epub_export: epubExportRow,
    course_report: courseReport,
    course_report_last: courseReportLastValue,
    course_report_detail: courseReportDetailValue,
    content_migration: contentMigrationRow,
    content_migration_detail: contentMigrationDetailValue,
    migration_issue: migrationIssueRow,
    migration_issue_detail: migrationIssueDetailValue,
    migration_migrator: migrationMigratorRow,
    migration_selective_data: selectiveData.value ? compactSelectiveData(selectiveData.value) : null,
    migration_asset_id_mapping: assetIdMapping.value ? compactAssetIdMapping(assetIdMapping.value) : null,
    progress,
    note: 'Canvas export context is read-only. This tool lists existing content/ePub export and Content Migration metadata, reads Course Report status only when a report type/id is provided, resolves existing Progress rows when export or migration metadata exposes progress_url, and never starts/cancels export, report, or migration jobs or downloads export packages.',
  };
}

async function getCanvasProgressContext(args: {
  course_id?: string | number;
  progress_id?: string | number;
  progress_url?: string;
  lti_progress_id?: string | number;
}): Promise<unknown> {
  const id = args.course_id === undefined || args.course_id === null || args.course_id === ''
    ? null
    : courseId(args);
  const ltiProgressId = args.lti_progress_id === undefined || args.lti_progress_id === null || args.lti_progress_id === ''
    ? null
    : String(args.lti_progress_id);
  const target = ltiProgressId
    ? { kind: 'lti' as const, progress_id: ltiProgressId, course_id: id, source_url: null }
    : progressTargetFromValue(args.progress_url ?? args.progress_id, id);
  if (target?.kind === 'lti' && !target.course_id) {
    return {
      generated_at: new Date().toISOString(),
      course_id: id,
      progress_id: target.progress_id,
      progress_kind: target.kind,
      progress_status: 'skipped',
      progress: null,
      reason: 'LTI progress requires course_id.',
      note: 'Canvas Progress context is read-only. Provide course_id with lti_progress_id to resolve LTI async job status.',
    };
  }
  if (!target) {
    return {
      generated_at: new Date().toISOString(),
      course_id: id,
      progress_status: 'skipped',
      progress: null,
      reason: 'No progress_id, progress_url, or lti_progress_id was provided.',
      note: 'Canvas Progress context is read-only. Provide a progress_url from export/report metadata or a known Progress ID to resolve async job status.',
    };
  }
  const result = await safe(() => target.kind === 'lti'
    ? canvasApiGet(`/api/lti/courses/${target.course_id ?? id}/progress/${target.progress_id}`)
    : canvasGet(`/progress/${target.progress_id}`));
  return {
    generated_at: new Date().toISOString(),
    course_id: target.course_id ?? id,
    progress_id: target.progress_id,
    progress_kind: target.kind,
    progress_status: result.error ? endpointStatus(result.error) : 'ok',
    progress: result.value ? compactProgress(result.value, {
      source_type: 'direct',
      progress_url: target.source_url ?? args.progress_url ?? null,
    }) : null,
    error: result.error,
    note: 'Canvas Progress context is read-only. It reads async Progress status and never calls the Progress cancel endpoint.',
  };
}

async function getCoursePacingContext(args: {
  course_id?: string | number;
  course_pace_id?: string | number;
  max_blackout_date?: number;
  max_module?: number;
  max_item?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxBlackoutDate = Math.max(0, Number(args.max_blackout_date ?? 80));
  const maxModule = Math.max(0, Number(args.max_module ?? 80));
  const maxItem = Math.max(0, Number(args.max_item ?? 200));
  const paceId = args.course_pace_id === undefined || args.course_pace_id === null || args.course_pace_id === ''
    ? null
    : String(args.course_pace_id);
  const [blackoutDate, coursePace] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/blackout_dates`)),
    paceId
      ? safe(() => canvasGet(`/courses/${id}/course_pacing/${paceId}`))
      : Promise.resolve({ value: null, error: 'course_pace_id not provided; course pace detail skipped' }),
  ]);
  const blackoutDateValue = limitRow((blackoutDate.value as any[]) ?? [], maxBlackoutDate);
  const coursePaceStatus = paceId
    ? (coursePace.error ? endpointStatus(coursePace.error) : 'ok')
    : 'skipped';

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    course_pace_id: paceId,
    endpoint: [
      {
        name: 'course_blackout_date',
        status: blackoutDate.error ? endpointStatus(blackoutDate.error) : 'ok',
        count: rowCount(blackoutDate.value),
        key: keySample(blackoutDate.value),
        error: blackoutDate.error,
      },
      {
        name: 'course_pace',
        status: coursePaceStatus,
        count: paceId && !coursePace.error ? rowCount(coursePace.value) : 0,
        key: keySample(coursePace.value),
        error: paceId ? coursePace.error : null,
      },
    ],
    blackout_date_status: blackoutDate.error ? endpointStatus(blackoutDate.error) : 'ok',
    blackout_date_count: rowCount(blackoutDate.value),
    returned_blackout_date_count: blackoutDateValue.length,
    course_pace_status: coursePaceStatus,
    course_pace: paceId && !coursePace.error ? compactCoursePace(coursePace.value, maxModule, maxItem) : null,
    blackout_date: blackoutDateValue.map(compactBlackoutDate),
    note: 'Course pacing context is read-only. Blackout dates and Course Pace rows can explain schedule constraints, but assignment due dates and submissions remain authoritative for owed-work classification.',
  };
}

async function getCoursePollContext(args: {
  course_id?: string | number;
  max_poll?: number;
  max_choice?: number;
  max_session?: number;
  max_submission?: number;
  max_submission_detail?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxPoll = Math.max(0, Number(args.max_poll ?? 80));
  const maxChoice = Math.max(0, Number(args.max_choice ?? 120));
  const maxSession = Math.max(0, Number(args.max_session ?? 80));
  const maxSubmission = Math.max(0, Number(args.max_submission ?? 20));
  const maxSubmissionDetail = Math.max(0, Number(args.max_submission_detail ?? 20));
  const maxChars = Math.max(0, Number(args.max_chars ?? 600));
  const [poll, openedSession, closedSession] = await Promise.all([
    safe(() => canvasGet('/polls')),
    safe(() => canvasGet('/poll_sessions/opened')),
    safe(() => canvasGet('/poll_sessions/closed')),
  ]);
  const pollValue = unwrapCanvasArray(poll.value, 'polls');
  const pollChoiceResult = await pool(limitRow(pollValue, maxPoll), async (one: any) => {
    const pollId = one?.id ?? null;
    if (!pollId) return { poll_id: null, value: null, error: 'poll id unavailable' };
    const result = await safe(() => canvasPaginate<any>(`/polls/${pollId}/poll_choices`));
    return { poll_id: pollId, value: result.value, error: result.error };
  }, 4);
  const pollChoice = limitRow(pollChoiceResult.flatMap((one: any) => (
    ((one.value as any[]) ?? []).map((choice: any) => ({ poll_id: one.poll_id, choice }))
  )), maxChoice);
  const openedSessionValue = unwrapCanvasArray(openedSession.value, 'poll_sessions')
    .filter((one: any) => !one?.course_id || String(one.course_id) === id);
  const closedSessionValue = unwrapCanvasArray(closedSession.value, 'poll_sessions')
    .filter((one: any) => !one?.course_id || String(one.course_id) === id);
  const session = [...openedSessionValue, ...closedSessionValue];
  const pollSubmissionTarget = limitRow(session.flatMap((one: any) => (
    unwrapCanvasArray(one?.poll_submissions, 'poll_submissions').map((submission: any) => ({
      poll_id: one?.poll_id,
      poll_session_id: one?.id,
      poll_submission_id: submission?.id,
    }))
  )).filter((one: any) => one.poll_id && one.poll_session_id && one.poll_submission_id), maxSubmissionDetail);
  const pollSubmissionDetailResult = await pool(pollSubmissionTarget, async (one: any) => {
    const result = await safe(() => canvasGet(`/polls/${one.poll_id}/poll_sessions/${one.poll_session_id}/poll_submissions/${one.poll_submission_id}`));
    return { ...one, value: result.value, error: result.error };
  }, 4);
  const pollSubmissionDetail = pollSubmissionDetailResult
    .filter((one: any) => one.value)
    .map((one: any) => ({
      poll_id: one.poll_id,
      poll_session_id: one.poll_session_id,
      ...compactPollSubmission(one.value),
    }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      {
        name: 'poll',
        status: poll.error ? endpointStatus(poll.error) : 'ok',
        count: pollValue.length,
        key: keySample(poll.value),
        error: poll.error,
      },
      {
        name: 'poll_choice',
        status: pollChoiceResult.some((one: any) => one.error && endpointStatus(one.error) === 'error')
          ? 'error'
          : pollValue.length > 0 ? 'ok' : 'skipped',
        count: pollChoiceResult.reduce((sum: number, one: any) => sum + rowCount(one.value), 0),
        key: keySample(pollChoiceResult.find((one: any) => rowCount(one.value) > 0)?.value),
        error: pollChoiceResult.find((one: any) => one.error)?.error ?? null,
      },
      {
        name: 'opened_poll_session',
        status: openedSession.error ? endpointStatus(openedSession.error) : 'ok',
        count: openedSessionValue.length,
        key: keySample(openedSession.value),
        error: openedSession.error,
      },
      {
        name: 'closed_poll_session',
        status: closedSession.error ? endpointStatus(closedSession.error) : 'ok',
        count: closedSessionValue.length,
        key: keySample(closedSession.value),
        error: closedSession.error,
      },
      {
        name: 'poll_submission_detail',
        status: pollSubmissionDetailResult.some((one: any) => one.error && endpointStatus(one.error) === 'error')
          ? 'error'
          : pollSubmissionTarget.length > 0 ? 'ok' : 'skipped',
        count: pollSubmissionDetailResult.reduce((sum: number, one: any) => sum + rowCount(one.value), 0),
        key: keySample(pollSubmissionDetailResult.find((one: any) => rowCount(one.value) > 0)?.value),
        error: pollSubmissionDetailResult.find((one: any) => one.error)?.error ?? null,
      },
    ],
    poll_status: poll.error ? endpointStatus(poll.error) : 'ok',
    poll_count: pollValue.length,
    returned_poll_count: Math.min(pollValue.length, maxPoll),
    poll_choice_status: pollChoiceResult.some((one: any) => one.error && endpointStatus(one.error) === 'error')
      ? 'error'
      : pollValue.length > 0 ? 'ok' : 'skipped',
    poll_choice_count: pollChoiceResult.reduce((sum: number, one: any) => sum + rowCount(one.value), 0),
    returned_poll_choice_count: pollChoice.length,
    opened_poll_session_status: openedSession.error ? endpointStatus(openedSession.error) : 'ok',
    opened_poll_session_count: openedSessionValue.length,
    returned_opened_poll_session_count: Math.min(openedSessionValue.length, maxSession),
    closed_poll_session_status: closedSession.error ? endpointStatus(closedSession.error) : 'ok',
    closed_poll_session_count: closedSessionValue.length,
    returned_closed_poll_session_count: Math.min(closedSessionValue.length, maxSession),
    poll_session_count: session.length,
    visible_poll_submission_count: session.reduce((sum: number, one: any) => {
      return sum + unwrapCanvasArray(one?.poll_submissions, 'poll_submissions').length;
    }, 0),
    poll_submission_detail_status: pollSubmissionDetailResult.some((one: any) => one.error && endpointStatus(one.error) === 'error')
      ? 'error'
      : pollSubmissionTarget.length > 0 ? 'ok' : 'skipped',
    poll_submission_detail_count: pollSubmissionDetailResult.reduce((sum: number, one: any) => sum + rowCount(one.value), 0),
    returned_poll_submission_detail_count: pollSubmissionDetail.length,
    poll: limitRow(pollValue, maxPoll).map((one: any) => compactPoll(one, maxChars)),
    poll_choice: pollChoice.map((one: any) => ({
      poll_id: one.poll_id ?? one.choice?.poll_id ?? null,
      ...compactPollChoice(one.choice, maxChars),
    })),
    opened_poll_session: limitRow(openedSessionValue, maxSession).map((one: any) => compactPollSession(one, maxSubmission)),
    closed_poll_session: limitRow(closedSessionValue, maxSession).map((one: any) => compactPollSession(one, maxSubmission)),
    poll_submission_detail: pollSubmissionDetail,
    note: 'Canvas poll context is read-only. Opened poll sessions may indicate participation opportunities, but this tool never creates polls or submits poll choices.',
  };
}

async function getUserNotificationContext(args: {
  max_channel?: number;
  max_preference?: number;
  max_category?: number;
} = {}): Promise<unknown> {
  const maxChannel = Math.max(0, Number(args.max_channel ?? 20));
  const maxPreference = Math.max(0, Number(args.max_preference ?? 120));
  const maxCategory = Math.max(0, Number(args.max_category ?? 80));
  const channel = await safe(() => canvasPaginate<any>('/users/self/communication_channels'));
  const channelValue = limitRow((channel.value as any[]) ?? [], maxChannel);
  const channelContext = await pool(channelValue, async (one: any) => {
    const channelId = one?.id === undefined || one?.id === null ? null : String(one.id);
    const [preference, category] = channelId
      ? await Promise.all([
        safe(() => canvasGet(`/users/self/communication_channels/${channelId}/notification_preferences`)),
        safe(() => canvasGet(`/users/self/communication_channels/${channelId}/notification_preference_categories`)),
      ])
      : [
        { value: null, error: 'communication_channel_id missing; notification preference skipped' },
        { value: null, error: 'communication_channel_id missing; notification category skipped' },
      ];
    const preferenceValue = limitRow(unwrapCanvasArray(preference.value, 'notification_preferences'), maxPreference);
    const categoryValue = limitRow(unwrapCanvasArray(category.value, 'categories'), maxCategory);
    return {
      ...compactCommunicationChannel(one),
      endpoint: [
        {
          name: 'notification_preference',
          status: preference.error ? endpointStatus(preference.error) : 'ok',
          count: rowCount(preference.value),
          key: keySample(preference.value),
          error: preference.error,
        },
        {
          name: 'notification_preference_category',
          status: category.error ? endpointStatus(category.error) : 'ok',
          count: rowCount(category.value),
          key: keySample(category.value),
          error: category.error,
        },
      ],
      notification_preference_status: preference.error ? endpointStatus(preference.error) : 'ok',
      notification_preference_count: rowCount(preference.value),
      returned_notification_preference_count: preferenceValue.length,
      notification_preference_category_status: category.error ? endpointStatus(category.error) : 'ok',
      notification_preference_category_count: rowCount(category.value),
      returned_notification_preference_category_count: categoryValue.length,
      notification_preference: preferenceValue.map(compactNotificationPreference),
      notification_preference_category: categoryValue.map(compactNotificationCategory),
    };
  }, 4);

  return {
    generated_at: new Date().toISOString(),
    endpoint: [
      {
        name: 'communication_channel',
        status: channel.error ? endpointStatus(channel.error) : 'ok',
        count: rowCount(channel.value),
        key: keySample(channel.value),
        error: channel.error,
      },
    ],
    communication_channel_status: channel.error ? endpointStatus(channel.error) : 'ok',
    communication_channel_count: rowCount(channel.value),
    returned_communication_channel_count: channelValue.length,
    notification_preference_count: channelContext.reduce((sum: number, one: any) => {
      return sum + Number(one.notification_preference_count ?? 0);
    }, 0),
    notification_preference_category_count: channelContext.reduce((sum: number, one: any) => {
      return sum + Number(one.notification_preference_category_count ?? 0);
    }, 0),
    communication_channel: channelValue.map(compactCommunicationChannel),
    communication_channel_context: channelContext,
    note: 'Canvas notification context is read-only. This tool lists current-user communication channels and notification preferences but never creates channels or changes preference frequencies.',
  };
}

async function getUserCommMessageContext(args: {
  start_time?: string;
  end_time?: string;
  max_message?: number;
  max_chars?: number;
} = {}): Promise<unknown> {
  const now = new Date();
  const startTime = args.start_time ?? new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const endTime = args.end_time ?? now.toISOString();
  const maxMessage = Math.max(0, Number(args.max_message ?? 40));
  const maxChar = Math.max(0, Number(args.max_chars ?? 600));
  const user = await safe(() => canvasGet('/users/self'));
  const userId = user.error ? null : String((user.value as any)?.id ?? '');
  const message = userId
    ? await safe(() => canvasPaginate<any>('/comm_messages', {
      user_id: userId,
      start_time: startTime,
      end_time: endTime,
    }))
    : { value: null, error: 'users/self unavailable; comm message skipped' };
  const messageValue = limitRow((message.value as any[]) ?? [], maxMessage)
    .map((one: any) => compactCommMessage(one, maxChar));
  const deadlineCandidate = messageValue.filter((one: any) => Array.isArray(one.deadline_candidate) && one.deadline_candidate.length > 0);

  return {
    generated_at: new Date().toISOString(),
    user_id: userId,
    date_window: { start_time: startTime, end_time: endTime },
    endpoint: [
      {
        name: 'user',
        status: user.error ? endpointStatus(user.error) : 'ok',
        count: rowCount(user.value),
        key: keySample(user.value),
        error: user.error,
      },
      {
        name: 'comm_message',
        status: message.error ? endpointStatus(message.error) : 'ok',
        count: rowCount(message.value),
        key: keySample(message.value),
        error: message.error,
      },
    ],
    comm_message_status: message.error ? endpointStatus(message.error) : 'ok',
    comm_message_count: rowCount(message.value),
    returned_comm_message_count: messageValue.length,
    deadline_candidate_count: deadlineCandidate.length,
    comm_message: messageValue,
    note: 'Canvas CommMessages context is read-only. Raw body/html_body fields are not returned; only compact metadata and short deadline-like excerpts are exposed.',
  };
}

async function getCourseAccountContext(args: {
  course_id?: string | number;
  account_id?: string | number;
  account_notification_id?: string | number;
  account_name?: string;
  account_domain?: string;
  include_domain_lookup?: boolean;
  include_api_scope?: boolean;
  include_auth_provider?: boolean;
  include_account_surface?: boolean;
  include_admin?: boolean;
  include_login?: boolean;
  include_authentication_event?: boolean;
  include_sis_import?: boolean;
  include_temporary_enrollment_pairing?: boolean;
  include_deleted_admin?: boolean;
  temporary_enrollment_pairing_id?: string | number;
  sis_import_id?: string | number;
  auth_provider_id?: string | number;
  role_id?: string | number;
  role_permission?: string;
  account_permission?: string[];
  max_domain?: number;
  max_api_scope?: number;
  max_auth_provider?: number;
  max_sub_account?: number;
  max_account_report?: number;
  max_role?: number;
  max_role_permission?: number;
  max_admin?: number;
  max_login?: number;
  max_authentication_event?: number;
  max_sis_import?: number;
  max_sis_import_error?: number;
  max_temporary_enrollment_pairing?: number;
  start_time?: string;
  end_time?: string;
  include_past?: boolean;
  show_is_closed?: boolean;
  max_notification?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxNotification = Math.max(0, Number(args.max_notification ?? 40));
  const maxDomain = Math.max(0, Math.min(5, Number(args.max_domain ?? 5)));
  const maxApiScope = Math.max(0, Number(args.max_api_scope ?? 80));
  const maxAuthProvider = Math.max(0, Number(args.max_auth_provider ?? 20));
  const maxSubAccount = Math.max(0, Number(args.max_sub_account ?? 20));
  const maxAccountReport = Math.max(0, Number(args.max_account_report ?? 20));
  const maxRole = Math.max(0, Number(args.max_role ?? 40));
  const maxRolePermission = Math.max(0, Number(args.max_role_permission ?? 80));
  const maxAdmin = Math.max(0, Number(args.max_admin ?? 80));
  const maxLogin = Math.max(0, Number(args.max_login ?? 80));
  const maxAuthenticationEvent = Math.max(0, Number(args.max_authentication_event ?? 25));
  const maxSisImport = Math.max(0, Number(args.max_sis_import ?? 20));
  const maxSisImportError = Math.max(0, Number(args.max_sis_import_error ?? 20));
  const maxTemporaryEnrollmentPairing = Math.max(0, Number(args.max_temporary_enrollment_pairing ?? 20));
  const maxChar = Math.max(0, Number(args.max_chars ?? 600));
  const now = new Date();
  const startTime = args.start_time ?? dateOffset(now, -30);
  const endTime = args.end_time ?? dateOffset(now, 0);
  const requestedRolePermission = typeof args.role_permission === 'string' && args.role_permission.trim()
    ? args.role_permission.trim()
    : 'read_reports';
  const accountPermissionKey = Array.isArray(args.account_permission) && args.account_permission.length
    ? args.account_permission.map((one) => String(one)).filter(Boolean).slice(0, 40)
    : [
      'read_reports',
      'manage_account_settings',
      'manage_courses',
      'manage_sis',
      'manage_account_memberships',
      'become_user',
    ];
  const configuredAccountDomain = (() => {
    try {
      return new URL(BASE_URL).hostname;
    } catch {
      return null;
    }
  })();
  const requestedAccountDomain = typeof args.account_domain === 'string' && args.account_domain.trim()
    ? args.account_domain.trim()
    : configuredAccountDomain;
  const requestedAccountName = typeof args.account_name === 'string' && args.account_name.trim()
    ? args.account_name.trim()
    : null;
  const course = await safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'term' }));
  const courseValue = course.value as any;
  const accountId = args.account_id
    ? String(args.account_id)
    : courseValue?.root_account_id
      ? String(courseValue.root_account_id)
      : courseValue?.account_id
        ? String(courseValue.account_id)
        : null;
  const notification = accountId
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/account_notifications`, {
      ...(args.include_past === undefined ? {} : { include_past: !!args.include_past }),
      show_is_closed: args.show_is_closed !== false,
    }))
    : { value: null, error: 'account id unavailable; account notification skipped' };
  const notificationValue = limitRow((notification.value as any[]) ?? [], maxNotification);
  const requestedNotificationId = args.account_notification_id ? String(args.account_notification_id) : null;
  const selectedNotification = requestedNotificationId
    ? notificationValue.find((one: any) => String(one?.id ?? '') === requestedNotificationId) ?? { id: requestedNotificationId }
    : notificationValue.find((one: any) => one?.id) ?? null;
  const notificationDetail = accountId && selectedNotification?.id
    ? await safe(() => canvasGet(`/accounts/${accountId}/account_notifications/${selectedNotification.id}`))
    : { value: null, error: 'no account notification visible for detail' };
  const domainLookupParam = {
    ...(requestedAccountName ? { name: requestedAccountName } : {}),
    ...(requestedAccountDomain ? { domain: requestedAccountDomain } : {}),
  };
  const domain = args.include_domain_lookup === false
    ? { value: null, error: 'account domain lookup skipped by caller' }
    : Object.keys(domainLookupParam).length
      ? await safe(() => canvasGet('/accounts/search', domainLookupParam))
      : { value: null, error: 'no account domain lookup query available' };
  const domainValue = limitRow(Array.isArray(domain.value) ? domain.value : [], maxDomain);
  const apiScope = accountId && args.include_api_scope !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/scopes`))
    : { value: null, error: accountId ? 'API scope lookup skipped by caller' : 'account id unavailable; API scope lookup skipped' };
  const apiScopeValue = limitRow((apiScope.value as any[]) ?? [], maxApiScope);
  const authProvider = accountId && args.include_auth_provider !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/authentication_providers`))
    : { value: null, error: accountId ? 'authentication provider lookup skipped by caller' : 'account id unavailable; authentication provider lookup skipped' };
  const authProviderValue = limitRow((authProvider.value as any[]) ?? [], maxAuthProvider);
  const requestedAuthProviderId = args.auth_provider_id ? String(args.auth_provider_id) : null;
  const selectedAuthProvider = requestedAuthProviderId
    ? authProviderValue.find((one: any) => String(one?.id ?? '') === requestedAuthProviderId) ?? { id: requestedAuthProviderId }
    : authProviderValue.find((one: any) => one?.id) ?? null;
  const authProviderDetail = accountId && selectedAuthProvider?.id
    ? await safe(() => canvasGet(`/accounts/${accountId}/authentication_providers/${selectedAuthProvider.id}`))
    : { value: null, error: 'no authentication provider visible for detail' };
  const accountSurfaceError = accountId
    ? 'account surface lookup skipped by caller'
    : 'account id unavailable; account surface lookup skipped';
  const accountDetail = accountId && args.include_account_surface !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}`))
    : { value: null, error: accountSurfaceError };
  const accountSetting = accountId && args.include_account_surface !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/settings`))
    : { value: null, error: accountSurfaceError };
  const accountPermission = accountId && args.include_account_surface !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/permissions`, { 'permissions[]': accountPermissionKey }))
    : { value: null, error: accountSurfaceError };
  const subAccount = accountId && args.include_account_surface !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/sub_accounts`, {
      'include[]': ['course_count', 'sub_account_count'],
    }))
    : { value: null, error: accountSurfaceError };
  const subAccountValue = limitRow((subAccount.value as any[]) ?? [], maxSubAccount);
  const accountHelpLink = accountId && args.include_account_surface !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/help_links`))
    : { value: null, error: accountSurfaceError };
  const accountReport = accountId && args.include_account_surface !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/reports`))
    : { value: null, error: accountSurfaceError };
  const accountReportValue = limitRow((accountReport.value as any[]) ?? [], maxAccountReport);
  const role = accountId && args.include_account_surface !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/roles`, { 'state[]': ['active', 'inactive'] }))
    : { value: null, error: accountSurfaceError };
  const roleValue = limitRow((role.value as any[]) ?? [], maxRole);
  const adminError = accountId
    ? 'account admin lookup skipped by caller'
    : 'account id unavailable; account admin lookup skipped';
  const accountAdmin = accountId && args.include_admin !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/admins`, {
      include_deleted: !!args.include_deleted_admin,
    }))
    : { value: null, error: adminError };
  const accountAdminValue = limitRow((accountAdmin.value as any[]) ?? [], maxAdmin);
  const selfAdminRole = accountId && args.include_admin !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/admins/self`))
    : { value: null, error: adminError };
  const selfAdminRoleValue = limitRow((selfAdminRole.value as any[]) ?? [], maxRole);
  const loginError = accountId
    ? 'account login lookup skipped by caller'
    : 'account id unavailable; account login lookup skipped';
  const accountLogin = accountId && args.include_login !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/logins`))
    : { value: null, error: loginError };
  const accountLoginValue = limitRow((accountLogin.value as any[]) ?? [], maxLogin);
  const authenticationEventError = accountId
    ? 'authentication event lookup skipped by caller'
    : 'account id unavailable; authentication event lookup skipped';
  const authenticationEvent = accountId && args.include_authentication_event !== false
    ? await safe(() => canvasGet(`/audit/authentication/accounts/${accountId}`, {
      start_time: startTime,
      end_time: endTime,
      per_page: maxAuthenticationEvent,
    }))
    : { value: null, error: authenticationEventError };
  const authenticationEventValue = limitRow(authenticationEventList(authenticationEvent.value), maxAuthenticationEvent);
  const sisImportError = accountId
    ? 'SIS import lookup skipped by caller'
    : 'account id unavailable; SIS import lookup skipped';
  const sisImport = accountId && args.include_sis_import !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/sis_imports`, {
      created_since: startTime,
      created_before: endTime,
    }))
    : { value: null, error: sisImportError };
  const sisImportValue = limitRow((sisImport.value as any[]) ?? [], maxSisImport);
  const requestedSisImportId = args.sis_import_id ? String(args.sis_import_id) : null;
  const selectedSisImport = requestedSisImportId
    ? sisImportValue.find((one: any) => String(one?.id ?? '') === requestedSisImportId) ?? { id: requestedSisImportId }
    : sisImportValue.find((one: any) => one?.id) ?? null;
  const importingSisImport = accountId && args.include_sis_import !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/sis_imports/importing`))
    : { value: null, error: sisImportError };
  const sisImportDetail = accountId && selectedSisImport?.id && args.include_sis_import !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/sis_imports/${selectedSisImport.id}`))
    : { value: null, error: accountId ? 'no SIS import visible for detail' : 'account id unavailable; SIS import detail skipped' };
  const allSisImportError = accountId && args.include_sis_import !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/sis_import_errors`))
    : { value: null, error: sisImportError };
  const allSisImportErrorValue = limitRow(sisImportErrorList(allSisImportError.value), maxSisImportError);
  const selectedSisImportError = accountId && selectedSisImport?.id && args.include_sis_import !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/sis_imports/${selectedSisImport.id}/errors`))
    : { value: null, error: accountId ? 'no SIS import visible for error detail' : 'account id unavailable; SIS import error detail skipped' };
  const selectedSisImportErrorValue = limitRow(sisImportErrorList(selectedSisImportError.value), maxSisImportError);
  const requestedRoleId = args.role_id ? String(args.role_id) : null;
  const selectedRole = requestedRoleId
    ? roleValue.find((one: any) => String(one?.id ?? '') === requestedRoleId) ?? { id: requestedRoleId }
    : roleValue.find((one: any) => one?.id) ?? null;
  const roleDetail = accountId && selectedRole?.id && args.include_account_surface !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/roles/${selectedRole.id}`))
    : { value: null, error: accountId ? 'no role visible for detail' : 'account id unavailable; role detail skipped' };
  const rolePermission = accountId && args.include_account_surface !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/roles/permissions`))
    : { value: null, error: accountSurfaceError };
  const rawRolePermission = rolePermission.value as any;
  const rolePermissionRow = Array.isArray(rawRolePermission)
    ? rawRolePermission
    : Array.isArray(rawRolePermission?.permissions)
      ? rawRolePermission.permissions
      : rawRolePermission && typeof rawRolePermission === 'object'
        ? Object.entries(rawRolePermission).map(([key, value]) => ({ ...(value && typeof value === 'object' ? value as any : {}), permission: key }))
        : [];
  const rolePermissionValue = limitRow(rolePermissionRow, maxRolePermission);
  const permissionHelp = args.include_account_surface !== false
    ? await safe(() => canvasGet(`/permissions/account/${encodeURIComponent(requestedRolePermission)}/help`))
    : { value: null, error: 'account surface lookup skipped by caller' };
  const courseCreationAccount = args.include_account_surface !== false
    ? await safe(() => canvasPaginate<any>('/course_creation_accounts'))
    : { value: null, error: 'account surface lookup skipped by caller' };
  const courseCreationAccountValue = limitRow((courseCreationAccount.value as any[]) ?? [], maxSubAccount);
  const courseAdminAccount = args.include_account_surface !== false
    ? await safe(() => canvasPaginate<any>('/course_accounts'))
    : { value: null, error: 'account surface lookup skipped by caller' };
  const courseAdminAccountValue = limitRow((courseAdminAccount.value as any[]) ?? [], maxSubAccount);
  const manualCourseAccount = args.include_account_surface !== false
    ? await safe(() => canvasGet('/manually_created_courses_account'))
    : { value: null, error: 'account surface lookup skipped by caller' };
  const temporaryEnrollmentPairingError = accountId
    ? 'temporary enrollment pairing lookup skipped by caller'
    : 'account id unavailable; temporary enrollment pairing lookup skipped';
  const temporaryEnrollmentPairing = accountId && args.include_temporary_enrollment_pairing !== false
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/temporary_enrollment_pairings`))
    : { value: null, error: temporaryEnrollmentPairingError };
  const temporaryEnrollmentPairingValue = limitRow((temporaryEnrollmentPairing.value as any[]) ?? [], maxTemporaryEnrollmentPairing);
  const requestedTemporaryEnrollmentPairingId = args.temporary_enrollment_pairing_id ? String(args.temporary_enrollment_pairing_id) : null;
  const selectedTemporaryEnrollmentPairing = requestedTemporaryEnrollmentPairingId
    ? temporaryEnrollmentPairingValue.find((one: any) => String(one?.id ?? '') === requestedTemporaryEnrollmentPairingId) ?? { id: requestedTemporaryEnrollmentPairingId }
    : temporaryEnrollmentPairingValue.find((one: any) => one?.id) ?? null;
  const temporaryEnrollmentPairingDetail = accountId && selectedTemporaryEnrollmentPairing?.id && args.include_temporary_enrollment_pairing !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/temporary_enrollment_pairings/${selectedTemporaryEnrollmentPairing.id}`))
    : { value: null, error: accountId ? 'no temporary enrollment pairing visible for detail' : 'account id unavailable; temporary enrollment pairing detail skipped' };
  const newTemporaryEnrollmentPairing = accountId && args.include_temporary_enrollment_pairing !== false
    ? await safe(() => canvasGet(`/accounts/${accountId}/temporary_enrollment_pairings/new`))
    : { value: null, error: temporaryEnrollmentPairingError };

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    account_id: accountId,
    domain_lookup: {
      name: requestedAccountName,
      domain: requestedAccountDomain,
    },
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      account_id: courseValue?.account_id ?? null,
      root_account_id: courseValue?.root_account_id ?? null,
      term: compactCourseTerm(courseValue?.term),
    } : null,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      {
        name: 'account_notification',
        status: notification.error ? endpointStatus(notification.error) : accountId ? 'ok' : 'skipped',
        count: rowCount(notification.value),
        key: keySample(notification.value),
        error: notification.error,
      },
      {
        name: 'account_notification_detail',
        status: notificationDetail.error?.includes('no account notification visible') ? 'skipped' : endpointStatus(notificationDetail.error),
        count: rowCount(notificationDetail.value),
        key: keySample(notificationDetail.value),
        error: notificationDetail.error,
      },
      {
        name: 'account_domain',
        status: domain.error?.includes('skipped by caller') || domain.error?.includes('no account domain lookup query') ? 'skipped' : endpointStatus(domain.error),
        count: rowCount(domain.value),
        key: keySample(domain.value),
        error: domain.error,
      },
      {
        name: 'account_detail',
        status: accountDetail.error?.includes('skipped') ? 'skipped' : endpointStatus(accountDetail.error),
        count: rowCount(accountDetail.value),
        key: keySample(accountDetail.value),
        error: accountDetail.error,
      },
      {
        name: 'account_setting',
        status: accountSetting.error?.includes('skipped') ? 'skipped' : endpointStatus(accountSetting.error),
        count: rowCount(accountSetting.value),
        key: keySample(accountSetting.value),
        error: accountSetting.error,
      },
      {
        name: 'account_permission',
        status: accountPermission.error?.includes('skipped') ? 'skipped' : endpointStatus(accountPermission.error),
        count: rowCount(accountPermission.value),
        key: keySample(accountPermission.value),
        error: accountPermission.error,
      },
      {
        name: 'sub_account',
        status: subAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(subAccount.error),
        count: rowCount(subAccount.value),
        key: keySample(subAccount.value),
        error: subAccount.error,
      },
      {
        name: 'account_help_link',
        status: accountHelpLink.error?.includes('skipped') ? 'skipped' : endpointStatus(accountHelpLink.error),
        count: rowCount(accountHelpLink.value),
        key: keySample(accountHelpLink.value),
        error: accountHelpLink.error,
      },
      {
        name: 'account_report',
        status: accountReport.error?.includes('skipped') ? 'skipped' : endpointStatus(accountReport.error),
        count: rowCount(accountReport.value),
        key: keySample(accountReport.value),
        error: accountReport.error,
      },
      {
        name: 'role',
        status: role.error?.includes('skipped') ? 'skipped' : endpointStatus(role.error),
        count: rowCount(role.value),
        key: keySample(role.value),
        error: role.error,
      },
      {
        name: 'role_detail',
        status: roleDetail.error?.includes('no role visible') ? 'skipped' : endpointStatus(roleDetail.error),
        count: rowCount(roleDetail.value),
        key: keySample(roleDetail.value),
        error: roleDetail.error,
      },
      {
        name: 'account_admin',
        status: accountAdmin.error?.includes('skipped') ? 'skipped' : endpointStatus(accountAdmin.error),
        count: rowCount(accountAdmin.value),
        key: keySample(accountAdmin.value),
        error: accountAdmin.error,
      },
      {
        name: 'self_admin_role',
        status: selfAdminRole.error?.includes('skipped') ? 'skipped' : endpointStatus(selfAdminRole.error),
        count: rowCount(selfAdminRole.value),
        key: keySample(selfAdminRole.value),
        error: selfAdminRole.error,
      },
      {
        name: 'account_login',
        status: accountLogin.error?.includes('skipped') ? 'skipped' : endpointStatus(accountLogin.error),
        count: rowCount(accountLogin.value),
        key: keySample(accountLogin.value),
        error: accountLogin.error,
      },
      {
        name: 'authentication_event',
        status: authenticationEvent.error?.includes('skipped') ? 'skipped' : endpointStatus(authenticationEvent.error),
        count: rowCount(authenticationEvent.value),
        key: keySample(authenticationEvent.value),
        error: authenticationEvent.error,
      },
      {
        name: 'sis_import',
        status: sisImport.error?.includes('skipped') ? 'skipped' : endpointStatus(sisImport.error),
        count: rowCount(sisImport.value),
        key: keySample(sisImport.value),
        error: sisImport.error,
      },
      {
        name: 'importing_sis_import',
        status: importingSisImport.error?.includes('skipped') ? 'skipped' : endpointStatus(importingSisImport.error),
        count: rowCount(importingSisImport.value),
        key: keySample(importingSisImport.value),
        error: importingSisImport.error,
      },
      {
        name: 'sis_import_detail',
        status: sisImportDetail.error?.includes('no SIS import visible') ? 'skipped' : endpointStatus(sisImportDetail.error),
        count: rowCount(sisImportDetail.value),
        key: keySample(sisImportDetail.value),
        error: sisImportDetail.error,
      },
      {
        name: 'sis_import_error',
        status: allSisImportError.error?.includes('skipped') ? 'skipped' : endpointStatus(allSisImportError.error),
        count: rowCount(allSisImportError.value),
        key: keySample(allSisImportError.value),
        error: allSisImportError.error,
      },
      {
        name: 'selected_sis_import_error',
        status: selectedSisImportError.error?.includes('no SIS import visible') ? 'skipped' : endpointStatus(selectedSisImportError.error),
        count: rowCount(selectedSisImportError.value),
        key: keySample(selectedSisImportError.value),
        error: selectedSisImportError.error,
      },
      {
        name: 'role_permission',
        status: rolePermission.error?.includes('skipped') ? 'skipped' : endpointStatus(rolePermission.error),
        count: rowCount(rolePermission.value),
        key: keySample(rolePermission.value),
        error: rolePermission.error,
      },
      {
        name: 'permission_help',
        status: permissionHelp.error?.includes('skipped') ? 'skipped' : endpointStatus(permissionHelp.error),
        count: rowCount(permissionHelp.value),
        key: keySample(permissionHelp.value),
        error: permissionHelp.error,
      },
      {
        name: 'course_creation_account',
        status: courseCreationAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(courseCreationAccount.error),
        count: rowCount(courseCreationAccount.value),
        key: keySample(courseCreationAccount.value),
        error: courseCreationAccount.error,
      },
      {
        name: 'course_admin_account',
        status: courseAdminAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(courseAdminAccount.error),
        count: rowCount(courseAdminAccount.value),
        key: keySample(courseAdminAccount.value),
        error: courseAdminAccount.error,
      },
      {
        name: 'manual_course_account',
        status: manualCourseAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(manualCourseAccount.error),
        count: rowCount(manualCourseAccount.value),
        key: keySample(manualCourseAccount.value),
        error: manualCourseAccount.error,
      },
      {
        name: 'temporary_enrollment_pairing',
        status: temporaryEnrollmentPairing.error?.includes('skipped') ? 'skipped' : endpointStatus(temporaryEnrollmentPairing.error),
        count: rowCount(temporaryEnrollmentPairing.value),
        key: keySample(temporaryEnrollmentPairing.value),
        error: temporaryEnrollmentPairing.error,
      },
      {
        name: 'temporary_enrollment_pairing_detail',
        status: temporaryEnrollmentPairingDetail.error?.includes('no temporary enrollment pairing visible') ? 'skipped' : endpointStatus(temporaryEnrollmentPairingDetail.error),
        count: rowCount(temporaryEnrollmentPairingDetail.value),
        key: keySample(temporaryEnrollmentPairingDetail.value),
        error: temporaryEnrollmentPairingDetail.error,
      },
      {
        name: 'new_temporary_enrollment_pairing',
        status: newTemporaryEnrollmentPairing.error?.includes('skipped') ? 'skipped' : endpointStatus(newTemporaryEnrollmentPairing.error),
        count: rowCount(newTemporaryEnrollmentPairing.value),
        key: keySample(newTemporaryEnrollmentPairing.value),
        error: newTemporaryEnrollmentPairing.error,
      },
      {
        name: 'api_scope',
        status: apiScope.error?.includes('skipped') ? 'skipped' : endpointStatus(apiScope.error),
        count: rowCount(apiScope.value),
        key: keySample(apiScope.value),
        error: apiScope.error,
      },
      {
        name: 'auth_provider',
        status: authProvider.error?.includes('skipped') ? 'skipped' : endpointStatus(authProvider.error),
        count: rowCount(authProvider.value),
        key: keySample(authProvider.value),
        error: authProvider.error,
      },
      {
        name: 'auth_provider_detail',
        status: authProviderDetail.error?.includes('no authentication provider visible') ? 'skipped' : endpointStatus(authProviderDetail.error),
        count: rowCount(authProviderDetail.value),
        key: keySample(authProviderDetail.value),
        error: authProviderDetail.error,
      },
    ],
    account_notification_status: notification.error ? endpointStatus(notification.error) : accountId ? 'ok' : 'skipped',
    account_notification_count: rowCount(notification.value),
    returned_account_notification_count: notificationValue.length,
    account_notification: notificationValue.map((one: any) => compactAccountNotification(one, maxChar)),
    account_notification_detail_status: notificationDetail.error?.includes('no account notification visible') ? 'skipped' : endpointStatus(notificationDetail.error),
    account_notification_detail: notificationDetail.value ? compactAccountNotification(notificationDetail.value, maxChar) : null,
    account_domain_status: domain.error?.includes('skipped by caller') || domain.error?.includes('no account domain lookup query') ? 'skipped' : endpointStatus(domain.error),
    account_domain_count: rowCount(domain.value),
    returned_account_domain_count: domainValue.length,
    account_domain: domainValue.map(compactAccountDomain),
    account_detail_status: accountDetail.error?.includes('skipped') ? 'skipped' : endpointStatus(accountDetail.error),
    account_detail: accountDetail.value ? compactAccount(accountDetail.value) : null,
    account_setting_status: accountSetting.error?.includes('skipped') ? 'skipped' : endpointStatus(accountSetting.error),
    account_setting: accountSetting.value ? compactAccountSetting(accountSetting.value) : null,
    account_permission_status: accountPermission.error?.includes('skipped') ? 'skipped' : endpointStatus(accountPermission.error),
    account_permission: accountPermission.value ? compactAccountPermission(accountPermission.value) : null,
    sub_account_status: subAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(subAccount.error),
    sub_account_count: rowCount(subAccount.value),
    returned_sub_account_count: subAccountValue.length,
    sub_account: subAccountValue.map(compactAccount),
    account_help_link_status: accountHelpLink.error?.includes('skipped') ? 'skipped' : endpointStatus(accountHelpLink.error),
    account_help_link: accountHelpLink.value ? compactAccountHelpLink(accountHelpLink.value) : null,
    account_report_status: accountReport.error?.includes('skipped') ? 'skipped' : endpointStatus(accountReport.error),
    account_report_count: rowCount(accountReport.value),
    returned_account_report_count: accountReportValue.length,
    account_report: accountReportValue.map(compactAccountReport),
    role_status: role.error?.includes('skipped') ? 'skipped' : endpointStatus(role.error),
    role_count: rowCount(role.value),
    returned_role_count: roleValue.length,
    selected_role_id: selectedRole?.id ? String(selectedRole.id) : null,
    role: roleValue.map(compactRole),
    role_detail_status: roleDetail.error?.includes('no role visible') ? 'skipped' : endpointStatus(roleDetail.error),
    role_detail: roleDetail.value ? compactRole(roleDetail.value) : null,
    account_admin_status: accountAdmin.error?.includes('skipped') ? 'skipped' : endpointStatus(accountAdmin.error),
    account_admin_count: rowCount(accountAdmin.value),
    returned_account_admin_count: accountAdminValue.length,
    account_admin: accountAdminValue.map(compactAccountAdmin),
    self_admin_role_status: selfAdminRole.error?.includes('skipped') ? 'skipped' : endpointStatus(selfAdminRole.error),
    self_admin_role_count: rowCount(selfAdminRole.value),
    returned_self_admin_role_count: selfAdminRoleValue.length,
    self_admin_role: selfAdminRoleValue.map(compactAccountAdmin),
    account_login_status: accountLogin.error?.includes('skipped') ? 'skipped' : endpointStatus(accountLogin.error),
    account_login_count: rowCount(accountLogin.value),
    returned_account_login_count: accountLoginValue.length,
    account_login: accountLoginValue.map(compactLogin),
    authentication_event_window: { start_time: startTime, end_time: endTime },
    authentication_event_status: authenticationEvent.error?.includes('skipped') ? 'skipped' : endpointStatus(authenticationEvent.error),
    authentication_event_count: rowCount(authenticationEvent.value),
    returned_authentication_event_count: authenticationEventValue.length,
    authentication_event: authenticationEventValue.map(compactAuthenticationEvent),
    sis_import_window: { created_since: startTime, created_before: endTime },
    sis_import_status: sisImport.error?.includes('skipped') ? 'skipped' : endpointStatus(sisImport.error),
    sis_import_count: rowCount(sisImport.value),
    returned_sis_import_count: sisImportValue.length,
    selected_sis_import_id: selectedSisImport?.id ? String(selectedSisImport.id) : null,
    sis_import: sisImportValue.map(compactSisImport),
    importing_sis_import_status: importingSisImport.error?.includes('skipped') ? 'skipped' : endpointStatus(importingSisImport.error),
    importing_sis_import: importingSisImport.value ? compactSisImport(importingSisImport.value) : null,
    sis_import_detail_status: sisImportDetail.error?.includes('no SIS import visible') ? 'skipped' : endpointStatus(sisImportDetail.error),
    sis_import_detail: sisImportDetail.value ? compactSisImport(sisImportDetail.value) : null,
    sis_import_error_status: allSisImportError.error?.includes('skipped') ? 'skipped' : endpointStatus(allSisImportError.error),
    sis_import_error_count: rowCount(allSisImportError.value),
    returned_sis_import_error_count: allSisImportErrorValue.length,
    sis_import_error: allSisImportErrorValue.map((one: any) => compactSisImportError(one, maxChar)),
    selected_sis_import_error_status: selectedSisImportError.error?.includes('no SIS import visible') ? 'skipped' : endpointStatus(selectedSisImportError.error),
    selected_sis_import_error_count: rowCount(selectedSisImportError.value),
    returned_selected_sis_import_error_count: selectedSisImportErrorValue.length,
    selected_sis_import_error: selectedSisImportErrorValue.map((one: any) => compactSisImportError(one, maxChar)),
    role_permission_status: rolePermission.error?.includes('skipped') ? 'skipped' : endpointStatus(rolePermission.error),
    role_permission_count: rowCount(rolePermission.value),
    returned_role_permission_count: rolePermissionValue.length,
    role_permission: rolePermissionValue.map(compactRolePermission),
    permission_help_status: permissionHelp.error?.includes('skipped') ? 'skipped' : endpointStatus(permissionHelp.error),
    permission_help: permissionHelp.value ? compactPermissionHelp(permissionHelp.value, maxChar) : null,
    course_creation_account_status: courseCreationAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(courseCreationAccount.error),
    course_creation_account_count: rowCount(courseCreationAccount.value),
    returned_course_creation_account_count: courseCreationAccountValue.length,
    course_creation_account: courseCreationAccountValue.map(compactAccount),
    course_admin_account_status: courseAdminAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(courseAdminAccount.error),
    course_admin_account_count: rowCount(courseAdminAccount.value),
    returned_course_admin_account_count: courseAdminAccountValue.length,
    course_admin_account: courseAdminAccountValue.map(compactAccount),
    manual_course_account_status: manualCourseAccount.error?.includes('skipped') ? 'skipped' : endpointStatus(manualCourseAccount.error),
    manual_course_account: manualCourseAccount.value ? compactAccount(manualCourseAccount.value) : null,
    temporary_enrollment_pairing_status: temporaryEnrollmentPairing.error?.includes('skipped') ? 'skipped' : endpointStatus(temporaryEnrollmentPairing.error),
    temporary_enrollment_pairing_count: rowCount(temporaryEnrollmentPairing.value),
    returned_temporary_enrollment_pairing_count: temporaryEnrollmentPairingValue.length,
    selected_temporary_enrollment_pairing_id: selectedTemporaryEnrollmentPairing?.id ? String(selectedTemporaryEnrollmentPairing.id) : null,
    temporary_enrollment_pairing: temporaryEnrollmentPairingValue.map(compactTemporaryEnrollmentPairing),
    temporary_enrollment_pairing_detail_status: temporaryEnrollmentPairingDetail.error?.includes('no temporary enrollment pairing visible') ? 'skipped' : endpointStatus(temporaryEnrollmentPairingDetail.error),
    temporary_enrollment_pairing_detail: temporaryEnrollmentPairingDetail.value ? compactTemporaryEnrollmentPairing(temporaryEnrollmentPairingDetail.value) : null,
    new_temporary_enrollment_pairing_status: newTemporaryEnrollmentPairing.error?.includes('skipped') ? 'skipped' : endpointStatus(newTemporaryEnrollmentPairing.error),
    new_temporary_enrollment_pairing: newTemporaryEnrollmentPairing.value ? compactTemporaryEnrollmentPairing(newTemporaryEnrollmentPairing.value) : null,
    api_scope_status: apiScope.error?.includes('skipped') ? 'skipped' : endpointStatus(apiScope.error),
    api_scope_count: rowCount(apiScope.value),
    returned_api_scope_count: apiScopeValue.length,
    api_scope: apiScopeValue.map(compactApiScope),
    auth_provider_status: authProvider.error?.includes('skipped') ? 'skipped' : endpointStatus(authProvider.error),
    auth_provider_count: rowCount(authProvider.value),
    returned_auth_provider_count: authProviderValue.length,
    auth_provider: authProviderValue.map(compactAuthProvider),
    auth_provider_detail_status: authProviderDetail.error?.includes('no authentication provider visible') ? 'skipped' : endpointStatus(authProviderDetail.error),
    auth_provider_detail: authProviderDetail.value ? compactAuthProvider(authProviderDetail.value) : null,
    note: 'Course account context is read-only. This tool reads active global account notifications, account domain lookup rows, compact account surfaces, temporary enrollment pairing visibility, role/permission metadata, API token scope metadata, safe authentication provider metadata, sanitized login rows, sanitized authentication audit-event visibility, and sanitized SIS import/error visibility; it never creates, updates, closes, deletes, runs reports, starts imports, creates/deletes temporary enrollment pairings, or changes account/authentication settings. SIS import error rows exclude row_info/raw CSV row contents.',
  };
}

async function getCourseBrandContext(args: {
  course_id?: string | number;
  account_id?: string | number;
  max_variable?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxVariable = Math.max(0, Number(args.max_variable ?? 80));
  const course = await safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'term' }));
  const courseValue = course.value as any;
  const accountId = args.account_id
    ? String(args.account_id)
    : courseValue?.root_account_id
      ? String(courseValue.root_account_id)
      : courseValue?.account_id
        ? String(courseValue.account_id)
        : null;
  const [rootBrandVariable, accountBrandVariable, courseBrandVariable] = await Promise.all([
    safe(() => canvasGet('/brand_variables')),
    accountId
      ? safe(() => canvasGet(`/accounts/${accountId}/brand_variables`))
      : Promise.resolve({ value: null, error: 'account id unavailable; account brand variables skipped' }),
    safe(() => canvasGet(`/courses/${id}/brand_variables`)),
  ]);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    account_id: accountId,
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      account_id: courseValue?.account_id ?? null,
      root_account_id: courseValue?.root_account_id ?? null,
      term: compactCourseTerm(courseValue?.term),
    } : null,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      {
        name: 'root_brand_variable',
        status: endpointStatus(rootBrandVariable.error),
        count: rowCount(rootBrandVariable.value),
        key: keySample(rootBrandVariable.value),
        error: rootBrandVariable.error,
      },
      {
        name: 'account_brand_variable',
        status: accountBrandVariable.error?.includes('account id unavailable') ? 'skipped' : endpointStatus(accountBrandVariable.error),
        count: rowCount(accountBrandVariable.value),
        key: keySample(accountBrandVariable.value),
        error: accountBrandVariable.error,
      },
      {
        name: 'course_brand_variable',
        status: endpointStatus(courseBrandVariable.error),
        count: rowCount(courseBrandVariable.value),
        key: keySample(courseBrandVariable.value),
        error: courseBrandVariable.error,
      },
    ],
    root_brand_variable_status: endpointStatus(rootBrandVariable.error),
    root_brand_variable: rootBrandVariable.value ? compactBrandVariable(rootBrandVariable.value, maxVariable) : null,
    account_brand_variable_status: accountBrandVariable.error?.includes('account id unavailable') ? 'skipped' : endpointStatus(accountBrandVariable.error),
    account_brand_variable: accountBrandVariable.value ? compactBrandVariable(accountBrandVariable.value, maxVariable) : null,
    course_brand_variable_status: endpointStatus(courseBrandVariable.error),
    course_brand_variable: courseBrandVariable.value ? compactBrandVariable(courseBrandVariable.value, maxVariable) : null,
    note: 'Brand Config context is read-only. Canvas may redirect brand variable GET requests to static JSON; this tool follows the read and returns compact variable-key summaries without storing redirected URLs or changing branding.',
  };
}

async function getCourseAccountCalendarContext(args: {
  course_id?: string | number;
  account_id?: string | number;
  account_calendar_id?: string | number;
  search_term?: string;
  max_calendar?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxCalendar = Math.max(0, Number(args.max_calendar ?? 40));
  const course = await safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'term' }));
  const courseValue = course.value as any;
  const accountId = args.account_id
    ? String(args.account_id)
    : courseValue?.root_account_id
      ? String(courseValue.root_account_id)
      : courseValue?.account_id
        ? String(courseValue.account_id)
        : null;
  const requestedCalendarId = args.account_calendar_id
    ? String(args.account_calendar_id)
    : accountId;
  const searchTerm = typeof args.search_term === 'string' && args.search_term.trim()
    ? args.search_term.trim()
    : null;
  const visibleCalendar = await safe(() => canvasGet('/account_calendars', {
    ...(searchTerm ? { search_term: searchTerm } : {}),
  }));
  const visibleCalendarValue = limitRow(unwrapCanvasArray(visibleCalendar.value, 'account_calendars'), maxCalendar);
  const selectedCalendar = requestedCalendarId
    ? visibleCalendarValue.find((one: any) => String(one?.id ?? one?.account_id ?? '') === requestedCalendarId) ?? { id: requestedCalendarId }
    : visibleCalendarValue.find((one: any) => one?.id || one?.account_id) ?? null;
  const calendarDetail = selectedCalendar?.id || selectedCalendar?.account_id
    ? await safe(() => canvasGet(`/account_calendars/${selectedCalendar.id ?? selectedCalendar.account_id}`))
    : { value: null, error: 'no account calendar visible for detail' };
  const accountCalendar = accountId
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/account_calendars`))
    : { value: null, error: 'account id unavailable; account calendar list skipped' };
  const accountCalendarValue = limitRow((accountCalendar.value as any[]) ?? [], maxCalendar);
  const visibleCount = accountId
    ? await safe(() => canvasGet(`/accounts/${accountId}/visible_calendars_count`))
    : { value: null, error: 'account id unavailable; visible calendar count skipped' };

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    account_id: accountId,
    search_term: searchTerm,
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      account_id: courseValue?.account_id ?? null,
      root_account_id: courseValue?.root_account_id ?? null,
      term: compactCourseTerm(courseValue?.term),
    } : null,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      {
        name: 'account_calendar',
        status: endpointStatus(visibleCalendar.error),
        count: rowCount(visibleCalendar.value),
        key: keySample(visibleCalendar.value),
        error: visibleCalendar.error,
      },
      {
        name: 'account_calendar_detail',
        status: calendarDetail.error?.includes('no account calendar visible') ? 'skipped' : endpointStatus(calendarDetail.error),
        count: rowCount(calendarDetail.value),
        key: keySample(calendarDetail.value),
        error: calendarDetail.error,
      },
      {
        name: 'account_calendar_admin',
        status: accountCalendar.error?.includes('account id unavailable') ? 'skipped' : endpointStatus(accountCalendar.error),
        count: rowCount(accountCalendar.value),
        key: keySample(accountCalendar.value),
        error: accountCalendar.error,
      },
      {
        name: 'visible_calendar_count',
        status: visibleCount.error?.includes('account id unavailable') ? 'skipped' : endpointStatus(visibleCount.error),
        count: rowCount(visibleCount.value),
        key: keySample(visibleCount.value),
        error: visibleCount.error,
      },
    ],
    account_calendar_status: endpointStatus(visibleCalendar.error),
    account_calendar_count: rowCount(visibleCalendar.value),
    returned_account_calendar_count: visibleCalendarValue.length,
    account_calendar: visibleCalendarValue.map(compactAccountCalendar),
    account_calendar_detail_status: calendarDetail.error?.includes('no account calendar visible') ? 'skipped' : endpointStatus(calendarDetail.error),
    account_calendar_detail: calendarDetail.value ? compactAccountCalendar(calendarDetail.value) : null,
    account_calendar_admin_status: accountCalendar.error?.includes('account id unavailable') ? 'skipped' : endpointStatus(accountCalendar.error),
    account_calendar_admin_count: rowCount(accountCalendar.value),
    returned_account_calendar_admin_count: accountCalendarValue.length,
    account_calendar_admin: accountCalendarValue.map(compactAccountCalendar),
    visible_calendar_count_status: visibleCount.error?.includes('account id unavailable') ? 'skipped' : endpointStatus(visibleCount.error),
    visible_calendar_count: (visibleCount.value as any)?.count ?? (visibleCount.value as any)?.visible_calendars_count ?? null,
    note: 'Account Calendar context is read-only. This tool reads visible account calendar metadata and account calendar visibility/count endpoints when Canvas permits them; it never updates calendar visibility or auto-subscribe settings.',
  };
}

async function getCourseBlueprintContext(args: {
  course_id?: string | number;
  blueprint_template_id?: string | number;
  blueprint_subscription_id?: string | number;
  blueprint_migration_id?: string | number;
  max_blueprint?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxBlueprint = Math.max(0, Number(args.max_blueprint ?? 20));
  const templateId = args.blueprint_template_id ? String(args.blueprint_template_id) : 'default';
  const subscriptionId = args.blueprint_subscription_id ? String(args.blueprint_subscription_id) : 'default';
  const requestedMigrationId = args.blueprint_migration_id ? String(args.blueprint_migration_id) : null;
  const course = await safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'term' }));
  const [
    blueprintTemplate,
    associatedCourse,
    unsyncedChange,
    blueprintMigration,
    blueprintSubscription,
    blueprintImport,
  ] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/blueprint_templates/${templateId}`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_templates/${templateId}/associated_courses`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_templates/${templateId}/unsynced_changes`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_templates/${templateId}/migrations`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_subscriptions`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_subscriptions/${subscriptionId}/migrations`)),
  ]);
  const blueprintMigrationValue = limitRow((blueprintMigration.value as any[]) ?? [], maxBlueprint);
  const blueprintImportValue = limitRow((blueprintImport.value as any[]) ?? [], maxBlueprint);
  const selectedMigration = requestedMigrationId
    ?? String(blueprintMigrationValue.find((one: any) => one?.id)?.id
      ?? blueprintImportValue.find((one: any) => one?.id)?.id
      ?? '');
  const blueprintMigrationDetail = selectedMigration
    ? await safe(() => canvasGet(`/courses/${id}/blueprint_templates/${templateId}/migrations/${selectedMigration}`))
    : { value: null, error: 'no blueprint migration id visible for detail' };
  const blueprintMigrationChange = selectedMigration
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_templates/${templateId}/migrations/${selectedMigration}/details`))
    : { value: null, error: 'no blueprint migration id visible for detail' };
  const blueprintImportDetail = selectedMigration
    ? await safe(() => canvasGet(`/courses/${id}/blueprint_subscriptions/${subscriptionId}/migrations/${selectedMigration}`))
    : { value: null, error: 'no blueprint import id visible for detail' };
  const blueprintImportChange = selectedMigration
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/blueprint_subscriptions/${subscriptionId}/migrations/${selectedMigration}/details`))
    : { value: null, error: 'no blueprint import id visible for detail' };
  const associatedCourseValue = limitRow((associatedCourse.value as any[]) ?? [], maxBlueprint);
  const unsyncedChangeValue = limitRow((unsyncedChange.value as any[]) ?? [], maxBlueprint);
  const blueprintSubscriptionValue = limitRow((blueprintSubscription.value as any[]) ?? [], maxBlueprint);
  const blueprintMigrationChangeValue = limitRow((blueprintMigrationChange.value as any[]) ?? [], maxBlueprint);
  const blueprintImportChangeValue = limitRow((blueprintImportChange.value as any[]) ?? [], maxBlueprint);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    blueprint_template_id: templateId,
    blueprint_subscription_id: subscriptionId,
    selected_blueprint_migration_id: selectedMigration || null,
    course: course.value ? {
      course_id: (course.value as any)?.id ?? null,
      course_code: (course.value as any)?.course_code ?? null,
      name: (course.value as any)?.name ?? null,
      account_id: (course.value as any)?.account_id ?? null,
      root_account_id: (course.value as any)?.root_account_id ?? null,
      term: compactCourseTerm((course.value as any)?.term),
    } : null,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      {
        name: 'blueprint_template',
        status: endpointStatus(blueprintTemplate.error),
        count: rowCount(blueprintTemplate.value),
        key: keySample(blueprintTemplate.value),
        error: blueprintTemplate.error,
      },
      {
        name: 'blueprint_associated_course',
        status: endpointStatus(associatedCourse.error),
        count: rowCount(associatedCourse.value),
        key: keySample(associatedCourse.value),
        error: associatedCourse.error,
      },
      {
        name: 'blueprint_unsynced_change',
        status: endpointStatus(unsyncedChange.error),
        count: rowCount(unsyncedChange.value),
        key: keySample(unsyncedChange.value),
        error: unsyncedChange.error,
      },
      {
        name: 'blueprint_migration',
        status: endpointStatus(blueprintMigration.error),
        count: rowCount(blueprintMigration.value),
        key: keySample(blueprintMigration.value),
        error: blueprintMigration.error,
      },
      {
        name: 'blueprint_migration_detail',
        status: blueprintMigrationDetail.error?.includes('no blueprint migration id visible') ? 'skipped' : endpointStatus(blueprintMigrationDetail.error),
        count: rowCount(blueprintMigrationDetail.value),
        key: keySample(blueprintMigrationDetail.value),
        error: blueprintMigrationDetail.error,
      },
      {
        name: 'blueprint_migration_change',
        status: blueprintMigrationChange.error?.includes('no blueprint migration id visible') ? 'skipped' : endpointStatus(blueprintMigrationChange.error),
        count: rowCount(blueprintMigrationChange.value),
        key: keySample(blueprintMigrationChange.value),
        error: blueprintMigrationChange.error,
      },
      {
        name: 'blueprint_subscription',
        status: endpointStatus(blueprintSubscription.error),
        count: rowCount(blueprintSubscription.value),
        key: keySample(blueprintSubscription.value),
        error: blueprintSubscription.error,
      },
      {
        name: 'blueprint_import',
        status: endpointStatus(blueprintImport.error),
        count: rowCount(blueprintImport.value),
        key: keySample(blueprintImport.value),
        error: blueprintImport.error,
      },
      {
        name: 'blueprint_import_detail',
        status: blueprintImportDetail.error?.includes('no blueprint import id visible') ? 'skipped' : endpointStatus(blueprintImportDetail.error),
        count: rowCount(blueprintImportDetail.value),
        key: keySample(blueprintImportDetail.value),
        error: blueprintImportDetail.error,
      },
      {
        name: 'blueprint_import_change',
        status: blueprintImportChange.error?.includes('no blueprint import id visible') ? 'skipped' : endpointStatus(blueprintImportChange.error),
        count: rowCount(blueprintImportChange.value),
        key: keySample(blueprintImportChange.value),
        error: blueprintImportChange.error,
      },
    ],
    blueprint_template_status: endpointStatus(blueprintTemplate.error),
    blueprint_template: blueprintTemplate.value ? compactBlueprintTemplate(blueprintTemplate.value) : null,
    blueprint_associated_course_status: endpointStatus(associatedCourse.error),
    blueprint_associated_course_count: rowCount(associatedCourse.value),
    returned_blueprint_associated_course_count: associatedCourseValue.length,
    blueprint_associated_course: associatedCourseValue.map(compactBlueprintCourse),
    blueprint_unsynced_change_status: endpointStatus(unsyncedChange.error),
    blueprint_unsynced_change_count: rowCount(unsyncedChange.value),
    returned_blueprint_unsynced_change_count: unsyncedChangeValue.length,
    blueprint_unsynced_change: unsyncedChangeValue.map(compactBlueprintChange),
    blueprint_migration_status: endpointStatus(blueprintMigration.error),
    blueprint_migration_count: rowCount(blueprintMigration.value),
    returned_blueprint_migration_count: blueprintMigrationValue.length,
    blueprint_migration: blueprintMigrationValue.map(compactBlueprintMigration),
    blueprint_migration_detail_status: blueprintMigrationDetail.error?.includes('no blueprint migration id visible') ? 'skipped' : endpointStatus(blueprintMigrationDetail.error),
    blueprint_migration_detail: blueprintMigrationDetail.value ? compactBlueprintMigration(blueprintMigrationDetail.value) : null,
    blueprint_migration_change_status: blueprintMigrationChange.error?.includes('no blueprint migration id visible') ? 'skipped' : endpointStatus(blueprintMigrationChange.error),
    blueprint_migration_change_count: rowCount(blueprintMigrationChange.value),
    returned_blueprint_migration_change_count: blueprintMigrationChangeValue.length,
    blueprint_migration_change: blueprintMigrationChangeValue.map(compactBlueprintChange),
    blueprint_subscription_status: endpointStatus(blueprintSubscription.error),
    blueprint_subscription_count: rowCount(blueprintSubscription.value),
    returned_blueprint_subscription_count: blueprintSubscriptionValue.length,
    blueprint_subscription: blueprintSubscriptionValue.map(compactBlueprintSubscription),
    blueprint_import_status: endpointStatus(blueprintImport.error),
    blueprint_import_count: rowCount(blueprintImport.value),
    returned_blueprint_import_count: blueprintImportValue.length,
    blueprint_import: blueprintImportValue.map(compactBlueprintMigration),
    blueprint_import_detail_status: blueprintImportDetail.error?.includes('no blueprint import id visible') ? 'skipped' : endpointStatus(blueprintImportDetail.error),
    blueprint_import_detail: blueprintImportDetail.value ? compactBlueprintMigration(blueprintImportDetail.value) : null,
    blueprint_import_change_status: blueprintImportChange.error?.includes('no blueprint import id visible') ? 'skipped' : endpointStatus(blueprintImportChange.error),
    blueprint_import_change_count: rowCount(blueprintImportChange.value),
    returned_blueprint_import_change_count: blueprintImportChangeValue.length,
    blueprint_import_change: blueprintImportChangeValue.map(compactBlueprintChange),
    note: 'Blueprint context is read-only. It checks whether a course is a blueprint source or blueprint-associated course and reads migration/import metadata when Canvas permits it; it never updates associations, syncs, restrictions, or blueprint settings.',
  };
}

async function getCourseGradingPeriodContext(args: {
  course_id?: string | number;
  account_id?: string | number;
  grading_period_id?: string | number;
  max_grading_period?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxGradingPeriod = Math.max(0, Number(args.max_grading_period ?? 40));
  const course = await safe(() => canvasGet(`/courses/${id}`, {
    'include[]': ['term', 'grading_periods', 'current_grading_period_scores'],
  }));
  const courseValue = course.value as any;
  const accountId = args.account_id
    ? String(args.account_id)
    : courseValue?.root_account_id
      ? String(courseValue.root_account_id)
      : courseValue?.account_id
        ? String(courseValue.account_id)
        : null;
  const [accountGradingPeriodSet, accountGradingPeriod, courseGradingPeriod] = await Promise.all([
    accountId
      ? safe(() => canvasGet(`/accounts/${accountId}/grading_period_sets`))
      : { value: null, error: 'no account id visible for grading period set list' },
    accountId
      ? safe(() => canvasGet(`/accounts/${accountId}/grading_periods`))
      : { value: null, error: 'no account id visible for account grading period list' },
    safe(() => canvasGet(`/courses/${id}/grading_periods`)),
  ]);
  const accountGradingPeriodSetValue = limitRow(
    unwrapCanvasArray(accountGradingPeriodSet.value, 'grading_period_sets')
      .concat(unwrapCanvasArray(accountGradingPeriodSet.value, 'grading_period_set')),
    maxGradingPeriod,
  );
  const accountGradingPeriodValue = limitRow(unwrapCanvasArray(accountGradingPeriod.value, 'grading_periods'), maxGradingPeriod);
  const courseGradingPeriodValue = limitRow(unwrapCanvasArray(courseGradingPeriod.value, 'grading_periods'), maxGradingPeriod);
  const includedGradingPeriod = Array.isArray(courseValue?.grading_periods) ? courseValue.grading_periods : [];
  const selectedGradingPeriodId = args.grading_period_id
    ? String(args.grading_period_id)
    : String(
      courseGradingPeriodValue.find((one: any) => one?.id)?.id
      ?? includedGradingPeriod.find((one: any) => one?.id)?.id
      ?? '',
    );
  const courseGradingPeriodDetail = selectedGradingPeriodId
    ? await safe(() => canvasGet(`/courses/${id}/grading_periods/${selectedGradingPeriodId}`))
    : { value: null, error: 'no course grading period id visible for detail' };

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    account_id: accountId,
    selected_grading_period_id: selectedGradingPeriodId || null,
    course: courseValue ? {
      course_id: courseValue?.id ?? null,
      course_code: courseValue?.course_code ?? null,
      name: courseValue?.name ?? null,
      account_id: courseValue?.account_id ?? null,
      root_account_id: courseValue?.root_account_id ?? null,
      term: compactCourseTerm(courseValue?.term),
      has_grading_period: !!courseValue?.has_grading_periods,
    } : null,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      {
        name: 'account_grading_period_set',
        status: accountGradingPeriodSet.error?.includes('no account id visible') ? 'skipped' : endpointStatus(accountGradingPeriodSet.error),
        count: rowCount(accountGradingPeriodSet.value),
        key: keySample(accountGradingPeriodSet.value),
        error: accountGradingPeriodSet.error,
      },
      {
        name: 'account_grading_period',
        status: accountGradingPeriod.error?.includes('no account id visible') ? 'skipped' : endpointStatus(accountGradingPeriod.error),
        count: rowCount(accountGradingPeriod.value),
        key: keySample(accountGradingPeriod.value),
        error: accountGradingPeriod.error,
      },
      {
        name: 'course_grading_period',
        status: endpointStatus(courseGradingPeriod.error),
        count: rowCount(courseGradingPeriod.value),
        key: keySample(courseGradingPeriod.value),
        error: courseGradingPeriod.error,
      },
      {
        name: 'course_grading_period_detail',
        status: courseGradingPeriodDetail.error?.includes('no course grading period id visible') ? 'skipped' : endpointStatus(courseGradingPeriodDetail.error),
        count: rowCount(courseGradingPeriodDetail.value),
        key: keySample(courseGradingPeriodDetail.value),
        error: courseGradingPeriodDetail.error,
      },
    ],
    account_grading_period_set_status: accountGradingPeriodSet.error?.includes('no account id visible') ? 'skipped' : endpointStatus(accountGradingPeriodSet.error),
    account_grading_period_set_count: rowCount(accountGradingPeriodSet.value),
    returned_account_grading_period_set_count: accountGradingPeriodSetValue.length,
    account_grading_period_set: accountGradingPeriodSetValue.map(compactGradingPeriodSet),
    account_grading_period_status: accountGradingPeriod.error?.includes('no account id visible') ? 'skipped' : endpointStatus(accountGradingPeriod.error),
    account_grading_period_count: rowCount(accountGradingPeriod.value),
    returned_account_grading_period_count: accountGradingPeriodValue.length,
    account_grading_period: accountGradingPeriodValue.map(compactGradingPeriod),
    course_grading_period_status: endpointStatus(courseGradingPeriod.error),
    course_grading_period_count: rowCount(courseGradingPeriod.value),
    returned_course_grading_period_count: courseGradingPeriodValue.length,
    course_grading_period: courseGradingPeriodValue.map(compactGradingPeriod),
    included_grading_period_count: includedGradingPeriod.length,
    included_grading_period: includedGradingPeriod.map(compactGradingPeriod),
    course_grading_period_detail_status: courseGradingPeriodDetail.error?.includes('no course grading period id visible') ? 'skipped' : endpointStatus(courseGradingPeriodDetail.error),
    course_grading_period_detail: courseGradingPeriodDetail.value ? compactGradingPeriod(courseGradingPeriodDetail.value) : null,
    note: 'Grading period context is read-only. It reads grading-period scope and detail visibility for current-term relevance checks, but never creates, updates, deletes, or batch-updates grading periods or grading-period sets.',
  };
}

async function getCourseFeatureContext(args: {
  course_id?: string | number;
  account_id?: string | number;
  max_feature?: number;
  max_enabled_feature?: number;
  max_environment_feature?: number;
  max_csp_domain?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxFeature = Math.max(0, Number(args.max_feature ?? 120));
  const maxEnabledFeature = Math.max(0, Number(args.max_enabled_feature ?? 120));
  const maxEnvironmentFeature = Math.max(0, Number(args.max_environment_feature ?? 160));
  const maxCspDomain = Math.max(0, Number(args.max_csp_domain ?? 80));
  const course = await safe(() => canvasGet(`/courses/${id}`, { 'include[]': ['term'] }));
  const courseValue = course.value as any;
  const accountId = args.account_id
    ?? courseValue?.root_account_id
    ?? courseValue?.account_id
    ?? null;
  const [latePolicy, courseCspSetting, accountCspSetting, courseFeature, courseEnabledFeature, userFeature, userEnabledFeature, environmentFeature] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/late_policy`)),
    safe(() => canvasGet(`/courses/${id}/csp_settings`)),
    accountId
      ? safe(() => canvasGet(`/accounts/${accountId}/csp_settings`))
      : Promise.resolve({ value: null, error: 'no account id visible for CSP settings' }),
    safe(() => canvasPaginate<any>(`/courses/${id}/features`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/features/enabled`)),
    safe(() => canvasPaginate<any>('/users/self/features')),
    safe(() => canvasPaginate<any>('/users/self/features/enabled')),
    safe(() => canvasGet('/features/environment')),
  ]);
  const courseFeatureValue = limitRow((courseFeature.value as any[]) ?? [], maxFeature);
  const courseEnabledFeatureValue = limitRow((courseEnabledFeature.value as any[]) ?? [], maxEnabledFeature);
  const userFeatureValue = limitRow((userFeature.value as any[]) ?? [], maxFeature);
  const userEnabledFeatureValue = limitRow((userEnabledFeature.value as any[]) ?? [], maxEnabledFeature);
  const environmentPair = Object.entries((environmentFeature.value && typeof environmentFeature.value === 'object') ? environmentFeature.value as Record<string, unknown> : {})
    .slice(0, maxEnvironmentFeature)
    .map(([feature, isEnabled]) => ({ feature, is_enabled: isEnabled }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    account_id: accountId,
    endpoint: [
      {
        name: 'course',
        status: course.error ? endpointStatus(course.error) : 'ok',
        count: rowCount(course.value),
        key: keySample(course.value),
        error: course.error,
      },
      {
        name: 'late_policy',
        status: latePolicy.error ? endpointStatus(latePolicy.error) : 'ok',
        count: rowCount(latePolicy.value),
        key: keySample(latePolicy.value),
        error: latePolicy.error,
      },
      {
        name: 'course_csp_setting',
        status: courseCspSetting.error ? endpointStatus(courseCspSetting.error) : 'ok',
        count: rowCount(courseCspSetting.value),
        key: keySample(courseCspSetting.value),
        error: courseCspSetting.error,
      },
      {
        name: 'account_csp_setting',
        status: accountCspSetting.error?.startsWith('no account id visible') ? 'skipped' : accountCspSetting.error ? endpointStatus(accountCspSetting.error) : 'ok',
        count: rowCount(accountCspSetting.value),
        key: keySample(accountCspSetting.value),
        error: accountCspSetting.error,
      },
      {
        name: 'course_feature',
        status: courseFeature.error ? endpointStatus(courseFeature.error) : 'ok',
        count: rowCount(courseFeature.value),
        key: keySample(courseFeature.value),
        error: courseFeature.error,
      },
      {
        name: 'course_enabled_feature',
        status: courseEnabledFeature.error ? endpointStatus(courseEnabledFeature.error) : 'ok',
        count: rowCount(courseEnabledFeature.value),
        key: keySample(courseEnabledFeature.value),
        error: courseEnabledFeature.error,
      },
      {
        name: 'user_feature',
        status: userFeature.error ? endpointStatus(userFeature.error) : 'ok',
        count: rowCount(userFeature.value),
        key: keySample(userFeature.value),
        error: userFeature.error,
      },
      {
        name: 'user_enabled_feature',
        status: userEnabledFeature.error ? endpointStatus(userEnabledFeature.error) : 'ok',
        count: rowCount(userEnabledFeature.value),
        key: keySample(userEnabledFeature.value),
        error: userEnabledFeature.error,
      },
      {
        name: 'environment_feature',
        status: environmentFeature.error ? endpointStatus(environmentFeature.error) : 'ok',
        count: environmentPair.length,
        key: keySample(environmentFeature.value),
        error: environmentFeature.error,
      },
    ],
    late_policy_status: latePolicy.error ? endpointStatus(latePolicy.error) : 'ok',
    late_policy: latePolicy.error ? null : compactLatePolicy(latePolicy.value),
    course_csp_setting_status: courseCspSetting.error ? endpointStatus(courseCspSetting.error) : 'ok',
    course_csp_setting: courseCspSetting.error ? null : compactCspSetting(courseCspSetting.value, maxCspDomain),
    account_csp_setting_status: accountCspSetting.error?.startsWith('no account id visible')
      ? 'skipped'
      : accountCspSetting.error ? endpointStatus(accountCspSetting.error) : 'ok',
    account_csp_setting: accountCspSetting.error ? null : compactCspSetting(accountCspSetting.value, maxCspDomain),
    course_feature_status: courseFeature.error ? endpointStatus(courseFeature.error) : 'ok',
    course_feature_count: rowCount(courseFeature.value),
    returned_course_feature_count: courseFeatureValue.length,
    course_enabled_feature_status: courseEnabledFeature.error ? endpointStatus(courseEnabledFeature.error) : 'ok',
    course_enabled_feature_count: rowCount(courseEnabledFeature.value),
    returned_course_enabled_feature_count: courseEnabledFeatureValue.length,
    user_feature_status: userFeature.error ? endpointStatus(userFeature.error) : 'ok',
    user_feature_count: rowCount(userFeature.value),
    returned_user_feature_count: userFeatureValue.length,
    user_enabled_feature_status: userEnabledFeature.error ? endpointStatus(userEnabledFeature.error) : 'ok',
    user_enabled_feature_count: rowCount(userEnabledFeature.value),
    returned_user_enabled_feature_count: userEnabledFeatureValue.length,
    environment_feature_status: environmentFeature.error ? endpointStatus(environmentFeature.error) : 'ok',
    environment_feature_count: environmentPair.length,
    course_feature: courseFeatureValue.map(compactFeature),
    course_enabled_feature: courseEnabledFeatureValue.map((one: any) => ({ feature_name: String(one) })),
    user_feature: userFeatureValue.map(compactFeature),
    user_enabled_feature: userEnabledFeatureValue.map((one: any) => ({ feature_name: String(one) })),
    environment_feature: environmentPair,
    note: 'Canvas feature context is read-only. Feature flags, CSP settings, and late policy explain Canvas behavior and policy, but this tool never sets flags, changes late policy, or mutates CSP domains.',
  };
}

async function getCourseActivityContext(args: {
  course_id?: string | number;
  include_conversation_detail?: boolean;
  max_activity?: number;
  max_audit_event?: number;
  max_history?: number;
  max_conversation?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxActivity = Math.max(0, Number(args.max_activity ?? 80));
  const maxAuditEvent = Math.max(0, Number(args.max_audit_event ?? 25));
  const maxHistory = Math.max(0, Number(args.max_history ?? 25));
  const maxConversation = Math.max(0, Number(args.max_conversation ?? 20));
  const user = await canvasGet('/users/self') as any;
  const userId = String(user.id);
  const [activityItem, activitySummary, courseActivityItem, courseActivitySummary, courseAuditLog, recentHistory, conversation, conversationCount] = await Promise.all([
    safe(() => canvasPaginate<any>('/users/self/activity_stream', { only_active_courses: true })),
    safe(() => canvasPaginate<any>('/users/self/activity_stream/summary', { only_active_courses: true })),
    safe(() => canvasPaginate<any>(`/courses/${id}/activity_stream`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/activity_stream/summary`)),
    safe(() => canvasGet(`/audit/course/courses/${id}`, { per_page: maxAuditEvent })),
    safe(() => canvasGet(`/users/${userId}/history`, { per_page: 25 })),
    safe(() => canvasPaginate<any>('/conversations', {
      scope: 'unread',
      'filter[]': `course_${id}`,
    })),
    safe(() => canvasGet('/conversations/unread_count')),
  ]);
  const activityValue = limitRow(((activityItem.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id)), maxActivity);
  const courseActivityValue = limitRow((courseActivityItem.value as any[]) ?? [], maxActivity);
  const auditEventValue = limitRow(courseAuditEventList(courseAuditLog.value), maxAuditEvent);
  const historyValue = limitRow(((recentHistory.value as any[]) ?? [])
    .filter((one: any) => String(one?.context_id ?? '') === String(id)), maxHistory);
  const conversationValue = limitRow((conversation.value as any[]) ?? [], maxConversation);
  const conversationDetail = args.include_conversation_detail
    ? await Promise.all(conversationValue.map((one: any) => safe(() => canvasGet(`/conversations/${one?.id}`, {
      scope: 'unread',
      'filter[]': `course_${id}`,
    }))))
    : [];
  const deadlineCandidate = conversationDetail.flatMap((one) => (
    one.error ? [] : compactConversationDetail(one.value)
  ));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    endpoint: [
      {
        name: 'activity_stream',
        status: activityItem.error ? endpointStatus(activityItem.error) : 'ok',
        count: rowCount(activityItem.value),
        key: keySample(activityItem.value),
        error: activityItem.error,
      },
      {
        name: 'activity_stream_summary',
        status: activitySummary.error ? endpointStatus(activitySummary.error) : 'ok',
        count: rowCount(activitySummary.value),
        key: keySample(activitySummary.value),
        error: activitySummary.error,
      },
      {
        name: 'course_activity_stream',
        status: courseActivityItem.error ? endpointStatus(courseActivityItem.error) : 'ok',
        count: rowCount(courseActivityItem.value),
        key: keySample(courseActivityItem.value),
        error: courseActivityItem.error,
      },
      {
        name: 'course_activity_stream_summary',
        status: courseActivitySummary.error ? endpointStatus(courseActivitySummary.error) : 'ok',
        count: rowCount(courseActivitySummary.value),
        key: keySample(courseActivitySummary.value),
        error: courseActivitySummary.error,
      },
      {
        name: 'course_audit_log',
        status: courseAuditLog.error ? endpointStatus(courseAuditLog.error) : 'ok',
        count: rowCount(courseAuditLog.value),
        key: keySample(courseAuditLog.value),
        error: courseAuditLog.error,
      },
      {
        name: 'recent_history',
        status: recentHistory.error ? endpointStatus(recentHistory.error) : 'ok',
        count: rowCount(recentHistory.value),
        key: keySample(recentHistory.value),
        error: recentHistory.error,
      },
      {
        name: 'conversation',
        status: conversation.error ? endpointStatus(conversation.error) : 'ok',
        count: rowCount(conversation.value),
        key: keySample(conversation.value),
        error: conversation.error,
      },
      {
        name: 'conversation_unread_count',
        status: conversationCount.error ? endpointStatus(conversationCount.error) : 'ok',
        count: rowCount(conversationCount.value),
        key: keySample(conversationCount.value),
        error: conversationCount.error,
      },
      {
        name: 'conversation_detail',
        status: args.include_conversation_detail ? 'ok' : 'skipped',
        count: conversationDetail.length,
        key: conversationDetail[0]?.value ? keySample(conversationDetail[0].value) : [],
        error: conversationDetail.find((one) => one.error)?.error ?? null,
      },
    ],
    activity_status: activityItem.error ? endpointStatus(activityItem.error) : 'ok',
    activity_count: activityValue.length,
    activity: activityValue.map(compactActivity),
    activity_summary_status: activitySummary.error ? endpointStatus(activitySummary.error) : 'ok',
    activity_summary_count: rowCount(activitySummary.value),
    activity_summary: limitRow(((activitySummary.value as any[]) ?? []).map((one: any) => ({
      type: one?.type ?? null,
      notification_category: one?.notification_category ?? null,
      count: one?.count ?? null,
      unread_count: one?.unread_count ?? null,
    })), 40),
    course_activity_status: courseActivityItem.error ? endpointStatus(courseActivityItem.error) : 'ok',
    course_activity_count: courseActivityValue.length,
    course_activity: courseActivityValue.map(compactActivity),
    course_activity_summary_status: courseActivitySummary.error ? endpointStatus(courseActivitySummary.error) : 'ok',
    course_activity_summary_count: rowCount(courseActivitySummary.value),
    course_activity_summary: limitRow(((courseActivitySummary.value as any[]) ?? []).map((one: any) => ({
      type: one?.type ?? null,
      notification_category: one?.notification_category ?? null,
      count: one?.count ?? null,
      unread_count: one?.unread_count ?? null,
    })), 40),
    course_audit_log_status: courseAuditLog.error ? endpointStatus(courseAuditLog.error) : 'ok',
    course_audit_log_count: rowCount(courseAuditLog.value),
    returned_course_audit_event_count: auditEventValue.length,
    course_audit_event: auditEventValue.map(compactCourseAuditEvent),
    recent_history_status: recentHistory.error ? endpointStatus(recentHistory.error) : 'ok',
    recent_history_count: historyValue.length,
    recent_history: historyValue.map(compactHistory),
    conversation_status: conversation.error ? endpointStatus(conversation.error) : 'ok',
    unread_conversation_count: rowCount(conversation.value),
    conversation: conversationValue.map(compactConversation),
    unread_count_status: conversationCount.error ? endpointStatus(conversationCount.error) : 'ok',
    unread_count: conversationCount.value,
    conversation_detail_status: args.include_conversation_detail ? 'enabled' : 'skipped',
    conversation_detail_count: conversationDetail.length,
    deadline_candidate_count: deadlineCandidate.length,
    deadline_candidate: limitRow(deadlineCandidate, 25),
    note: 'Canvas activity context is read-only. Conversation details are optional and only deadline-related excerpts are returned; raw inbox bodies are not returned or stored.',
  };
}

async function getCourseAnalyticsContext(args: {
  course_id?: string | number;
  max_assignment?: number;
  max_student_summary?: number;
  max_participation?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxAssignment = Math.max(0, Number(args.max_assignment ?? 80));
  const maxStudentSummary = Math.max(0, Number(args.max_student_summary ?? 10));
  const maxParticipation = Math.max(0, Number(args.max_participation ?? 80));
  const user = await canvasGet('/users/self') as any;
  const userId = String(user.id);
  const [courseActivity, courseAssignment, studentSummary, userActivity, userAssignment, userCommunication] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/analytics/activity`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/analytics/assignments`, { async: false })),
    safe(() => canvasPaginate<any>(`/courses/${id}/analytics/student_summaries`, { student_id: userId })),
    safe(() => canvasGet(`/courses/${id}/analytics/users/${userId}/activity`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/analytics/users/${userId}/assignments`)),
    safe(() => canvasGet(`/courses/${id}/analytics/users/${userId}/communication`)),
  ]);

  const courseAssignmentValue = limitRow((courseAssignment.value as any[]) ?? [], maxAssignment);
  const studentSummaryValue = limitRow((studentSummary.value as any[]) ?? [], maxStudentSummary);
  const participationValue = limitRow(unwrapCanvasArray(userActivity.value, 'participations'), maxParticipation);
  const userAssignmentValue = limitRow((userAssignment.value as any[]) ?? [], maxAssignment);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    endpoint: [
      ['course_analytics_activity', courseActivity],
      ['course_analytics_assignment', courseAssignment],
      ['course_analytics_student_summary', studentSummary],
      ['analytics_user_activity', userActivity],
      ['analytics_user_assignment', userAssignment],
      ['analytics_user_communication', userCommunication],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error ? endpointStatus(one.error) : 'ok',
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    course_activity_status: courseActivity.error ? endpointStatus(courseActivity.error) : 'ok',
    course_activity: courseActivity.error ? null : compactAnalyticsActivity(courseActivity.value),
    course_assignment_status: courseAssignment.error ? endpointStatus(courseAssignment.error) : 'ok',
    course_assignment_count: rowCount(courseAssignment.value),
    returned_course_assignment_count: courseAssignmentValue.length,
    course_assignment: courseAssignmentValue.map(compactAnalyticsAssignment),
    student_summary_status: studentSummary.error ? endpointStatus(studentSummary.error) : 'ok',
    student_summary_count: rowCount(studentSummary.value),
    returned_student_summary_count: studentSummaryValue.length,
    student_summary: studentSummaryValue.map(compactAnalyticsStudentSummary),
    user_activity_status: userActivity.error ? endpointStatus(userActivity.error) : 'ok',
    user_activity: userActivity.error ? null : compactAnalyticsActivity(userActivity.value),
    user_participation_count: unwrapCanvasArray(userActivity.value, 'participations').length,
    returned_user_participation_count: participationValue.length,
    user_participation: participationValue.map(compactAnalyticsParticipation),
    user_assignment_status: userAssignment.error ? endpointStatus(userAssignment.error) : 'ok',
    user_assignment_count: rowCount(userAssignment.value),
    returned_user_assignment_count: userAssignmentValue.length,
    user_assignment: userAssignmentValue.map(compactAnalyticsAssignment),
    user_communication_status: userCommunication.error ? endpointStatus(userCommunication.error) : 'ok',
    user_communication: userCommunication.error ? null : compactAnalyticsCommunication(userCommunication.value),
    note: 'Canvas analytics context is read-only cross-check evidence. Analytics endpoints are often permission-bound under a student PAT and must not override submissions/self completion truth.',
  };
}

async function getCourseActionContext(args: {
  course_id?: string | number;
  start_date?: string;
  end_date?: string;
  max_history?: number;
  include_conversation_body?: boolean;
  max_conversation?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const now = new Date();
  const startDate = args.start_date ?? dateOffset(now, -14);
  const endDate = args.end_date ?? dateOffset(now, 45);
  const maxHistory = Number(args.max_history ?? 25);
  const maxConversation = Number(args.max_conversation ?? 5);
  const user = await canvasGet('/users/self') as any;
  const userId = String(user.id);

  const read = async <T>(name: string, fn: () => Promise<T>): Promise<{
    name: string;
    status: 'ok' | 'blocked_or_absent' | 'error';
    value: T | null;
    error: string | null;
    count: number;
    key: string[];
  }> => {
    const result = await safe(fn);
    return {
      name,
      status: endpointStatus(result.error),
      value: result.value,
      error: result.error,
      count: rowCount(result.value),
      key: keySample(result.value),
    };
  };

  const [
    plannerItem,
    todoItem,
    todoCount,
    missingSubmission,
    upcomingEvent,
    calendarItem,
    enrollment,
    assignmentGroup,
    selfGroup,
    courseGroup,
    courseTab,
    conversation,
    conversationCount,
    appointmentGroup,
    module,
    outcomeAlignment,
    outcomeResult,
    outcomeRollup,
    activityItem,
    activitySummary,
    recentHistory,
  ] = await Promise.all([
    read('planner_item', () => canvasPaginate<any>('/planner/items', {
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': `course_${id}`,
      filter: 'incomplete_items',
    })),
    read('todo_item', () => canvasPaginate<any>('/users/self/todo', { 'include[]': 'ungraded_quizzes' })),
    read('todo_count', () => canvasGet('/users/self/todo_item_count', { 'include[]': 'ungraded_quizzes' })),
    read('missing_submission', () => canvasPaginate<any>(`/users/${userId}/missing_submissions`, {
      'course_ids[]': id,
      'include[]': ['planner_overrides', 'course'],
      'filter[]': ['submittable', 'current_grading_period'],
    })),
    read('upcoming_event', () => canvasPaginate<any>('/users/self/upcoming_events')),
    read('calendar_item', () => canvasPaginate<any>('/users/self/calendar_events', {
      type: 'assignment',
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': `course_${id}`,
    })),
    read('enrollment', () => canvasPaginate<any>(`/courses/${id}/enrollments`, {
      user_id: userId,
      'include[]': 'current_points',
    })),
    read('assignment_group', () => canvasPaginate<any>(`/courses/${id}/assignment_groups`)),
    read('self_group', () => canvasPaginate<any>('/users/self/groups', {
      context_type: 'Course',
      'include[]': 'tabs',
    })),
    read('course_group', () => canvasPaginate<any>(`/courses/${id}/groups`, {
      only_own_groups: true,
      'include[]': 'tabs',
    })),
    read('course_tab', () => canvasPaginate<any>(`/courses/${id}/tabs`)),
    read('conversation', () => canvasPaginate<any>('/conversations', {
      scope: 'unread',
      'filter[]': `course_${id}`,
    })),
    read('conversation_count', () => canvasGet('/conversations/unread_count')),
    read('appointment_group', () => canvasPaginate<any>('/appointment_groups', {
      scope: 'reservable',
      'context_codes[]': `course_${id}`,
      'include[]': ['appointments', 'reserved_times', 'participant_count'],
    })),
    read('module', () => canvasPaginate<any>(`/courses/${id}/modules`, { 'include[]': 'items' })),
    read('outcome_alignment', () => canvasPaginate<any>(`/courses/${id}/outcome_alignments`, { student_id: userId })),
    read('outcome_result', () => canvasGet(`/courses/${id}/outcome_results`, {
      'user_ids[]': userId,
      'include[]': 'alignments',
    })),
    read('outcome_rollup', () => canvasGet(`/courses/${id}/outcome_rollups`, {
      'user_ids[]': userId,
      'exclude[]': ['missing_user_rollups', 'missing_outcome_results'],
    })),
    read('activity_item', () => canvasPaginate<any>('/users/self/activity_stream', { only_active_courses: true })),
    read('activity_summary', () => canvasPaginate<any>('/users/self/activity_stream/summary', { only_active_courses: true })),
    read('recent_history', () => canvasGet(`/users/${userId}/history`, { per_page: 25 })),
  ]);

  const ownGroup = [
    ...((selfGroup.value as any[]) ?? []),
    ...((courseGroup.value as any[]) ?? []),
  ].filter((one: any) => String(one?.course_id) === String(id));
  const enrollmentRow = ((enrollment.value as any[]) ?? [])[0] ?? null;
  const grade = enrollmentRow?.grades ?? null;
  const moduleItem = ((module.value as any[]) ?? []).flatMap((one: any) => (
    Array.isArray(one?.items)
      ? one.items
        .filter((item: any) => item?.type === 'Assignment' || item?.content_id)
        .map((item: any) => compactModuleGate(one, item))
      : []
  ));
  const historyItem = ((recentHistory.value as any[]) ?? [])
    .filter((one: any) => String(one?.context_id ?? '') === String(id));
  const activityForCourse = ((activityItem.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id));
  const todoForCourse = ((todoItem.value as any[]) ?? [])
    .filter((one: any) => String(one?.assignment?.course_id ?? one?.course_id ?? '') === String(id));
  const conversationForCourse = limitRow(((conversation.value as any[]) ?? []), maxConversation);
  const conversationDetail = args.include_conversation_body
    ? await Promise.all(conversationForCourse.map((one: any) => read(
      `conversation_detail:${one?.id}`,
      () => canvasGet(`/conversations/${one?.id}`),
    )))
    : [];
  const conversationCandidate = conversationDetail.flatMap((one) => (
    one.value ? compactConversationDetail(one.value) : []
  ));

  const endpoint = [
    plannerItem,
    todoItem,
    todoCount,
    missingSubmission,
    upcomingEvent,
    calendarItem,
    enrollment,
    assignmentGroup,
    selfGroup,
    courseGroup,
    courseTab,
    conversation,
    conversationCount,
    appointmentGroup,
    module,
    outcomeAlignment,
    outcomeResult,
    outcomeRollup,
    activityItem,
    activitySummary,
    recentHistory,
  ].map((one) => ({
    name: one.name,
    status: one.status,
    count: one.count,
    key: one.key,
    error: one.error,
  }));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    date_window: { start_date: startDate, end_date: endDate },
    endpoint,
    queue_context: {
      planner_item_status: plannerItem.status,
      planner_item_count: plannerItem.count,
      planner_item: limitRow(((plannerItem.value as any[]) ?? []).map(compactPlannerItem), 50),
      todo_item_status: todoItem.status,
      todo_item_count: todoForCourse.length,
      todo_item: limitRow(todoForCourse.map(compactTodoItem), 50),
      todo_count_status: todoCount.status,
      todo_count: todoCount.value,
      missing_submission_status: missingSubmission.status,
      missing_submission_count: missingSubmission.count,
      missing_submission: limitRow(((missingSubmission.value as any[]) ?? []).map(compactAssignmentLike), 50),
      upcoming_event_status: upcomingEvent.status,
      upcoming_event_count: upcomingEvent.count,
      upcoming_event: limitRow(((upcomingEvent.value as any[]) ?? [])
        .filter((one: any) => String(one?.course_id ?? one?.assignment?.course_id ?? '') === String(id))
        .map(compactCalendarItem), 50),
      calendar_item_status: calendarItem.status,
      calendar_item_count: calendarItem.count,
      calendar_item: limitRow(((calendarItem.value as any[]) ?? []).map(compactCalendarItem), 50),
    },
    grade_context: {
      enrollment_status: enrollment.status,
      enrollment_count: enrollment.count,
      enrollment_key: keySample(enrollmentRow),
      grade_key: keySample(grade),
      assignment_group_status: assignmentGroup.status,
      assignment_group_count: assignmentGroup.count,
      assignment_group: limitRow(((assignmentGroup.value as any[]) ?? []).map((one: any) => ({
        assignment_group_id: one?.id ?? null,
        name: one?.name ?? null,
        group_weight: one?.group_weight ?? null,
        rule_key: keySample(one?.rules),
      })), 50),
    },
    group_context: {
      self_group_status: selfGroup.status,
      course_group_status: courseGroup.status,
      own_group_count: ownGroup.length,
      own_group: limitRow(ownGroup.map(compactGroup), 50),
    },
    navigation_context: {
      course_tab_status: courseTab.status,
      course_tab_count: courseTab.count,
      course_tab: limitRow(((courseTab.value as any[]) ?? []).map(compactTab), 50),
    },
    inbox_context: {
      conversation_status: conversation.status,
      unread_conversation_count: conversation.count,
      conversation: limitRow(((conversation.value as any[]) ?? []).map(compactConversation), 25),
      unread_count_status: conversationCount.status,
      unread_count_key: keySample(conversationCount.value),
      body_scan_status: args.include_conversation_body ? 'enabled' : 'disabled',
      deadline_candidate_count: conversationCandidate.length,
      deadline_candidate: limitRow(conversationCandidate, 25),
      body_scan_error: conversationDetail
        .filter((one) => one.status === 'error')
        .map((one) => `${one.name}: ${one.error}`),
    },
    calendar_context: {
      appointment_group_status: appointmentGroup.status,
      appointment_group_count: appointmentGroup.count,
      appointment_group: limitRow(((appointmentGroup.value as any[]) ?? []).map((one: any) => ({
        appointment_group_id: one?.id ?? null,
        title: one?.title ?? null,
        start_at: one?.start_at ?? null,
        end_at: one?.end_at ?? null,
        participant_count: one?.participant_count ?? null,
        is_requiring_action: !!one?.requiring_action,
        html_url: one?.html_url ?? null,
      })), 25),
    },
    module_context: {
      module_status: module.status,
      assignment_gate_count: moduleItem.length,
      assignment_gate: limitRow(moduleItem, 100),
    },
    outcome_context: {
      outcome_alignment_status: outcomeAlignment.status,
      outcome_alignment_count: outcomeAlignment.count,
      outcome_result_status: outcomeResult.status,
      outcome_result_key: keySample(outcomeResult.value),
      outcome_rollup_status: outcomeRollup.status,
      outcome_rollup_key: keySample(outcomeRollup.value),
    },
    weak_signal_context: {
      activity_status: activityItem.status,
      activity_count: activityForCourse.length,
      activity: limitRow(activityForCourse.map(compactActivity), maxHistory),
      activity_summary_status: activitySummary.status,
      activity_summary: limitRow(((activitySummary.value as any[]) ?? []).map((one: any) => ({
        type: one?.type ?? null,
        notification_category: one?.notification_category ?? null,
        count: one?.count ?? null,
        unread_count: one?.unread_count ?? null,
      })), maxHistory),
      history_status: recentHistory.status,
      history_count: historyItem.length,
      history: limitRow(historyItem.map(compactHistory), maxHistory),
      note: 'Weak seen/opened context only; never use this as completion proof.',
    },
  };
}

async function getCoursePlannerContext(args: {
  course_id?: string | number;
  start_date?: string;
  end_date?: string;
  filter?: 'incomplete_items' | 'complete_items' | 'new_activity';
  max_item?: number;
  max_note?: number;
  max_override?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const now = new Date();
  const startDate = args.start_date ?? dateOffset(now, -30);
  const endDate = args.end_date ?? dateOffset(now, 60);
  const filter = args.filter ?? 'incomplete_items';
  const maxItem = Math.max(0, Number(args.max_item ?? 120));
  const maxNote = Math.max(0, Number(args.max_note ?? 80));
  const maxOverride = Math.max(0, Number(args.max_override ?? 120));
  const maxChar = Number(args.max_chars ?? 600);
  const contextCode = `course_${id}`;

  const [plannerItem, plannerNote, plannerOverride] = await Promise.all([
    safe(() => canvasPaginate<any>('/planner/items', {
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': contextCode,
      filter,
    })),
    safe(() => canvasPaginate<any>('/planner_notes', {
      start_date: startDate,
      end_date: endDate,
      'context_codes[]': contextCode,
    })),
    safe(() => canvasPaginate<any>('/planner/overrides')),
  ]);

  const plannerItemValue = limitRow((plannerItem.value as any[]) ?? [], maxItem);
  const plannerNoteValue = limitRow(((plannerNote.value as any[]) ?? [])
    .filter((one: any) => String(one?.course_id ?? '') === String(id) || one?.course_id === null), maxNote);
  const plannerOverrideValue = limitRow((plannerOverride.value as any[]) ?? [], maxOverride);
  const plannerItemCompact = plannerItemValue.map(compactPlannerItem);
  const plannerNoteCompact = plannerNoteValue.map((one: any) => compactPlannerNote(one, maxChar));
  const plannerOverrideCompact = plannerOverrideValue.map(compactPlannerOverride);
  const noteLink = plannerNoteValue.flatMap((one: any) => ([
    one?.linked_object_html_url,
    one?.linked_object_url,
  ].filter(Boolean).map((url: string) => ({
    kind: classify(url),
    url,
    source: { type: 'planner_note', id: one?.id, title: one?.title },
  }))));

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    date_window: { start_date: startDate, end_date: endDate },
    filter,
    endpoint: [
      ['planner_item', plannerItem],
      ['planner_note', plannerNote],
      ['planner_override', plannerOverride],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    planner_item_status: plannerItem.error ? endpointStatus(plannerItem.error) : 'ok',
    planner_item_count: rowCount(plannerItem.value),
    returned_planner_item_count: plannerItemCompact.length,
    planner_item: plannerItemCompact,
    planner_note_status: plannerNote.error ? endpointStatus(plannerNote.error) : 'ok',
    planner_note_count: rowCount(plannerNote.value),
    returned_planner_note_count: plannerNoteCompact.length,
    planner_note: plannerNoteCompact,
    planner_override_status: plannerOverride.error ? endpointStatus(plannerOverride.error) : 'ok',
    planner_override_count: rowCount(plannerOverride.value),
    returned_planner_override_count: plannerOverrideCompact.length,
    planner_override: plannerOverrideCompact,
    marked_complete_count: plannerOverrideCompact.filter((one: any) => one.is_marked_complete).length,
    dismissed_count: plannerOverrideCompact.filter((one: any) => one.is_dismissed).length,
    linked_note_count: plannerNoteCompact.filter((one: any) => one.linked_object_id).length,
    link: noteLink,
    note: 'Planner complete/dismissed state is user planning context only; use submissions/self for completion truth.',
  };
}

async function getCourseDueDateContext(args: {
  course_id?: string | number;
  assignment_id?: Array<string | number> | string | number;
  include_assignment?: boolean;
  include_setting?: boolean;
  include_permission?: boolean;
  permission_name?: Array<string | number>;
  max_assignment?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeAssignment = args.include_assignment !== false;
  const includeSetting = args.include_setting !== false;
  const includePermission = args.include_permission !== false;
  const maxAssignment = Math.max(0, Number(args.max_assignment ?? 120));
  const requestedAssignmentId = normalizeMaybeStringArray(args.assignment_id, 'assignment_id');
  const permissionName = normalizeStringArray(args.permission_name, 'permission_name');
  const permission = permissionName.length > 0
    ? permissionName
    : ['read_grades', 'view_all_grades', 'manage_assignments', 'manage_grades', 'manage_files', 'read_as_admin'];

  const [self, assignment, courseTodo, setting, coursePermission] = await Promise.all([
    safe(() => canvasGet('/users/self')),
    includeAssignment
      ? safe(() => canvasPaginate<any>(`/courses/${id}/assignments`, { 'include[]': ['all_dates', 'overrides'] }))
      : Promise.resolve({ value: null, error: null }),
    safe(() => canvasPaginate<any>(`/courses/${id}/todo`)),
    includeSetting
      ? safe(() => canvasGet(`/courses/${id}/settings`))
      : Promise.resolve({ value: null, error: null }),
    includePermission
      ? safe(() => canvasGet(`/courses/${id}/permissions`, { 'permissions[]': permission }))
      : Promise.resolve({ value: null, error: null }),
  ]);

  const userId = (self.value as any)?.id ? String((self.value as any).id) : null;
  const assignmentValue = limitRow((assignment.value as any[]) ?? [], maxAssignment);
  const selectedAssignmentId = limitRow((requestedAssignmentId.length > 0
    ? requestedAssignmentId
    : assignmentValue.map((one: any) => String(one?.id)).filter(Boolean)), maxAssignment);
  const effectiveDueDate = selectedAssignmentId.length > 0
    ? await safe(() => canvasGet(`/courses/${id}/effective_due_dates`, { 'assignment_ids[]': selectedAssignmentId }))
    : { value: null, error: null };
  const courseTodoValue = (courseTodo.value as any[]) ?? [];
  const effectiveDueDateValue = effectiveDueDate.value && typeof effectiveDueDate.value === 'object'
    ? effectiveDueDate.value
    : null;
  const effectiveAssignmentKey = effectiveDueDateValue
    ? Object.keys(effectiveDueDateValue as Record<string, unknown>)
    : [];
  const currentUserEffectiveDueDate = effectiveDueDate.error
    ? selectedAssignmentId.map((assignmentId) => ({
      assignment_id: assignmentId,
      user_id: userId,
      status: endpointStatus(effectiveDueDate.error),
      due_at: null,
      unlock_at: null,
      lock_at: null,
      grading_period_id: null,
      in_closed_grading_period: null,
    }))
    : compactEffectiveDueDate(effectiveDueDate.value, selectedAssignmentId, userId);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    include_assignment: includeAssignment,
    include_setting: includeSetting,
    include_permission: includePermission,
    endpoint: [
      ['user_self', self],
      ['assignment_all_date', assignment],
      ['course_effective_due_date', effectiveDueDate],
      ['course_todo', courseTodo],
      ['course_setting', setting],
      ['course_permission', coursePermission],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    assignment_status: assignment.error ? endpointStatus(assignment.error) : (includeAssignment ? 'ok' : 'skipped'),
    assignment_count: rowCount(assignment.value),
    returned_assignment_count: assignmentValue.length,
    assignment: assignmentValue.map(compactCourseDueAssignment),
    selected_assignment_id: selectedAssignmentId,
    effective_due_date_status: effectiveDueDate.error ? endpointStatus(effectiveDueDate.error) : (selectedAssignmentId.length > 0 ? 'ok' : 'skipped'),
    effective_due_date_assignment_count: effectiveAssignmentKey.length,
    effective_due_date_current_user_count: currentUserEffectiveDueDate.filter((one: any) => one.status === 'ok').length,
    effective_due_date: currentUserEffectiveDueDate,
    effective_due_date_privacy_note: 'Canvas effective_due_dates can return a nested assignment/user map; this tool returns only the current token user row and count/key metadata.',
    course_todo_status: courseTodo.error ? endpointStatus(courseTodo.error) : 'ok',
    course_todo_count: courseTodoValue.length,
    course_todo: limitRow(courseTodoValue.map(compactTodoItem), 50),
    setting_status: setting.error ? endpointStatus(setting.error) : (includeSetting ? 'ok' : 'skipped'),
    setting: setting.value ? compactCourseSetting(setting.value) : null,
    permission_status: coursePermission.error ? endpointStatus(coursePermission.error) : (includePermission ? 'ok' : 'skipped'),
    permission_name: permission,
    permission: coursePermission.value ? compactCoursePermission(coursePermission.value) : null,
    note: 'Due-date context is for deadline reconciliation only. Completion truth still comes from submissions/self and quiz submission endpoints.',
  };
}

async function getCourseOutcomeContext(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  include_result?: boolean;
  max_group?: number;
  max_link?: number;
  max_alignment?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeResult = args.include_result !== false;
  const maxGroup = Math.max(0, Number(args.max_group ?? 80));
  const maxLink = Math.max(0, Number(args.max_link ?? 120));
  const maxAlignment = Math.max(0, Number(args.max_alignment ?? 120));
  const maxChar = Number(args.max_chars ?? 600);

  const self = await safe(() => canvasGet('/users/self'));
  const userId = (self.value as any)?.id ? String((self.value as any).id) : null;
  const alignmentParam: Record<string, CanvasParamValue> = {};
  if (userId) alignmentParam.student_id = userId;
  if (args.assignment_id) alignmentParam.assignment_id = String(args.assignment_id);

  const [rootGroup, outcomeGroup, outcomeLink, outcomeAlignment, outcomeProficiency, outcomeResult, outcomeRollup] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/root_outcome_group`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/outcome_groups`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/outcome_group_links`, {
      outcome_style: 'full',
      outcome_group_style: 'full',
    })),
    safe(() => canvasPaginate<any>(`/courses/${id}/outcome_alignments`, alignmentParam)),
    safe(() => canvasGet(`/courses/${id}/outcome_proficiency`)),
    includeResult && userId
      ? safe(() => canvasGet(`/courses/${id}/outcome_results`, {
        'user_ids[]': userId,
        'include[]': ['alignments', 'outcomes'],
      }))
      : Promise.resolve({ value: null, error: includeResult ? 'users/self unavailable; outcome results skipped' : null }),
    includeResult && userId
      ? safe(() => canvasGet(`/courses/${id}/outcome_rollups`, {
        'user_ids[]': userId,
        'exclude[]': ['missing_user_rollups', 'missing_outcome_results'],
      }))
      : Promise.resolve({ value: null, error: includeResult ? 'users/self unavailable; outcome rollups skipped' : null }),
  ]);

  const outcomeGroupValue = limitRow((outcomeGroup.value as any[]) ?? [], maxGroup);
  const outcomeLinkValue = limitRow((outcomeLink.value as any[]) ?? [], maxLink);
  const outcomeAlignmentValue = limitRow((outcomeAlignment.value as any[]) ?? [], maxAlignment);
  const compactProficiency = compactOutcomeProficiency(outcomeProficiency.value);
  const compactResult = compactOutcomeResultContainer(outcomeResult.value);
  const compactRollup = compactOutcomeRollupContainer(outcomeRollup.value);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user_id: userId,
    assignment_id: args.assignment_id ? String(args.assignment_id) : null,
    include_result: includeResult,
    endpoint: [
      ['user_self', self],
      ['outcome_root_group', rootGroup],
      ['outcome_group', outcomeGroup],
      ['outcome_group_link', outcomeLink],
      ['outcome_alignment', outcomeAlignment],
      ['outcome_proficiency', outcomeProficiency],
      ['outcome_result', outcomeResult],
      ['outcome_rollup', outcomeRollup],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    root_group_status: rootGroup.error ? endpointStatus(rootGroup.error) : 'ok',
    root_group: rootGroup.value ? compactOutcomeGroup(rootGroup.value, maxChar) : null,
    outcome_group_status: outcomeGroup.error ? endpointStatus(outcomeGroup.error) : 'ok',
    outcome_group_count: rowCount(outcomeGroup.value),
    returned_outcome_group_count: outcomeGroupValue.length,
    outcome_group: outcomeGroupValue.map((one: any) => compactOutcomeGroup(one, maxChar)),
    outcome_link_status: outcomeLink.error ? endpointStatus(outcomeLink.error) : 'ok',
    outcome_link_count: rowCount(outcomeLink.value),
    returned_outcome_link_count: outcomeLinkValue.length,
    outcome_link: outcomeLinkValue.map((one: any) => compactOutcomeLink(one, maxChar)),
    outcome_alignment_status: outcomeAlignment.error ? endpointStatus(outcomeAlignment.error) : 'ok',
    outcome_alignment_count: rowCount(outcomeAlignment.value),
    returned_outcome_alignment_count: outcomeAlignmentValue.length,
    outcome_alignment: compactOutcomeAlignment(outcomeAlignmentValue),
    outcome_proficiency_status: outcomeProficiency.error ? endpointStatus(outcomeProficiency.error) : 'ok',
    outcome_proficiency: compactProficiency,
    outcome_result_status: outcomeResult.error ? endpointStatus(outcomeResult.error) : (includeResult ? 'ok' : 'skipped'),
    ...compactResult,
    outcome_rollup_status: outcomeRollup.error ? endpointStatus(outcomeRollup.error) : (includeResult ? 'ok' : 'skipped'),
    ...compactRollup,
    note: 'Outcome context is read-only assessment/rubric context. Result and rollup reads are scoped to users/self; it does not pull broad class outcome results.',
  };
}

async function getCourseAssessmentContext(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  rubric_id?: string | number;
  live_assessment_id?: string | number;
  max_rubric?: number;
  max_live_assessment?: number;
  max_live_assessment_result?: number;
  max_question_bank?: number;
  max_question?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const assignmentId = args.assignment_id ? String(args.assignment_id) : null;
  const requestedRubricId = args.rubric_id ? String(args.rubric_id) : null;
  const requestedLiveAssessmentId = args.live_assessment_id ? String(args.live_assessment_id) : null;
  const maxRubric = Math.max(0, Number(args.max_rubric ?? 50));
  const maxLiveAssessment = Math.max(0, Number(args.max_live_assessment ?? 50));
  const maxLiveAssessmentResult = Math.max(0, Number(args.max_live_assessment_result ?? 80));
  const maxQuestionBank = Math.max(0, Number(args.max_question_bank ?? 50));
  const maxQuestion = Math.max(0, Number(args.max_question ?? 80));
  const maxChar = Number(args.max_chars ?? 600);
  const [self, rubricCatalog, liveAssessment, questionBank, assignment, learningObjectDate, submission, rubricRead, annotationRead] = await Promise.all([
    safe(() => canvasGet('/users/self')),
    safe(() => canvasPaginate<any>(`/courses/${id}/rubrics`)),
    safe(() => canvasGet(`/courses/${id}/live_assessments`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/question_banks`)),
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}`))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; assignment rubric skipped' }),
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}/date_details`, { 'include[]': 'peer_review' }))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; learning-object date skipped' }),
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}/submissions/self`, {
        'include[]': ['submission_history', 'rubric_assessment', 'submission_comments'],
      }))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; submission feedback skipped' }),
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}/submissions/self/rubric_assessments/read`))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; rubric read-state skipped' }),
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}/submissions/self/document_annotations/read`))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; annotation read-state skipped' }),
  ]);
  const rubricCatalogValue = limitRow((rubricCatalog.value as any[]) ?? [], maxRubric);
  const liveAssessmentValue = limitRow(unwrapCanvasArray(liveAssessment.value, 'assessments'), maxLiveAssessment);
  const questionBankValue = limitRow((questionBank.value as any[]) ?? [], maxQuestionBank);
  const assignmentValue = assignment.value as any;
  const selectedRubricId = requestedRubricId
    ?? (rubricCatalogValue.find((one: any) => one?.id)?.id ? String(rubricCatalogValue.find((one: any) => one?.id)?.id) : null)
    ?? (assignmentValue?.rubric_settings?.id ? String(assignmentValue.rubric_settings.id) : null);
  const selectedLiveAssessment = requestedLiveAssessmentId
    ? liveAssessmentValue.find((one: any) => String(one?.id ?? '') === requestedLiveAssessmentId) ?? { id: requestedLiveAssessmentId }
    : liveAssessmentValue.find((one: any) => one?.id) ?? null;
  const selfValue = self.value as any;
  const selectedQuestionBank = questionBankValue.find((one: any) => one?.id) ?? null;
  const [rubricDetail, rubricUsedLocation, liveAssessmentResult, questionBankDetail, assessmentQuestion] = await Promise.all([
    selectedRubricId
      ? safe(() => canvasGet(`/courses/${id}/rubrics/${selectedRubricId}`))
      : Promise.resolve({ value: null, error: 'no rubric visible; rubric detail skipped' }),
    selectedRubricId
      ? safe(() => canvasGet(`/courses/${id}/rubrics/${selectedRubricId}/used_locations`))
      : Promise.resolve({ value: null, error: 'no rubric visible; rubric used-location skipped' }),
    selectedLiveAssessment?.id && selfValue?.id
      ? safe(() => canvasGet(`/courses/${id}/live_assessments/${selectedLiveAssessment.id}/results`, { user_id: String(selfValue.id) }))
      : Promise.resolve({ value: null, error: selectedLiveAssessment?.id ? 'current user unavailable; live assessment result skipped' : 'no live assessment visible; live assessment result skipped' }),
    selectedQuestionBank?.id
      ? safe(() => canvasGet(`/courses/${id}/question_banks/${selectedQuestionBank.id}`))
      : Promise.resolve({ value: null, error: 'no question bank visible; question-bank detail skipped' }),
    selectedQuestionBank?.id
      ? safe(() => canvasPaginate<any>(`/courses/${id}/question_banks/${selectedQuestionBank.id}/questions`))
      : Promise.resolve({ value: [], error: 'no question bank visible; assessment question skipped' }),
  ]);
  const liveAssessmentResultValue = limitRow(unwrapCanvasArray(liveAssessmentResult.value, 'results'), maxLiveAssessmentResult);
  const assessmentQuestionValue = limitRow((assessmentQuestion.value as any[]) ?? [], maxQuestion);
  const submissionValue = submission.value as any;
  const rubricAssessment = compactRubricAssessment(submissionValue?.rubric_assessment);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    assignment_id: assignmentId,
    endpoint: [
      ['rubric_catalog', rubricCatalog],
      ['rubric_detail', rubricDetail],
      ['rubric_used_location', rubricUsedLocation],
      ['live_assessment', liveAssessment],
      ['live_assessment_result', liveAssessmentResult],
      ['assessment_question_bank', questionBank],
      ['assessment_question_bank_detail', questionBankDetail],
      ['assessment_question', assessmentQuestion],
      ['assignment', assignment],
      ['learning_object_date', learningObjectDate],
      ['submission_feedback', submission],
      ['rubric_read_state', rubricRead],
      ['document_annotation_read_state', annotationRead],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('not provided') || one.error?.includes('skipped') ? 'skipped' : endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    rubric_catalog_status: rubricCatalog.error ? endpointStatus(rubricCatalog.error) : 'ok',
    rubric_catalog_count: rowCount(rubricCatalog.value),
    returned_rubric_catalog_count: rubricCatalogValue.length,
    rubric_catalog: rubricCatalogValue.map(compactRubricCatalog),
    selected_rubric_id: selectedRubricId,
    rubric_detail_status: rubricDetail.error?.includes('no rubric visible') ? 'skipped' : (rubricDetail.error ? endpointStatus(rubricDetail.error) : 'ok'),
    rubric_detail: rubricDetail.error ? null : compactRubricCatalog(rubricDetail.value),
    rubric_used_location_status: rubricUsedLocation.error?.includes('no rubric visible') ? 'skipped' : (rubricUsedLocation.error ? endpointStatus(rubricUsedLocation.error) : 'ok'),
    rubric_used_location: rubricUsedLocation.error ? null : compactRubricUsedLocation(rubricUsedLocation.value),
    live_assessment_status: liveAssessment.error ? endpointStatus(liveAssessment.error) : 'ok',
    live_assessment_count: rowCount(liveAssessment.value),
    returned_live_assessment_count: liveAssessmentValue.length,
    selected_live_assessment_id: selectedLiveAssessment?.id ? String(selectedLiveAssessment.id) : null,
    live_assessment: liveAssessmentValue.map((one: any) => compactLiveAssessment(one, maxChar)),
    live_assessment_result_status: liveAssessmentResult.error?.includes('skipped') ? 'skipped' : (liveAssessmentResult.error ? endpointStatus(liveAssessmentResult.error) : 'ok'),
    live_assessment_result_count: rowCount(liveAssessmentResult.value),
    returned_live_assessment_result_count: liveAssessmentResultValue.length,
    live_assessment_result: liveAssessmentResultValue.map(compactLiveAssessmentResult),
    assessment_question_bank_status: questionBank.error ? endpointStatus(questionBank.error) : 'ok',
    assessment_question_bank_count: rowCount(questionBank.value),
    returned_assessment_question_bank_count: questionBankValue.length,
    selected_question_bank_id: selectedQuestionBank?.id ? String(selectedQuestionBank.id) : null,
    assessment_question_bank: questionBankValue.map(compactAssessmentQuestionBank),
    assessment_question_bank_detail_status: questionBankDetail.error?.includes('no question bank visible') ? 'skipped' : (questionBankDetail.error ? endpointStatus(questionBankDetail.error) : 'ok'),
    assessment_question_bank_detail: questionBankDetail.error ? null : compactAssessmentQuestionBank(questionBankDetail.value),
    assessment_question_status: assessmentQuestion.error?.includes('no question bank visible') ? 'skipped' : (assessmentQuestion.error ? endpointStatus(assessmentQuestion.error) : 'ok'),
    assessment_question_count: rowCount(assessmentQuestion.value),
    returned_assessment_question_count: assessmentQuestionValue.length,
    assessment_question: assessmentQuestionValue.map((one: any) => compactAssessmentQuestion(one, maxChar)),
    assignment_status: assignment.error?.includes('not provided') ? 'skipped' : (assignment.error ? endpointStatus(assignment.error) : 'ok'),
    assignment: assignmentValue ? compactAssignmentLike(assignmentValue) : null,
    embedded_rubric_count: Array.isArray(assignmentValue?.rubric) ? assignmentValue.rubric.length : 0,
    embedded_rubric: compactRubric(assignmentValue?.rubric),
    rubric_settings_key: keySample(assignmentValue?.rubric_settings),
    learning_object_date_status: learningObjectDate.error?.includes('not provided') ? 'skipped' : (learningObjectDate.error ? endpointStatus(learningObjectDate.error) : 'ok'),
    learning_object_date: learningObjectDate.error ? null : compactLearningObjectDate(learningObjectDate.value),
    submission_feedback_status: submission.error?.includes('not provided') ? 'skipped' : (submission.error ? endpointStatus(submission.error) : 'ok'),
    rubric_assessment_count: rubricAssessment.length,
    rubric_assessment: rubricAssessment,
    rubric_read_state_status: rubricRead.error?.includes('not provided') ? 'skipped' : (rubricRead.error ? endpointStatus(rubricRead.error) : 'ok'),
    rubric_read_state: rubricRead.value,
    document_annotation_read_state_status: annotationRead.error?.includes('not provided') ? 'skipped' : (annotationRead.error ? endpointStatus(annotationRead.error) : 'ok'),
    document_annotation_read_state: annotationRead.value,
    note: 'Assessment context is read-only. Course rubric catalog/detail/used-location, LiveAssessments, assessment question banks, and learning-object date details are best-effort under a student PAT; assignment-embedded rubric and submissions/self remain the primary student-visible assessment evidence. LiveAssessment results are filtered to users/self when queried. Assessment questions are compacted without answer bodies, correctness, or answer weights.',
  };
}

async function getAssignmentModerationContext(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  anonymous_id?: string | number;
  max_student?: number;
}): Promise<unknown> {
  const id = courseId(args);
  if (!args.assignment_id) throw new Error('assignment_id is required');
  const assignmentId = String(args.assignment_id);
  const anonymousId = args.anonymous_id ? String(args.anonymous_id) : null;
  const maxStudent = Math.max(0, Number(args.max_student ?? 80));
  const self = await safe(() => canvasGet('/users/self'));
  const userId = (self.value as any)?.id ? String((self.value as any).id) : null;
  const [assignment, moderatedStudent, provisionalStatus, anonymousProvisionalStatus] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/assignments/${assignmentId}/moderated_students`)),
    userId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}/provisional_grades/status`, { student_id: userId }))
      : Promise.resolve({ value: null, error: 'users/self unavailable; provisional grade status skipped' }),
    anonymousId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}/anonymous_provisional_grades/status`, { anonymous_id: anonymousId }))
      : Promise.resolve({ value: null, error: 'anonymous_id not provided; anonymous provisional grade status skipped' }),
  ]);
  const moderatedStudentValue = limitRow((moderatedStudent.value as any[]) ?? [], maxStudent);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    assignment_id: assignmentId,
    user_id: userId,
    anonymous_id: anonymousId,
    endpoint: [
      ['user_self', self],
      ['assignment', assignment],
      ['moderated_student', moderatedStudent],
      ['provisional_grade_status', provisionalStatus],
      ['anonymous_provisional_grade_status', anonymousProvisionalStatus],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('skipped') || one.error?.includes('not provided') || one.error?.includes('unavailable') ? 'skipped' : endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    assignment_status: assignment.error ? endpointStatus(assignment.error) : 'ok',
    assignment: assignment.value ? compactAssignmentLike(assignment.value) : null,
    moderated_student_status: moderatedStudent.error ? endpointStatus(moderatedStudent.error) : 'ok',
    moderated_student_count: rowCount(moderatedStudent.value),
    returned_moderated_student_count: moderatedStudentValue.length,
    moderated_student: moderatedStudentValue.map(compactModeratedStudent),
    provisional_grade_status: provisionalStatus.error?.includes('unavailable') ? 'skipped' : (provisionalStatus.error ? endpointStatus(provisionalStatus.error) : 'ok'),
    provisional_grade: provisionalStatus.error ? null : compactProvisionalGradeStatus(provisionalStatus.value),
    anonymous_provisional_grade_status: anonymousProvisionalStatus.error?.includes('not provided') ? 'skipped' : (anonymousProvisionalStatus.error ? endpointStatus(anonymousProvisionalStatus.error) : 'ok'),
    anonymous_provisional_grade: anonymousProvisionalStatus.error ? null : compactProvisionalGradeStatus(anonymousProvisionalStatus.value),
    note: 'Moderated Grading context is read-only. It checks moderated-student and provisional-grade status visibility, but never selects students, selects provisional grades, bulk-selects, publishes, grades, or comments on submissions.',
  };
}

async function getCourseCollaborationContext(args: {
  course_id?: string | number;
  include_group_collaboration?: boolean;
  include_member?: boolean;
  max_collaboration?: number;
  max_group?: number;
  max_member?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeGroupCollaboration = args.include_group_collaboration !== false;
  const includeMember = args.include_member !== false;
  const maxCollaboration = Math.max(0, Number(args.max_collaboration ?? 80));
  const maxGroup = Math.max(0, Number(args.max_group ?? 10));
  const maxMember = Math.max(0, Number(args.max_member ?? 25));
  const maxChar = Number(args.max_chars ?? 600);

  const [courseCollaboration, ownGroup] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/collaborations`)),
    includeGroupCollaboration
      ? safe(() => canvasPaginate<any>(`/courses/${id}/groups`, {
        only_own_groups: true,
        'include[]': 'tabs',
      }))
      : Promise.resolve({ value: null, error: null }),
  ]);

  const ownGroupValue = limitRow((ownGroup.value as any[]) ?? [], maxGroup);
  const groupCollaborationResult = includeGroupCollaboration
    ? await pool(ownGroupValue, async (group: any) => {
      const groupId = group?.id ?? null;
      if (!groupId) return { group, value: null, error: 'group id unavailable' };
      const result = await safe(() => canvasPaginate<any>(`/groups/${groupId}/collaborations`));
      return { group, value: result.value, error: result.error };
    })
    : [];

  const courseCollaborationValue = ((courseCollaboration.value as any[]) ?? []).map((one: any) => ({
    context_source: 'course',
    group: null,
    collaboration: one,
  }));
  const groupCollaborationValue = groupCollaborationResult.flatMap((one: any) => (
    ((one.value as any[]) ?? []).map((collaboration: any) => ({
      context_source: 'group',
      group: one.group,
      collaboration,
    }))
  ));
  const collaborationSource = limitRow([...courseCollaborationValue, ...groupCollaborationValue], maxCollaboration);
  const memberResult = includeMember
    ? await pool(collaborationSource, async (one: any) => {
      const collaborationId = one.collaboration?.id ?? null;
      if (!collaborationId) return { collaboration_id: null, value: null, error: 'collaboration id unavailable' };
      const result = await safe(() => canvasPaginate<any>(`/collaborations/${collaborationId}/members`));
      return { collaboration_id: collaborationId, value: result.value, error: result.error };
    })
    : [];
  const memberByCollaborationId = new Map(memberResult.map((one: any) => [String(one.collaboration_id), one]));

  const collaboration = collaborationSource.map((one: any) => {
    const compact = compactCollaboration(one.collaboration, maxChar);
    const collaborationId = String(compact.collaboration_id ?? '');
    const member = memberByCollaborationId.get(collaborationId);
    const text = [
      compact.title,
      compact.description_text,
      compact.collaboration_type,
      compact.url,
    ].filter(Boolean).join(' ');
    const link = [
      compact.url,
    ].filter(Boolean).map((url: any) => ({
      kind: classify(String(url)),
      url,
      source: { type: 'collaboration', id: compact.collaboration_id, title: compact.title },
    }));
    const signal = materialSignal(text, link, [], { is_group: one.context_source === 'group' });
    return {
      ...compact,
      context_source: one.context_source,
      group: one.group ? compactGroup(one.group) : null,
      member_status: member?.error ? endpointStatus(member.error) : (includeMember ? 'ok' : 'skipped'),
      member_count: rowCount(member?.value),
      member: limitRow(((member?.value as any[]) ?? []).map(compactCollaborator), maxMember),
      link,
      requirement_tag: signal.requirement_tag,
      work_mode: signal.work_mode,
    };
  });

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    endpoint: [
      ['course_collaboration', courseCollaboration],
      ['own_group', ownGroup],
      ...groupCollaborationResult.map((one: any) => [`group_collaboration:${one.group?.id ?? 'unknown'}`, { value: one.value, error: one.error }]),
      ...memberResult.map((one: any) => [`collaboration_member:${one.collaboration_id ?? 'unknown'}`, { value: one.value, error: one.error }]),
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    course_collaboration_status: courseCollaboration.error ? endpointStatus(courseCollaboration.error) : 'ok',
    course_collaboration_count: rowCount(courseCollaboration.value),
    own_group_status: ownGroup.error ? endpointStatus(ownGroup.error) : (includeGroupCollaboration ? 'ok' : 'skipped'),
    own_group_count: ownGroupValue.length,
    group_collaboration_status: groupCollaborationResult.some((one: any) => one.error && endpointStatus(one.error) === 'error')
      ? 'error'
      : includeGroupCollaboration ? 'ok' : 'skipped',
    group_collaboration_count: groupCollaborationValue.length,
    collaboration_count: collaboration.length,
    member_endpoint_count: memberResult.length,
    member_count: collaboration.reduce((sum: number, one: any) => sum + Number(one.member_count ?? 0), 0),
    group_collaboration_count_returned: collaboration.filter((one: any) => one.context_source === 'group').length,
    course_collaboration_count_returned: collaboration.filter((one: any) => one.context_source === 'course').length,
    collaboration,
    note: 'Collaboration context follows visible course collaborations and current-user own group collaborations only; it does not scan broad potential collaborator rosters.',
  };
}

async function extractCourse(id: string): Promise<unknown> {
  const errors: Record<string, string> = {};
  const [course, modules, assignments, announcements, discussionList, quizList, files, pageStubs] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}`, { 'include[]': 'syllabus_body' })),
    safe(() => canvasPaginate<any>(`/courses/${id}/modules`, { 'include[]': 'items' })),
    safe(() => canvasPaginate<any>(`/courses/${id}/assignments`)),
    safe(() => canvasPaginate<any>(`/announcements`, { 'context_codes[]': `course_${id}` })),
    safe(() => canvasPaginate<any>(`/courses/${id}/discussion_topics`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/quizzes`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/files`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/pages`)),
  ]);
  for (const [k, r] of Object.entries({ course, modules, assignments, announcements, discussions: discussionList, quizzes: quizList, files, pages: pageStubs }))
    if (r.error) errors[k] = r.error;

  const pageUrls = new Set<string>([...((pageStubs.value as any[]) ?? []).map((p) => p.url)]);
  for (const m of (modules.value as any[]) ?? []) for (const it of m.items ?? []) if (it.type === 'Page' && it.page_url) pageUrls.add(it.page_url);
  const pages = await pool([...pageUrls], async (url) => {
    try { return await canvasGet(`/courses/${id}/pages/${url}`); }
    catch (err) { errors[`page:${url}`] = (err as Error).message; return { url, body: null, _missing: true }; }
  });

  const discussions = await pool((discussionList.value as any[]) ?? [], async (d) => {
    try { return await canvasGet(`/courses/${id}/discussion_topics/${d.id}`); }
    catch (err) { errors[`discussion:${d.id}`] = (err as Error).message; return d; }
  });

  const quizIds = new Set<number>([...((quizList.value as any[]) ?? []).map((q) => q.id)]);
  for (const m of (modules.value as any[]) ?? []) for (const it of m.items ?? []) if (it.type === 'Quiz' && it.content_id) quizIds.add(it.content_id);
  const quizzes = await pool([...quizIds], async (qid) => {
    let meta: any = ((quizList.value as any[]) ?? []).find((q) => q.id === qid);
    if (!meta) { const r = await safe(() => canvasGet(`/courses/${id}/quizzes/${qid}`)); if (r.error) { errors[`quiz:${qid}`] = r.error; return { id: qid, _missing: true, questions: [] }; } meta = r.value; }
    const questions = await safe(() => canvasPaginate<any>(`/courses/${id}/quizzes/${qid}/questions`));
    if (questions.error) errors[`quiz:${qid}:questions`] = questions.error;
    return { ...meta, questions: questions.value ?? [] };
  });

  const embeds: any[] = [];
  if ((course.value as any)?.syllabus_body) embeds.push(...extractEmbeds((course.value as any).syllabus_body, { type: 'syllabus', title: (course.value as any).name }));
  for (const p of pages as any[]) embeds.push(...extractEmbeds(p.body, { type: 'page', id: p.url, title: p.title }));
  for (const a of (assignments.value as any[]) ?? []) embeds.push(...extractEmbeds(a.description, { type: 'assignment', id: a.id, title: a.name }));
  for (const d of discussions as any[]) embeds.push(...extractEmbeds(d.message, { type: 'discussion', id: d.id, title: d.title }));
  for (const a of (announcements.value as any[]) ?? []) embeds.push(...extractEmbeds(a.message, { type: 'announcement', id: a.id, title: a.title }));
  for (const q of quizzes as any[]) {
    embeds.push(...extractEmbeds(q.description, { type: 'quiz', id: q.id, title: q.title }));
    for (const qq of q.questions ?? []) embeds.push(...extractEmbeds(qq.question_text, { type: 'quiz-question', id: qq.id, title: q.title }));
  }

  const modulesValue = (modules.value as any[]) ?? [];
  return {
    generatedAt: new Date().toISOString(),
    course: course.value,
    modules: modulesValue,
    pages,
    assignments: assignments.value ?? [],
    discussions,
    quizzes,
    announcements: announcements.value ?? [],
    files: files.value ?? [],
    embeds,
    errors,
    stats: {
      modules: modulesValue.length,
      pages: pages.length,
      assignments: ((assignments.value as any[]) ?? []).length,
      discussions: discussions.length,
      quizzes: quizzes.length,
      announcements: ((announcements.value as any[]) ?? []).length,
      files: ((files.value as any[]) ?? []).length,
      embeds: embeds.length,
      moduleItems: modulesValue.reduce((s, m: any) => s + (m.items?.length ?? 0), 0),
    },
  };
}

function courseParam(args: { enrollment_state?: string; state?: string; include_concluded?: boolean }): Record<string, CanvasParamValue> {
  const include = ['term', 'enrollments', 'total_scores'];
  if (args.include_concluded) include.push('concluded');
  const param: Record<string, CanvasParamValue> = { 'include[]': include };
  if (args.enrollment_state) param.enrollment_state = args.enrollment_state;
  else param.enrollment_state = 'active';
  if (args.state) param['state[]'] = args.state;
  return param;
}

function submissionInclude(args: { include_assignment?: boolean; include_history?: boolean }): string[] {
  const include = [];
  if (args.include_assignment !== false) include.push('assignment');
  if (args.include_history) include.push('submission_history', 'rubric_assessment', 'submission_comments');
  return include;
}

function normalizeParam(param: unknown): Record<string, CanvasParamValue> | undefined {
  if (param === undefined || param === null) return undefined;
  if (Array.isArray(param) || typeof param !== 'object') {
    throw new Error('request_canvas_api param must be an object when provided');
  }
  const out: Record<string, CanvasParamValue> = {};
  for (const [key, value] of Object.entries(param as Record<string, unknown>)) {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      out[key] = value;
      continue;
    }
    if (Array.isArray(value) && value.every((item) => (
      typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean'
    ))) {
      out[key] = value;
      continue;
    }
    throw new Error(`request_canvas_api param "${key}" must be a string, number, boolean, or primitive array`);
  }
  return out;
}

async function requestCanvasApi(args: {
  path: string;
  param?: Record<string, unknown>;
  paginate?: boolean;
}): Promise<unknown> {
  const param = normalizeParam(args.param);
  const response = args.paginate
    ? await canvasApiPaginate<unknown>(args.path, param)
    : await canvasApiGet(args.path, param);
  return {
    generated_at: new Date().toISOString(),
    path: args.path,
    is_paginated: !!args.paginate,
    row_count: rowCount(response),
    response,
  };
}

async function requestCanvasWrite(args: {
  path: string;
  method?: string;
  param?: Record<string, unknown>;
  body?: Record<string, unknown>;
}): Promise<unknown> {
  const allow = ALLOW_WRITES;
  const path = String(args.path ?? '').trim();
  if (!/^\/api\/v1\//.test(path)) {
    return { generated_at: new Date().toISOString(), ok: false, reason: 'write paths begin with /api/v1/' };
  }
  if (!allow) {
    return {
      generated_at: new Date().toISOString(),
      ok: false,
      reason: 'writes are opt-in: set CANVAS_ALLOW_WRITES=1 (env) or pass --allow-writes to enable. Nothing was sent to Canvas.',
    };
  }
  const method = String(args.method ?? 'POST').toUpperCase();
  const url = new URL(String(path), BASE_URL);
  const param = normalizeParam(args.param);
  applyParam(url, param);
  const res = await canvasFetch(url, {
    method,
    headers: { ...canvasHeader('application/json'), 'Content-Type': 'application/json' },
    body: JSON.stringify(args.body ?? {}),
  });
  const body = await res.text();
  let parsed: unknown = body;
  try {
    parsed = JSON.parse(body);
  } catch {
    parsed = body.slice(0, 4000);
  }
  return {
    generated_at: new Date().toISOString(),
    path,
    method,
    ok: res.ok,
    status: res.status,
    response: parsed,
  };
}

function httpStatusFromError(error: string | null): number | null {
  const match = String(error ?? '').match(/Canvas\s+(\d{3})\b/);
  return match ? Number(match[1]) : null;
}

function normalizeStringArray(value: unknown, name: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(`${name} must be an array when provided`);
  return value.map((item) => {
    if (typeof item !== 'string' && typeof item !== 'number') {
      throw new Error(`${name} entries must be strings or numbers`);
    }
    return String(item);
  });
}

function normalizeMaybeStringArray(value: unknown, name: string): string[] {
  if (value === undefined || value === null || value === '') return [];
  if (Array.isArray(value)) return normalizeStringArray(value, name);
  if (typeof value === 'string' || typeof value === 'number') return [String(value)];
  throw new Error(`${name} must be a string, number, or array when provided`);
}

function capabilityTermScore(course: any): number {
  const name = String(course?.term?.name ?? '');
  const year = name.match(/SY\s+(\d{4})\s*-\s*(\d{4})/i);
  if (!year) return -1;
  const start = Number(year[1]);
  const termName = name.toLowerCase();
  const rank = termName.includes('intersession') ? 3 : termName.includes('2nd') ? 2 : termName.includes('1st') ? 1 : 0;
  return start * 10 + rank;
}

async function readCapabilityEndpoint(entry: any, context: Record<string, string | null>): Promise<Record<string, unknown>> {
  const skipReason = entry.skip?.(context);
  if (skipReason) {
    return {
      id: entry.id,
      label: entry.label,
      status: 'skipped',
      reason: skipReason,
      doc_url: entry.doc_url,
    };
  }
  const path = entry.path(context);
  const param = entry.param?.(context) ?? undefined;
  const requestPath = (() => {
    try {
      const url = canvasApiUrl(path, param);
      return `${url.pathname}${url.search}`;
    } catch {
      return path;
    }
  })();
  const result = await safe(async () => (
    entry.paginated === false
      ? await canvasApiGet(path, param)
      : await canvasApiPaginate(path, param)
  ));
  if (result.error) {
    const status = httpStatusFromError(result.error);
    return {
      id: entry.id,
      label: entry.label,
      status: endpointStatus(result.error),
      http_status: status,
      path: requestPath,
      error: result.error,
      doc_url: entry.doc_url,
    };
  }
  return {
    id: entry.id,
    label: entry.label,
    status: 'ok',
    http_status: 200,
    path: requestPath,
    row_count: rowCount(result.value),
    sample_key: keySample(result.value),
    doc_url: entry.doc_url,
  };
}

function capabilityProbeDefinition(): any[] {
  return [
    {
      id: 'planner_item',
      label: 'Planner incomplete item',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/planner',
      path: () => '/api/v1/planner/items',
      param: (ctx: any) => ({
        start_date: ctx.start_date,
        end_date: ctx.end_date,
        'context_codes[]': `course_${ctx.course_id}`,
        filter: 'incomplete_items',
      }),
    },
    {
      id: 'planner_note',
      label: 'Planner note',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/planner',
      path: () => '/api/v1/planner_notes',
      param: (ctx: any) => ({
        start_date: ctx.start_date,
        end_date: ctx.end_date,
        'context_codes[]': `course_${ctx.course_id}`,
      }),
    },
    {
      id: 'planner_override',
      label: 'Planner override',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/planner',
      path: () => '/api/v1/planner/overrides',
    },
    {
      id: 'todo_item',
      label: 'User todo item',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/todo',
      param: () => ({ 'include[]': 'ungraded_quizzes' }),
    },
    {
      id: 'todo_count',
      label: 'User todo count',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/todo_item_count',
      param: () => ({ 'include[]': 'ungraded_quizzes' }),
      paginated: false,
    },
    {
      id: 'missing_submission',
      label: 'User missing submission',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: (ctx: any) => `/api/v1/users/${ctx.user_id}/missing_submissions`,
      param: (ctx: any) => ({
        'course_ids[]': ctx.course_id,
        'include[]': ['planner_overrides', 'course'],
        'filter[]': ['submittable', 'current_grading_period'],
      }),
    },
    {
      id: 'upcoming_event',
      label: 'Upcoming event',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/upcoming_events',
    },
    {
      id: 'user_profile',
      label: 'Current-user profile',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/profile',
      paginated: false,
    },
    {
      id: 'user_login',
      label: 'Current-user login',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/logins',
      path: (ctx: any) => `/api/v1/users/${ctx.user_id}/logins`,
    },
    {
      id: 'user_access_token',
      label: 'Current-user access token',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/access_tokens',
      path: (ctx: any) => `/api/v1/users/${ctx.user_id}/user_generated_tokens`,
    },
    {
      id: 'access_token_detail',
      label: 'Current-user access token detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/access_tokens',
      path: (ctx: any) => `/api/v1/users/${ctx.user_id}/tokens/${ctx.access_token_id}`,
      skip: (ctx: any) => ctx.access_token_id ? null : 'no current-user access token visible for detail',
      paginated: false,
    },
    {
      id: 'favorite_course',
      label: 'Favorite course',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/favorites',
      path: () => '/api/v1/users/self/favorites/courses',
    },
    {
      id: 'course_nickname',
      label: 'Course nickname',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: (ctx: any) => `/api/v1/users/self/course_nicknames/${ctx.course_id}`,
      paginated: false,
    },
    {
      id: 'dashboard_card',
      label: 'Dashboard card',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/dashboard/dashboard_cards',
    },
    {
      id: 'custom_color',
      label: 'Current-user custom color map',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/colors',
      paginated: false,
    },
    {
      id: 'selected_custom_color',
      label: 'Selected course custom color',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: (ctx: any) => `/api/v1/users/self/colors/course_${ctx.course_id}`,
      paginated: false,
    },
    {
      id: 'dashboard_position',
      label: 'Current-user dashboard position',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
    path: () => '/api/v1/users/self/dashboard_positions',
    paginated: false,
  },
  {
    id: 'account_calendar',
    label: 'Visible account calendar',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_calendars',
    path: () => '/api/v1/account_calendars',
    paginated: false,
  },
  {
    id: 'account_calendar_detail',
    label: 'Account calendar detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_calendars',
    path: (ctx: any) => `/api/v1/account_calendars/${ctx.account_calendar_id}`,
    skip: (ctx: any) => ctx.account_calendar_id ? null : 'no account calendar id visible for selected course/account',
    paginated: false,
  },
  {
    id: 'account_calendar_admin',
    label: 'Account calendar admin list',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_calendars',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/account_calendars`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'visible_calendar_count',
    label: 'Visible account calendar count',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_calendars',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/visible_calendars_count`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'blueprint_template',
    label: 'Blueprint template',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_templates/default`,
    paginated: false,
  },
  {
    id: 'blueprint_associated_course',
    label: 'Blueprint associated course',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_templates/default/associated_courses`,
  },
  {
    id: 'blueprint_unsynced_change',
    label: 'Blueprint unsynced change',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_templates/default/unsynced_changes`,
  },
  {
    id: 'blueprint_migration',
    label: 'Blueprint migration',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_templates/default/migrations`,
  },
  {
    id: 'blueprint_migration_detail',
    label: 'Blueprint migration detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_templates/default/migrations/${ctx.blueprint_migration_id}`,
    skip: (ctx: any) => ctx.blueprint_migration_id ? null : 'no blueprint migration id visible for selected course',
    paginated: false,
  },
  {
    id: 'blueprint_migration_change',
    label: 'Blueprint migration change',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_templates/default/migrations/${ctx.blueprint_migration_id}/details`,
    skip: (ctx: any) => ctx.blueprint_migration_id ? null : 'no blueprint migration id visible for selected course',
  },
  {
    id: 'blueprint_subscription',
    label: 'Blueprint subscription',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_subscriptions`,
  },
  {
    id: 'blueprint_import',
    label: 'Blueprint import',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_subscriptions/default/migrations`,
  },
  {
    id: 'blueprint_import_detail',
    label: 'Blueprint import detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_subscriptions/default/migrations/${ctx.blueprint_migration_id}`,
    skip: (ctx: any) => ctx.blueprint_migration_id ? null : 'no blueprint import id visible for selected course',
    paginated: false,
  },
  {
    id: 'blueprint_import_change',
    label: 'Blueprint import change',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blueprint_courses',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blueprint_subscriptions/default/migrations/${ctx.blueprint_migration_id}/details`,
    skip: (ctx: any) => ctx.blueprint_migration_id ? null : 'no blueprint import id visible for selected course',
  },
  {
    id: 'account_grading_period_set',
    label: 'Account grading period set',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grading_period_sets',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/grading_period_sets`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'account_grading_period',
    label: 'Account grading period',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grading_periods',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/grading_periods`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'course_grading_period',
    label: 'Course grading period',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grading_periods',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/grading_periods`,
    paginated: false,
  },
  {
    id: 'course_grading_period_detail',
    label: 'Course grading period detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grading_periods',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/grading_periods/${ctx.grading_period_id}`,
    skip: (ctx: any) => ctx.grading_period_id ? null : 'no course grading period id visible for selected course',
    paginated: false,
  },
  {
    id: 'graded_submission',
    label: 'Current-user recent graded submission',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/graded_submissions',
      param: () => ({ 'include[]': 'assignment' }),
    },
    {
      id: 'page_view',
      label: 'Current-user page view',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/page_views',
      param: (ctx: any) => ({
        start_time: ctx.page_view_start_time,
        end_time: ctx.page_view_end_time,
        per_page: 25,
      }),
      paginated: false,
    },
    {
      id: 'bookmark',
      label: 'Current-user bookmark',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/bookmarks',
      path: () => '/api/v1/users/self/bookmarks',
    },
    {
      id: 'eportfolio',
      label: 'Current-user ePortfolio',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/e_portfolios',
      path: (ctx: any) => `/api/v1/users/${ctx.user_id}/eportfolios`,
    },
    {
      id: 'eportfolio_page',
      label: 'ePortfolio page',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/e_portfolios',
      path: (ctx: any) => `/api/v1/eportfolios/${ctx.eportfolio_id}/pages`,
      skip: (ctx: any) => ctx.eportfolio_id ? null : 'no ePortfolio visible for current user',
    },
    {
      id: 'content_share_sent',
      label: 'Current-user sent content share',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_shares',
      path: () => '/api/v1/users/self/content_shares/sent',
    },
    {
      id: 'content_share_received',
      label: 'Current-user received content share',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_shares',
      path: () => '/api/v1/users/self/content_shares/received',
    },
    {
      id: 'content_share_unread_count',
      label: 'Current-user content share unread count',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_shares',
      path: () => '/api/v1/users/self/content_shares/unread_count',
      paginated: false,
    },
    {
      id: 'content_share_detail',
      label: 'Current-user content share detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_shares',
      path: (ctx: any) => `/api/v1/users/self/content_shares/${ctx.content_share_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.content_share_id ? null : 'no sent or received content share visible for current user',
    },
  {
    id: 'observee',
    label: 'Linked observee',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/user_observees',
    path: () => '/api/v1/users/self/observees',
  },
  {
    id: 'communication_channel',
    label: 'Current-user communication channel',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/communication_channels',
    path: () => '/api/v1/users/self/communication_channels',
  },
  {
    id: 'comm_message',
    label: 'Current-user CommMessage',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/comm_messages',
    path: () => '/api/v1/comm_messages',
    param: (ctx: any) => ({
      user_id: ctx.user_id,
      start_time: ctx.page_view_start_time,
      end_time: ctx.page_view_end_time,
    }),
  },
  {
    id: 'account_notification',
    label: 'Account notification',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_notifications',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/account_notifications`,
    param: () => ({ show_is_closed: true }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'account_notification_detail',
    label: 'Account notification detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_notifications',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/account_notifications/${ctx.account_notification_id}`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.account_notification_id) return 'no account notification visible for selected account';
      return null;
    },
    paginated: false,
  },
  {
    id: 'account_domain',
    label: 'Account domain lookup',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_domain_lookups',
    path: () => '/api/v1/accounts/search',
    param: (ctx: any) => ({ domain: ctx.account_domain }),
    skip: (ctx: any) => ctx.account_domain ? null : 'no account domain available for lookup',
    paginated: false,
  },
  {
    id: 'account_detail',
    label: 'Account detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'account_setting',
    label: 'Account setting',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/settings`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'account_permission',
    label: 'Account permission',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/permissions`,
    param: () => ({
      'permissions[]': [
        'read_reports',
        'manage_account_settings',
        'manage_courses',
        'manage_sis',
        'manage_account_memberships',
        'become_user',
      ],
    }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'sub_account',
    label: 'Sub-account',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/sub_accounts`,
    param: () => ({ 'include[]': ['course_count', 'sub_account_count'] }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'account_help_link',
    label: 'Account help link',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/help_links`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'account_report',
    label: 'Account report',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/account_reports',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/reports`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'role',
    label: 'Account role',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/roles',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/roles`,
    param: () => ({ 'state[]': ['active', 'inactive'] }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'role_detail',
    label: 'Account role detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/roles',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/roles/${ctx.role_id}`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.role_id) return 'no role visible for selected account';
      return null;
    },
    paginated: false,
  },
  {
    id: 'account_admin',
    label: 'Account admin',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/admins',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/admins`,
    param: () => ({ include_deleted: false }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'self_admin_role',
    label: 'Current-user admin role',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/admins',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/admins/self`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'account_login',
    label: 'Account login',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/logins',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/logins`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'authentication_event',
    label: 'Authentication event audit',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/authentications_log',
    path: (ctx: any) => `/api/v1/audit/authentication/accounts/${ctx.account_id}`,
    param: () => ({
      start_time: dateOffset(new Date(), -30),
      end_time: dateOffset(new Date(), 0),
    }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'sis_import',
    label: 'SIS import',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sis_imports',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/sis_imports`,
    param: (ctx: any) => ({
      created_since: ctx.page_view_start_time,
      created_before: ctx.page_view_end_time,
    }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'importing_sis_import',
    label: 'Importing SIS import',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sis_imports',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/sis_imports/importing`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'sis_import_detail',
    label: 'SIS import detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sis_imports',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/sis_imports/${ctx.sis_import_id}`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.sis_import_id) return 'no SIS import visible for selected account';
      return null;
    },
    paginated: false,
  },
  {
    id: 'sis_import_error',
    label: 'SIS import error',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sis_import_errors',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/sis_import_errors`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'selected_sis_import_error',
    label: 'Selected SIS import error',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sis_import_errors',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/sis_imports/${ctx.sis_import_id}/errors`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.sis_import_id) return 'no SIS import visible for selected account';
      return null;
    },
  },
  {
    id: 'role_permission',
    label: 'Assignable role permission',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/roles',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/roles/permissions`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'permission_help',
    label: 'Role permission help',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/roles',
    path: () => '/api/v1/permissions/account/read_reports/help',
    paginated: false,
  },
  {
    id: 'course_creation_account',
    label: 'Course creation account',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: () => '/api/v1/course_creation_accounts',
  },
  {
    id: 'course_admin_account',
    label: 'Course admin account',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: () => '/api/v1/course_accounts',
  },
  {
    id: 'manual_course_account',
    label: 'Manual course account',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/accounts',
    path: () => '/api/v1/manually_created_courses_account',
    paginated: false,
  },
  {
    id: 'temporary_enrollment_pairing',
    label: 'Temporary enrollment pairing',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/temporary_enrollment_pairings',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/temporary_enrollment_pairings`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'temporary_enrollment_pairing_detail',
    label: 'Temporary enrollment pairing detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/temporary_enrollment_pairings',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/temporary_enrollment_pairings/${ctx.temporary_enrollment_pairing_id}`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.temporary_enrollment_pairing_id) return 'no temporary enrollment pairing visible for selected account';
      return null;
    },
    paginated: false,
  },
  {
    id: 'new_temporary_enrollment_pairing',
    label: 'New temporary enrollment pairing initializer',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/temporary_enrollment_pairings',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/temporary_enrollment_pairings/new`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'api_scope',
    label: 'API token scope catalog',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/api_token_scopes',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/scopes`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'auth_provider',
    label: 'Authentication provider',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/authentication_providers',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/authentication_providers`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
  },
  {
    id: 'auth_provider_detail',
    label: 'Authentication provider detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/authentication_providers',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/authentication_providers/${ctx.auth_provider_id}`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.auth_provider_id) return 'no authentication provider visible for selected account';
      return null;
    },
    paginated: false,
  },
  {
    id: 'root_brand_variable',
    label: 'Root Brand Config variable',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/brand_configs',
    path: () => '/api/v1/brand_variables',
    paginated: false,
  },
  {
    id: 'account_brand_variable',
    label: 'Account Brand Config variable',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/brand_configs',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/brand_variables`,
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'course_brand_variable',
    label: 'Course Brand Config variable',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/brand_configs',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/brand_variables`,
    paginated: false,
  },
  {
    id: 'account_enrollment_term',
    label: 'Account enrollment term',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/enrollment_terms',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/terms`,
    param: () => ({
      'workflow_state[]': 'active',
      'include[]': ['overrides', 'course_count'],
    }),
    skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
    paginated: false,
  },
  {
    id: 'account_enrollment_term_detail',
    label: 'Account enrollment term detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/enrollment_terms',
    path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/terms/${ctx.enrollment_term_id}`,
    skip: (ctx: any) => {
      if (!ctx.account_id) return 'no account id visible for selected course';
      if (!ctx.enrollment_term_id) return 'no enrollment term visible for selected course';
      return null;
    },
    paginated: false,
  },
  {
    id: 'notification_preference',
    label: 'Communication channel notification preference',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/notification_preferences',
    path: (ctx: any) => `/api/v1/users/self/communication_channels/${ctx.communication_channel_id}/notification_preferences`,
    skip: (ctx: any) => ctx.communication_channel_id ? null : 'no communication channel visible for current user',
    paginated: false,
  },
  {
    id: 'notification_preference_category',
    label: 'Communication channel notification preference category',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/notification_preferences',
    path: (ctx: any) => `/api/v1/users/self/communication_channels/${ctx.communication_channel_id}/notification_preference_categories`,
    skip: (ctx: any) => ctx.communication_channel_id ? null : 'no communication channel visible for current user',
    paginated: false,
  },
  {
    id: 'calendar_event',
    label: 'Calendar assignment/event',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/calendar_events',
      path: () => '/api/v1/users/self/calendar_events',
      param: (ctx: any) => ({
        type: 'assignment',
        start_date: ctx.start_date,
        end_date: ctx.end_date,
        'context_codes[]': `course_${ctx.course_id}`,
      }),
    },
    {
      id: 'course_calendar_event',
      label: 'Course calendar event',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/calendar_events',
      path: () => '/api/v1/calendar_events',
      param: (ctx: any) => ({
        type: 'event',
        start_date: ctx.start_date,
        end_date: ctx.end_date,
        'context_codes[]': `course_${ctx.course_id}`,
        'includes[]': ['web_conference', 'series_natural_language'],
      }),
    },
    {
      id: 'calendar_event_detail',
      label: 'Calendar event detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/calendar_events',
      path: (ctx: any) => `/api/v1/calendar_events/${ctx.calendar_event_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.calendar_event_id ? null : 'no calendar event visible in selected course',
    },
    {
      id: 'course_timetable',
      label: 'Course timetable',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/calendar_events',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/calendar_events/timetable`,
      paginated: false,
    },
    {
      id: 'course_effective_due_date',
      label: 'Course effective due date',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/effective_due_dates`,
      param: (ctx: any) => ({ 'assignment_ids[]': ctx.assignment_id }),
      paginated: false,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'course_todo',
      label: 'Course todo',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/todo`,
    },
    {
      id: 'course_setting',
      label: 'Course setting',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/settings`,
      paginated: false,
    },
    {
      id: 'course_permission',
      label: 'Course permission',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/permissions`,
      param: () => ({
        'permissions[]': ['read_grades', 'view_all_grades', 'manage_assignments', 'manage_grades', 'manage_files', 'read_as_admin'],
      }),
      paginated: false,
    },
    {
      id: 'late_policy',
      label: 'Course late policy',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/late_policy',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/late_policy`,
      paginated: false,
    },
    {
      id: 'course_csp_setting',
      label: 'Course Content Security Policy setting',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_security_policy_settings',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/csp_settings`,
      paginated: false,
    },
    {
      id: 'account_csp_setting',
      label: 'Account Content Security Policy setting',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_security_policy_settings',
      path: (ctx: any) => `/api/v1/accounts/${ctx.account_id}/csp_settings`,
      skip: (ctx: any) => ctx.account_id ? null : 'no account id visible for selected course',
      paginated: false,
    },
    {
      id: 'course_feature',
      label: 'Course feature flag',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/feature_flags',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/features`,
    },
    {
      id: 'course_enabled_feature',
      label: 'Course enabled feature flag',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/feature_flags',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/features/enabled`,
    },
    {
      id: 'user_feature',
      label: 'Current-user feature flag',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/feature_flags',
      path: () => '/api/v1/users/self/features',
    },
    {
      id: 'user_enabled_feature',
      label: 'Current-user enabled feature flag',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/feature_flags',
      path: () => '/api/v1/users/self/features/enabled',
    },
    {
      id: 'environment_feature',
      label: 'Environment feature flag',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/feature_flags',
      path: () => '/api/v1/features/environment',
      paginated: false,
    },
    {
      id: 'course_announcement',
      label: 'Course announcement',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/announcements',
      path: () => '/api/v1/announcements',
      param: (ctx: any) => ({
        'context_codes[]': `course_${ctx.course_id}`,
        start_date: ctx.start_date,
        end_date: ctx.end_date,
      }),
    },
    {
      id: 'course_external_feed',
      label: 'Course announcement external feed',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/announcement_external_feeds',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/external_feeds`,
    },
    {
      id: 'group_external_feed',
      label: 'Own-group announcement external feed',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/announcement_external_feeds',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/external_feeds`,
      skip: (ctx: any) => ctx.group_id ? null : 'no current-user own group visible in selected course',
    },
    {
      id: 'enrollment_grade',
      label: 'Enrollment grade',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/enrollments',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/enrollments`,
      param: (ctx: any) => ({ user_id: ctx.user_id, 'include[]': 'current_points' }),
    },
    {
      id: 'course_term_section',
      label: 'Course term/section include',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}`,
      param: () => ({
        'include[]': ['term', 'sections', 'grading_periods', 'current_grading_period_scores', 'total_scores', 'concluded'],
      }),
      paginated: false,
    },
    {
      id: 'course_syllabus',
      label: 'Course syllabus body',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}`,
      param: () => ({
        'include[]': ['syllabus_body', 'term', 'sections', 'public_description', 'course_progress', 'teachers', 'concluded'],
      }),
      paginated: false,
    },
    {
      id: 'course_preference',
      label: 'Course preference/progress include',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}`,
      param: () => ({
        'include[]': ['term', 'sections', 'course_progress', 'tabs', 'favorites', 'teachers', 'course_image', 'banner_image', 'concluded', 'total_scores'],
      }),
      paginated: false,
    },
    {
      id: 'course_section',
      label: 'Course section',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sections',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/sections`,
      param: () => ({ 'include[]': ['total_students', 'passback_status'] }),
    },
    {
      id: 'section_detail',
      label: 'Section detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sections',
      path: (ctx: any) => `/api/v1/sections/${ctx.section_id}`,
      param: () => ({ 'include[]': ['total_students', 'passback_status', 'permissions'] }),
      paginated: false,
      skip: (ctx: any) => ctx.section_id ? null : 'no section visible for selected course',
    },
    {
      id: 'section_user',
      label: 'Section user',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/sections',
      path: (ctx: any) => `/api/v1/sections/${ctx.section_id}/users`,
      param: () => ({ exclude_inactive: true, enrollment_type: 'student' }),
      skip: (ctx: any) => ctx.section_id ? null : 'no section visible for selected course',
    },
    {
      id: 'course_user',
      label: 'Course user roster',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/users`,
      param: () => ({
        'include[]': ['enrollments', 'locked'],
        'enrollment_state[]': ['active', 'invited'],
      }),
    },
    {
      id: 'course_user_self',
      label: 'Current user in course roster',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/users/${ctx.user_id}`,
      param: () => ({ 'include[]': ['enrollments', 'locked'] }),
      paginated: false,
      skip: (ctx: any) => ctx.user_id ? null : 'users/self unavailable',
    },
    {
      id: 'lti_course_name_role',
      label: 'LTI Names and Role course membership',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/names_and_role',
      path: (ctx: any) => `/api/lti/courses/${ctx.course_id}/names_and_roles`,
      paginated: false,
    },
    {
      id: 'assignment_group',
      label: 'Assignment group and weight',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/assignment_groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignment_groups`,
    },
    {
      id: 'grading_standard',
      label: 'Course grading standard',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grading_standards',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/grading_standards`,
    },
    {
      id: 'gradebook_history_day',
      label: 'Gradebook history day',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/gradebook_history',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/gradebook_history/days`,
    },
    {
      id: 'gradebook_history_feed',
      label: 'Current-user gradebook history feed',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/gradebook_history',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/gradebook_history/feed`,
      param: (ctx: any) => ({
        user_id: ctx.user_id,
        assignment_id: ctx.assignment_id,
      }),
    },
    {
      id: 'course_grade_change_event',
      label: 'Course grade-change audit event',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grade_change_log',
      path: (ctx: any) => `/api/v1/audit/grade_change/courses/${ctx.course_id}`,
      param: () => ({
        start_time: dateOffset(new Date(), -30),
        end_time: dateOffset(new Date(), 0),
      }),
      paginated: false,
    },
    {
      id: 'assignment_grade_change_event',
      label: 'Assignment grade-change audit event',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/grade_change_log',
      path: (ctx: any) => `/api/v1/audit/grade_change/assignments/${ctx.assignment_id}`,
      param: () => ({
        start_time: dateOffset(new Date(), -30),
        end_time: dateOffset(new Date(), 0),
      }),
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
      paginated: false,
    },
    {
      id: 'custom_gradebook_column',
      label: 'Custom gradebook column',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/custom_gradebook_columns',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/custom_gradebook_columns`,
    },
    {
      id: 'custom_gradebook_column_datum',
      label: 'Custom gradebook column data',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/custom_gradebook_columns',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/custom_gradebook_columns/${ctx.custom_gradebook_column_id}/data`,
      skip: (ctx: any) => ctx.custom_gradebook_column_id ? null : 'no custom gradebook column visible in selected course',
    },
    {
      id: 'learning_object_date',
      label: 'Learning-object date detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/learning_object_dates',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/date_details`,
      param: () => ({ 'include[]': 'peer_review' }),
      paginated: false,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'moderated_student',
      label: 'Moderated grading student',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/moderated_grading',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/moderated_students`,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'provisional_grade_status',
      label: 'Provisional grade status',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/moderated_grading',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/provisional_grades/status`,
      param: (ctx: any) => ({ student_id: ctx.user_id }),
      paginated: false,
      skip: (ctx: any) => {
        if (!ctx.assignment_id) return 'no assignment visible in selected course';
        if (!ctx.user_id) return 'users/self unavailable';
        return null;
      },
    },
    {
      id: 'anonymous_provisional_grade_status',
      label: 'Anonymous provisional grade status',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/moderated_grading',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/anonymous_provisional_grades/status`,
      param: (ctx: any) => ({ anonymous_id: ctx.anonymous_id }),
      paginated: false,
      skip: (ctx: any) => {
        if (!ctx.assignment_id) return 'no assignment visible in selected course';
        if (!ctx.anonymous_id) return 'no anonymous grading id visible for selected assignment';
        return null;
      },
    },
    {
      id: 'assignment_override',
      label: 'Assignment due-date override',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/assignments',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/overrides`,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'rubric_assessment_read_state',
      label: 'Submission rubric assessment read state',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/submissions',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/submissions/self/rubric_assessments/read`,
      paginated: false,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'document_annotation_read_state',
      label: 'Submission document annotation read state',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/submissions',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/submissions/self/document_annotations/read`,
      paginated: false,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'originality_report',
      label: 'Submitted file originality report',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/originality_reports',
      path: (ctx: any) => `/api/lti/assignments/${ctx.assignment_id}/files/${ctx.submission_file_id}/originality_report`,
      paginated: false,
      skip: (ctx: any) => {
        if (!ctx.assignment_id) return 'no assignment visible in selected course';
        if (!ctx.submission_file_id) return 'no submitted file attachment visible for selected assignment';
        return null;
      },
    },
    {
      id: 'peer_review',
      label: 'Peer review allocation',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/peer_reviews',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/peer_reviews`,
      param: () => ({ 'include[]': ['submission_comments', 'user'] }),
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'assignment_group_member',
      label: 'Assignment group member for current user',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/assignments',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/assignments/${ctx.assignment_id}/users/${ctx.user_id}/group_members`,
      skip: (ctx: any) => {
        if (!ctx.assignment_id) return 'no assignment visible in selected course';
        if (!ctx.user_id) return 'users/self unavailable';
        return null;
      },
    },
    {
      id: 'self_group',
      label: 'Current-user group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: () => '/api/v1/users/self/groups',
      param: () => ({ context_type: 'Course', 'include[]': 'tabs' }),
    },
    {
      id: 'course_group',
      label: 'Course own group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/groups`,
      param: () => ({ only_own_groups: true, 'include[]': 'tabs' }),
    },
    {
      id: 'group_category',
      label: 'Group category',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/group_categories',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/group_categories`,
      param: () => ({ collaboration_state: 'all' }),
    },
    {
      id: 'group_category_group',
      label: 'Group category group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/group_categories',
      path: (ctx: any) => `/api/v1/group_categories/${ctx.group_category_id}/groups`,
      skip: (ctx: any) => ctx.group_category_id ? null : 'no group category visible in selected course',
    },
    {
      id: 'group_category_user',
      label: 'Group category user',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/group_categories',
      path: (ctx: any) => `/api/v1/group_categories/${ctx.group_category_id}/users`,
      skip: (ctx: any) => ctx.group_category_id ? null : 'no group category visible in selected course',
    },
    {
      id: 'lti_group_name_role',
      label: 'LTI Names and Role group membership',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/names_and_role',
      path: (ctx: any) => `/api/lti/groups/${ctx.group_id}/names_and_roles`,
      paginated: false,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_detail',
      label: 'Own group detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}`,
      param: () => ({ 'include[]': 'permissions' }),
      paginated: false,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_member',
      label: 'Own group member',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/users`,
      param: () => ({ 'include[]': 'avatar_url' }),
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_tab',
      label: 'Own group tab',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/tabs',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/tabs`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_permission',
      label: 'Own group permission',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/permissions`,
      param: () => ({ 'permissions[]': ['read_roster', 'send_messages_all', 'create_discussion_topic', 'create_announcement'] }),
      paginated: false,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_membership',
      label: 'Own group membership',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/memberships`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_self_membership',
      label: 'Own group current-user membership',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/users/self`,
      paginated: false,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_file',
      label: 'Own group file',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/files`,
      param: () => ({ 'include[]': 'usage_rights' }),
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_folder',
      label: 'Own group folder',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/folders`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_page',
      label: 'Own group page',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/pages',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/pages`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_discussion',
      label: 'Own group discussion',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/discussion_topics',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/discussion_topics`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_activity_summary',
      label: 'Own group activity summary',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/activity_stream/summary`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'group_activity',
      label: 'Own group activity stream',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/groups',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/activity_stream`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'course_media_attachment',
      label: 'Course media attachment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/media_objects',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/media_attachments`,
      param: () => ({ sort: 'title' }),
    },
    {
      id: 'group_media_attachment',
      label: 'Own group media attachment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/media_objects',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/media_attachments`,
      param: () => ({ sort: 'title' }),
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'kaltura_config',
      label: 'Kaltura config',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/services',
      path: () => '/api/v1/services/kaltura',
      paginated: false,
    },
    {
      id: 'user_conference',
      label: 'Current-user conference',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/conferences',
      path: () => '/api/v1/conferences',
      paginated: false,
    },
    {
      id: 'course_conference',
      label: 'Course conference',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/conferences',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/conferences`,
      paginated: false,
    },
    {
      id: 'group_conference',
      label: 'Own group conference',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/conferences',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/conferences`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
      paginated: false,
    },
    {
      id: 'course_content_export',
      label: 'Course content export',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_exports',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_exports`,
    },
    {
      id: 'user_content_export',
      label: 'Current-user content export',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_exports',
      path: () => '/api/v1/users/self/content_exports',
    },
    {
      id: 'group_content_export',
      label: 'Own group content export',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_exports',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/content_exports`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'epub_export',
      label: 'Current-user ePub export',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/e_pub_exports',
      path: () => '/api/v1/epub_exports',
      paginated: false,
    },
    {
      id: 'course_report_last',
      label: 'Course report last status',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/course_reports',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/reports/${ctx.course_report_type}`,
      skip: (ctx: any) => ctx.course_report_type ? null : 'no course_report_type provided',
      paginated: false,
    },
    {
      id: 'course_report_detail',
      label: 'Course report status',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/course_reports',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/reports/${ctx.course_report_type}/${ctx.course_report_id}`,
      skip: (ctx: any) => {
        if (!ctx.course_report_type) return 'no course_report_type provided';
        if (!ctx.course_report_id) return 'no course_report_id provided';
        return null;
      },
      paginated: false,
    },
    {
      id: 'content_migration',
      label: 'Course content migration',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations`,
    },
    {
      id: 'content_migration_detail',
      label: 'Course content migration detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations/${ctx.content_migration_id}`,
      skip: (ctx: any) => ctx.content_migration_id ? null : 'no content migration visible in selected course',
      paginated: false,
    },
    {
      id: 'migration_issue',
      label: 'Content migration issue',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations/${ctx.content_migration_id}/migration_issues`,
      skip: (ctx: any) => ctx.content_migration_id ? null : 'no content migration visible in selected course',
    },
    {
      id: 'migration_issue_detail',
      label: 'Content migration issue detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations/${ctx.content_migration_id}/migration_issues/${ctx.migration_issue_id}`,
      skip: (ctx: any) => {
        if (!ctx.content_migration_id) return 'no content migration visible in selected course';
        if (!ctx.migration_issue_id) return 'no migration issue visible for selected migration';
        return null;
      },
      paginated: false,
    },
    {
      id: 'migration_migrator',
      label: 'Content migration system',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations/migrators`,
    },
    {
      id: 'migration_selective_data',
      label: 'Content migration selective data',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations/${ctx.content_migration_id}/selective_data`,
      skip: (ctx: any) => ctx.content_migration_id ? null : 'no content migration visible in selected course',
      paginated: false,
    },
    {
      id: 'migration_asset_id_mapping',
      label: 'Content migration asset id mapping',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/content_migrations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_migrations/${ctx.content_migration_id}/asset_id_mapping`,
      skip: (ctx: any) => ctx.content_migration_id ? null : 'no content migration visible in selected course',
      paginated: false,
    },
    {
      id: 'progress',
      label: 'Canvas async progress',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/progress',
      path: (ctx: any) => `/api/v1/progress/${ctx.progress_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.progress_id ? null : 'no progress_url visible from export/report context',
    },
    {
      id: 'lti_progress',
      label: 'LTI async progress',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/progress',
      path: (ctx: any) => `/api/lti/courses/${ctx.course_id}/progress/${ctx.lti_progress_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.lti_progress_id ? null : 'no LTI progress id visible from export/report context',
    },
    {
      id: 'course_blackout_date',
      label: 'Course blackout date',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/blackout_dates',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/blackout_dates`,
    },
  {
    id: 'course_pace',
    label: 'Course pace detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/course_pace',
    path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/course_pacing/${ctx.course_pace_id}`,
    skip: (ctx: any) => ctx.course_pace_id ? null : 'no course_pace_id provided',
    paginated: false,
  },
  {
    id: 'poll',
    label: 'Current-user poll',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/polls',
    path: () => '/api/v1/polls',
    paginated: false,
  },
  {
    id: 'poll_choice',
    label: 'Poll choice',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/poll_choices',
    path: (ctx: any) => `/api/v1/polls/${ctx.poll_id}/poll_choices`,
    skip: (ctx: any) => ctx.poll_id ? null : 'no poll visible to current user',
  },
  {
    id: 'opened_poll_session',
    label: 'Opened poll session',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/poll_sessions',
    path: () => '/api/v1/poll_sessions/opened',
    paginated: false,
  },
  {
    id: 'closed_poll_session',
    label: 'Closed poll session',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/poll_sessions',
    path: () => '/api/v1/poll_sessions/closed',
    paginated: false,
  },
  {
    id: 'poll_submission_detail',
    label: 'Poll submission detail',
    doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/poll_submissions',
    path: (ctx: any) => `/api/v1/polls/${ctx.poll_id}/poll_sessions/${ctx.poll_session_id}/poll_submissions/${ctx.poll_submission_id}`,
    skip: (ctx: any) => ctx.poll_id && ctx.poll_session_id && ctx.poll_submission_id ? null : 'no poll submission visible to current user',
    paginated: false,
  },
  {
    id: 'course_collaboration',
    label: 'Course collaboration',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/collaborations',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/collaborations`,
    },
    {
      id: 'group_collaboration',
      label: 'Own group collaboration',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/collaborations',
      path: (ctx: any) => `/api/v1/groups/${ctx.group_id}/collaborations`,
      skip: (ctx: any) => ctx.group_id ? null : 'no own group visible in selected course',
    },
    {
      id: 'collaboration_member',
      label: 'Collaboration member',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/collaborations',
      path: (ctx: any) => `/api/v1/collaborations/${ctx.collaboration_id}/members`,
      skip: (ctx: any) => ctx.collaboration_id ? null : 'no collaboration visible in selected course or own group',
    },
    {
      id: 'course_tab',
      label: 'Course navigation tab',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/tabs',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/tabs`,
    },
    {
      id: 'course_external_tool',
      label: 'Course external tool',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/external_tools',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/external_tools`,
      param: () => ({ include_parents: true }),
    },
    {
      id: 'external_tool_detail',
      label: 'Course external tool detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/external_tools',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/external_tools/${ctx.external_tool_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.external_tool_id ? null : 'no external tool visible in selected course',
    },
    {
      id: 'external_tool_sessionless_launch',
      label: 'External tool sessionless launch URL',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/external_tools',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/external_tools/sessionless_launch`,
      param: (ctx: any) => ({
        launch_type: 'module_item',
        module_item_id: ctx.external_module_item_id,
      }),
      paginated: false,
      skip: (ctx: any) => ctx.external_module_item_id ? null : 'no external-tool module item visible in selected course',
    },
    {
      id: 'course_module',
      label: 'Course module with item detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/modules',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/modules`,
      param: (ctx: any) => ({
        'include[]': ['items', 'content_details'],
        ...(ctx.user_id ? { student_id: ctx.user_id } : {}),
      }),
    },
    {
      id: 'module_item',
      label: 'Module item list',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/modules',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/modules/${ctx.module_id}/items`,
      param: () => ({ 'include[]': 'content_details' }),
      skip: (ctx: any) => ctx.module_id ? null : 'no module visible in selected course',
    },
    {
      id: 'module_item_sequence',
      label: 'Module item sequence',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/modules',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/module_item_sequence`,
      param: (ctx: any) => ({
        asset_type: 'ModuleItem',
        asset_id: ctx.module_item_id,
      }),
      paginated: false,
      skip: (ctx: any) => ctx.module_item_id ? null : 'no module item visible in selected course',
    },
    {
      id: 'module_assignment_override',
      label: 'Module assignment override',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/modules',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/modules/${ctx.module_id}/assignment_overrides`,
      skip: (ctx: any) => ctx.module_id ? null : 'no module visible in selected course',
    },
    {
      id: 'user_file',
      label: 'Current-user file library',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: () => '/api/v1/users/self/files',
      param: () => ({ 'include[]': ['user', 'usage_rights'] }),
    },
    {
      id: 'user_folder',
      label: 'Current-user folder library',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: () => '/api/v1/users/self/folders',
    },
    {
      id: 'user_root_folder',
      label: 'Current-user root folder',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: () => '/api/v1/users/self/folders/root',
      paginated: false,
    },
    {
      id: 'user_file_quota',
      label: 'Current-user file quota',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: () => '/api/v1/users/self/files/quota',
      paginated: false,
    },
    {
      id: 'course_file',
      label: 'Course file library',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/files`,
      param: () => ({ 'include[]': ['user', 'usage_rights'] }),
    },
    {
      id: 'course_file_detail',
      label: 'Course file detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/files/${ctx.course_file_id}`,
      param: () => ({ 'include[]': ['user', 'usage_rights'] }),
      paginated: false,
      skip: (ctx: any) => ctx.course_file_id ? null : 'no course file visible in selected course',
    },
    {
      id: 'file_public_url',
      label: 'File public inline preview URL',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/files/${ctx.course_file_id}/public_url`,
      paginated: false,
      skip: (ctx: any) => ctx.course_file_id ? null : 'no course file visible in selected course',
    },
    {
      id: 'file_icon_metadata',
      label: 'File icon metadata',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/files/${ctx.course_file_id}/icon_metadata`,
      paginated: false,
      skip: (ctx: any) => ctx.course_file_id ? null : 'no course file visible in selected course',
    },
    {
      id: 'course_folder',
      label: 'Course folder library',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/folders`,
    },
    {
      id: 'course_page',
      label: 'Course wiki page index',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/pages',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/pages`,
    },
    {
      id: 'smart_search',
      label: 'Course Smart Search',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/smart_search',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/smartsearch`,
      param: () => ({
        q: 'assignment',
        'filter[]': ['pages', 'assignments', 'announcements', 'discussion_topics'],
        'include[]': ['status', 'modules'],
      }),
      paginated: false,
    },
    {
      id: 'search_recipient',
      label: 'Search recipient context',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/search',
      path: () => '/api/v1/search/recipients',
      param: (ctx: any) => ({
        search: ctx.course_code ?? String(ctx.course_id),
        context: `course_${ctx.course_id}`,
        type: 'context',
        'permissions[]': 'send_messages',
      }),
    },
    {
      id: 'public_course_search',
      label: 'Public course search',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/search',
      path: () => '/api/v1/search/all_courses',
      param: (ctx: any) => ({
        search: ctx.course_code ?? String(ctx.course_id),
        public_only: true,
      }),
    },
    {
      id: 'course_front_page',
      label: 'Course front page',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/pages',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/front_page`,
      paginated: false,
    },
    {
      id: 'root_folder',
      label: 'Course root folder',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/folders/root`,
      paginated: false,
    },
    {
      id: 'content_license',
      label: 'Course file content license',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/files',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/content_licenses`,
    },
    {
      id: 'rubric',
      label: 'Rubric catalog',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/rubrics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/rubrics`,
    },
    {
      id: 'rubric_detail',
      label: 'Rubric detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/rubrics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/rubrics/${ctx.rubric_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.rubric_id ? null : 'no rubric visible in selected course',
    },
    {
      id: 'rubric_used_location',
      label: 'Rubric used location',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/rubrics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/rubrics/${ctx.rubric_id}/used_locations`,
      paginated: false,
      skip: (ctx: any) => ctx.rubric_id ? null : 'no rubric visible in selected course',
    },
    {
      id: 'live_assessment',
      label: 'LiveAssessment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/live_assessments',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/live_assessments`,
      paginated: false,
    },
    {
      id: 'live_assessment_result',
      label: 'LiveAssessment result',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/live_assessments',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/live_assessments/${ctx.live_assessment_id}/results`,
      param: (ctx: any) => ({ user_id: ctx.user_id }),
      paginated: false,
      skip: (ctx: any) => ctx.live_assessment_id ? null : 'no live assessment visible in selected course',
    },
    {
      id: 'assessment_question_bank',
      label: 'Assessment question bank',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/assessment_question_banks',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/question_banks`,
    },
    {
      id: 'assessment_question_bank_detail',
      label: 'Assessment question-bank detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/assessment_question_banks',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/question_banks/${ctx.assessment_question_bank_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.assessment_question_bank_id ? null : 'no assessment question bank visible in selected course',
    },
    {
      id: 'assessment_question',
      label: 'Assessment question',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/assessment_question_banks',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/question_banks/${ctx.assessment_question_bank_id}/questions`,
      skip: (ctx: any) => ctx.assessment_question_bank_id ? null : 'no assessment question bank visible in selected course',
    },
    {
      id: 'conversation',
      label: 'Canvas inbox conversation',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/conversations',
      path: () => '/api/v1/conversations',
      param: (ctx: any) => ({ scope: 'unread', 'filter[]': `course_${ctx.course_id}` }),
    },
    {
      id: 'conversation_unread_count',
      label: 'Canvas inbox unread count',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/conversations',
      path: () => '/api/v1/conversations/unread_count',
      paginated: false,
    },
    {
      id: 'conversation_detail',
      label: 'Canvas inbox conversation detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/conversations',
      path: (ctx: any) => `/api/v1/conversations/${ctx.conversation_id}`,
      param: (ctx: any) => ({ scope: 'unread', 'filter[]': `course_${ctx.course_id}` }),
      paginated: false,
      skip: (ctx: any) => ctx.conversation_id ? null : 'no unread course conversation visible in selected course',
    },
    {
      id: 'classic_quiz_submission',
      label: 'Classic quiz submission',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_submissions',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/submission`,
      paginated: false,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_submission_list',
      label: 'Classic quiz submission list',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_submissions',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/submissions`,
      param: () => ({ 'include[]': ['submission', 'quiz', 'user'] }),
      paginated: false,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_question',
      label: 'Classic quiz question',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_questions',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/questions`,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_question_group',
      label: 'Classic quiz question group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_question_groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/groups`,
      paginated: false,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_question_group_detail',
      label: 'Classic quiz question group detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_question_groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/groups/${ctx.quiz_question_group_id}`,
      paginated: false,
      skip: (ctx: any) => {
        if (!ctx.quiz_id) return 'no classic quiz visible in selected course';
        if (!ctx.quiz_question_group_id) return 'no quiz question group visible in selected course';
        return null;
      },
    },
    {
      id: 'classic_quiz_ip_filter',
      label: 'Classic quiz IP filter',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_ip_filters',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/ip_filters`,
      paginated: false,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_assignment_override',
      label: 'Classic quiz assignment override',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_assignment_overrides',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/assignment_overrides`,
      param: (ctx: any) => ({ 'quiz_assignment_overrides[][quiz_ids][]': ctx.quiz_id }),
      paginated: false,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_report',
      label: 'Classic quiz report',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_reports',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/reports`,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_statistic',
      label: 'Classic quiz statistic',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_statistics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/statistics`,
      param: () => ({ all_versions: true }),
      paginated: false,
      skip: (ctx: any) => ctx.quiz_id ? null : 'no classic quiz visible in selected course',
    },
    {
      id: 'classic_quiz_submission_question',
      label: 'Classic quiz submission question',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_submission_questions',
      path: (ctx: any) => `/api/v1/quiz_submissions/${ctx.quiz_submission_id}/questions`,
      param: () => ({ 'include[]': 'quiz_question' }),
      skip: (ctx: any) => ctx.quiz_submission_id ? null : 'no current-user classic quiz submission visible',
    },
    {
      id: 'classic_quiz_submission_event',
      label: 'Classic quiz submission event',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_submission_events',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/submissions/${ctx.quiz_submission_id}/events`,
      skip: (ctx: any) => {
        if (!ctx.quiz_id) return 'no classic quiz visible in selected course';
        if (!ctx.quiz_submission_id) return 'no current-user classic quiz submission visible';
        return null;
      },
    },
    {
      id: 'classic_quiz_submission_time',
      label: 'Classic quiz submission time',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_submissions',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/quizzes/${ctx.quiz_id}/submissions/${ctx.quiz_submission_id}/time`,
      paginated: false,
      skip: (ctx: any) => {
        if (!ctx.quiz_id) return 'no classic quiz visible in selected course';
        if (!ctx.quiz_submission_id) return 'no current-user classic quiz submission visible';
        return null;
      },
    },
    {
      id: 'new_quiz',
      label: 'New Quiz catalog',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/new_quizzes',
      path: (ctx: any) => `/api/quiz/v1/courses/${ctx.course_id}/quizzes`,
    },
    {
      id: 'new_quiz_detail',
      label: 'New Quiz detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/new_quizzes',
      path: (ctx: any) => `/api/quiz/v1/courses/${ctx.course_id}/quizzes/${ctx.assignment_id}`,
      paginated: false,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible for New Quiz detail probe',
    },
    {
      id: 'new_quiz_item',
      label: 'New Quiz item',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/new_quiz_items',
      path: (ctx: any) => `/api/quiz/v1/courses/${ctx.course_id}/quizzes/${ctx.assignment_id}/items`,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible for New Quiz item probe',
    },
    {
      id: 'new_quiz_assignment_override',
      label: 'New Quiz assignment override',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/quiz_assignment_overrides',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/new_quizzes/assignment_overrides`,
      param: (ctx: any) => ({ 'quiz_assignment_overrides[][quiz_ids][]': ctx.assignment_id }),
      paginated: false,
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible for New Quiz override probe',
    },
    {
      id: 'lti_line_item',
      label: 'LTI line item',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/line_items',
      path: (ctx: any) => `/api/lti/courses/${ctx.course_id}/line_items`,
    },
    {
      id: 'appointment_group',
      label: 'Appointment group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/appointment_groups',
      path: () => '/api/v1/appointment_groups',
      param: (ctx: any) => ({
        scope: 'reservable',
        'context_codes[]': `course_${ctx.course_id}`,
        'include[]': ['appointments', 'reserved_times', 'participant_count'],
      }),
    },
    {
      id: 'appointment_group_detail',
      label: 'Appointment group detail',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/appointment_groups',
      path: (ctx: any) => `/api/v1/appointment_groups/${ctx.appointment_group_id}`,
      param: () => ({ 'include[]': ['appointments', 'child_events', 'all_context_codes'] }),
      paginated: false,
      skip: (ctx: any) => ctx.appointment_group_id ? null : 'no appointment group visible for selected course',
    },
    {
      id: 'appointment_user',
      label: 'Appointment group user participant',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/appointment_groups',
      path: (ctx: any) => `/api/v1/appointment_groups/${ctx.appointment_group_id}/users`,
      param: () => ({ registration_status: 'all' }),
      skip: (ctx: any) => ctx.appointment_group_id ? null : 'no appointment group visible for selected course',
    },
    {
      id: 'appointment_group_participant',
      label: 'Appointment group participant group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/appointment_groups',
      path: (ctx: any) => `/api/v1/appointment_groups/${ctx.appointment_group_id}/groups`,
      param: () => ({ registration_status: 'all' }),
      skip: (ctx: any) => ctx.appointment_group_id ? null : 'no appointment group visible for selected course',
    },
    {
      id: 'next_appointment',
      label: 'Next appointment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/appointment_groups',
      path: () => '/api/v1/appointment_groups/next_appointment',
      param: (ctx: any) => ({ 'appointment_group_ids[]': ctx.appointment_group_id }),
      skip: (ctx: any) => ctx.appointment_group_id ? null : 'no appointment group visible for selected course',
    },
    {
      id: 'course_analytics_activity',
      label: 'Course analytics activity',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/analytics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/analytics/activity`,
      paginated: false,
    },
    {
      id: 'course_analytics_assignment',
      label: 'Course analytics assignment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/analytics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/analytics/assignments`,
      param: () => ({ async: false }),
    },
    {
      id: 'course_analytics_student_summary',
      label: 'Course analytics student summary',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/analytics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/analytics/student_summaries`,
      param: (ctx: any) => ({ student_id: ctx.user_id }),
    },
    {
      id: 'analytics_user_activity',
      label: 'Analytics user activity',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/analytics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/analytics/users/${ctx.user_id}/activity`,
      paginated: false,
    },
    {
      id: 'analytics_user_assignment',
      label: 'Analytics user assignment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/analytics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/analytics/users/${ctx.user_id}/assignments`,
    },
    {
      id: 'analytics_user_communication',
      label: 'Analytics user communication',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/analytics',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/analytics/users/${ctx.user_id}/communication`,
      paginated: false,
    },
    {
      id: 'outcome_root_group',
      label: 'Course root outcome group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/outcome_groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/root_outcome_group`,
      paginated: false,
    },
    {
      id: 'outcome_group',
      label: 'Course outcome group',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/outcome_groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/outcome_groups`,
    },
    {
      id: 'outcome_group_link',
      label: 'Course outcome group link',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/outcome_groups',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/outcome_group_links`,
      param: () => ({
        outcome_style: 'full',
        outcome_group_style: 'full',
      }),
    },
    {
      id: 'outcome_alignment',
      label: 'Outcome alignment',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/outcomes',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/outcome_alignments`,
      param: (ctx: any) => ({ student_id: ctx.user_id, assignment_id: ctx.assignment_id }),
      skip: (ctx: any) => ctx.assignment_id ? null : 'no assignment visible in selected course',
    },
    {
      id: 'outcome_result',
      label: 'Outcome result',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/outcome_results',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/outcome_results`,
      param: (ctx: any) => ({ 'user_ids[]': ctx.user_id, 'include[]': 'alignments' }),
      paginated: false,
    },
    {
      id: 'outcome_rollup',
      label: 'Outcome rollup',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/outcome_results',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/outcome_rollups`,
      param: (ctx: any) => ({
        'user_ids[]': ctx.user_id,
        'exclude[]': ['missing_user_rollups', 'missing_outcome_results'],
      }),
      paginated: false,
    },
    {
      id: 'outcome_proficiency',
      label: 'Outcome proficiency rating',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/proficiency_ratings',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/outcome_proficiency`,
      paginated: false,
    },
    {
      id: 'activity_stream',
      label: 'Activity stream',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/activity_stream',
      param: () => ({ only_active_courses: true }),
    },
    {
      id: 'activity_stream_summary',
      label: 'Activity stream summary',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      path: () => '/api/v1/users/self/activity_stream/summary',
      param: () => ({ only_active_courses: true }),
    },
    {
      id: 'course_activity_stream',
      label: 'Course activity stream',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/activity_stream`,
    },
    {
      id: 'course_activity_stream_summary',
      label: 'Course activity stream summary',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/courses',
      path: (ctx: any) => `/api/v1/courses/${ctx.course_id}/activity_stream/summary`,
    },
    {
      id: 'course_audit_log',
      label: 'Course audit log',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/course_audit_log',
      path: (ctx: any) => `/api/v1/audit/course/courses/${ctx.course_id}`,
      param: () => ({ per_page: 25 }),
      paginated: false,
    },
    {
      id: 'recent_history',
      label: 'Recent history',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/history',
      path: (ctx: any) => `/api/v1/users/${ctx.user_id}/history`,
      param: () => ({ per_page: 25 }),
      paginated: false,
    },
    {
      id: 'page_view_async_query',
      label: 'Page-view async query',
      doc_url: 'https://developerdocs.instructure.com/services/canvas/resources/users',
      method: 'POST',
      skip: () => 'skipped in MCP because it requires a POST query job; use the explicit capability smoke --include-page-view only when requested',
      path: () => '/api/v1/users/self/page_views/query',
    },
  ];
}

function listCanvasApiEndpoint(): unknown {
  const context = {
    user_id: '{user_id}',
    course_id: '{course_id}',
    assignment_id: '{assignment_id}',
    rubric_id: '{rubric_id}',
    live_assessment_id: '{live_assessment_id}',
    assessment_question_bank_id: '{assessment_question_bank_id}',
    course_file_id: '{course_file_id}',
    access_token_id: '{access_token_id}',
    account_id: '{account_id}',
    account_calendar_id: '{account_calendar_id}',
    account_notification_id: '{account_notification_id}',
    section_id: '{section_id}',
    temporary_enrollment_pairing_id: '{temporary_enrollment_pairing_id}',
    role_id: '{role_id}',
    sis_import_id: '{sis_import_id}',
    blueprint_migration_id: '{blueprint_migration_id}',
    grading_period_id: '{grading_period_id}',
    anonymous_id: '{anonymous_id}',
    account_domain: '{account_domain}',
    enrollment_term_id: '{enrollment_term_id}',
    quiz_id: '{quiz_id}',
    quiz_question_group_id: '{quiz_question_group_id}',
    quiz_submission_id: '{quiz_submission_id}',
    poll_id: '{poll_id}',
    poll_session_id: '{poll_session_id}',
    poll_submission_id: '{poll_submission_id}',
    course_report_type: '{course_report_type}',
    course_report_id: '{course_report_id}',
    content_migration_id: '{content_migration_id}',
    migration_issue_id: '{migration_issue_id}',
    progress_id: '{progress_id}',
    lti_progress_id: '{lti_progress_id}',
    module_id: '{module_id}',
    module_item_id: '{module_item_id}',
    external_module_item_id: '{external_module_item_id}',
    external_tool_id: '{external_tool_id}',
    group_id: '{group_id}',
    appointment_group_id: '{appointment_group_id}',
    collaboration_id: '{collaboration_id}',
    content_share_id: '{content_share_id}',
    calendar_event_id: '{calendar_event_id}',
    submission_file_id: '{submission_file_id}',
    start_date: '{start_date}',
    end_date: '{end_date}',
    page_view_start_time: '{page_view_start_time}',
    page_view_end_time: '{page_view_end_time}',
  };
  const endpoint = capabilityProbeDefinition().map((entry) => {
    const param = entry.param?.(context) ?? {};
    return {
      probe_id: entry.id,
      label: entry.label,
      method: entry.method ?? 'GET',
      is_paginated: entry.paginated !== false,
      path_template: entry.path(context),
      param_key: Object.keys(param),
      is_skipped_by_default: Boolean(entry.skip?.(context)),
      doc_url: entry.doc_url,
    };
  });
  return {
    generated_at: new Date().toISOString(),
    endpoint_count: endpoint.length,
    endpoint,
  };
}

async function getCanvasApiCapability(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  account_id?: string | number;
  account_notification_id?: string | number;
  section_id?: string | number;
  temporary_enrollment_pairing_id?: string | number;
  sis_import_id?: string | number;
  account_domain?: string;
  enrollment_term_id?: string | number;
  role_id?: string | number;
  quiz_id?: string | number;
  course_report_type?: string;
  course_report_id?: string | number;
  assessment_question_bank_id?: string | number;
  content_migration_id?: string | number;
  migration_issue_id?: string | number;
  start_date?: string;
  end_date?: string;
  probe_id?: unknown;
}): Promise<unknown> {
  const now = new Date();
  const startDate = args.start_date ?? dateOffset(now, -14);
  const endDate = args.end_date ?? dateOffset(now, 45);
  const pageViewStartTime = `${startDate}T00:00:00Z`;
  const pageViewEndTime = `${endDate}T23:59:59Z`;
  const courseReportType = typeof args.course_report_type === 'string' && args.course_report_type.trim()
    ? args.course_report_type.trim()
    : null;
  const courseReportId = args.course_report_id ? String(args.course_report_id) : null;
  const requestedQuestionBankId = args.assessment_question_bank_id ? String(args.assessment_question_bank_id) : null;
  const requestedMigrationId = args.content_migration_id ? String(args.content_migration_id) : null;
  const requestedMigrationIssueId = args.migration_issue_id ? String(args.migration_issue_id) : null;
  const requestedAccountId = args.account_id ? String(args.account_id) : null;
  const requestedAccountNotificationId = args.account_notification_id ? String(args.account_notification_id) : null;
  const requestedSectionId = args.section_id ? String(args.section_id) : null;
  const requestedTemporaryEnrollmentPairingId = args.temporary_enrollment_pairing_id ? String(args.temporary_enrollment_pairing_id) : null;
  const requestedSisImportId = args.sis_import_id ? String(args.sis_import_id) : null;
  const requestedAccountDomain = typeof args.account_domain === 'string' && args.account_domain.trim()
    ? args.account_domain.trim()
    : null;
  const requestedEnrollmentTermId = args.enrollment_term_id ? String(args.enrollment_term_id) : null;
  const requestedRoleId = args.role_id ? String(args.role_id) : null;
  const user = await canvasGet('/users/self') as any;
  const course = await canvasPaginate<any>('/courses', courseParam({ enrollment_state: 'active' }));
  const selectedCourse = (() => {
    if (args.course_id) return course.find((one: any) => String(one.id) === String(args.course_id));
    if (DEFAULT_COURSE_ID) return course.find((one: any) => String(one.id) === String(DEFAULT_COURSE_ID));
    return [...course].sort((a: any, b: any) => capabilityTermScore(b) - capabilityTermScore(a))[0] ?? null;
  })();
  if (!selectedCourse) throw new Error('No visible Canvas course found for capability probe');
  const id = String(selectedCourse.id);
  const accountId = requestedAccountId
    ?? (selectedCourse.root_account_id ? String(selectedCourse.root_account_id) : selectedCourse.account_id ? String(selectedCourse.account_id) : null);
  const enrollmentTermId = requestedEnrollmentTermId
    ?? (selectedCourse.term?.id ? String(selectedCourse.term.id) : selectedCourse.enrollment_term_id ? String(selectedCourse.enrollment_term_id) : null);
  const assignment = await safe(() => canvasPaginate<any>(`/courses/${id}/assignments`));
  const assignmentValue = (assignment.value as any[]) ?? [];
  const selectedAssignment = (() => {
    if (args.assignment_id) return assignmentValue.find((one: any) => String(one.id) === String(args.assignment_id)) ?? { id: args.assignment_id };
    return assignmentValue.find((one: any) => one.due_at) ?? assignmentValue[0] ?? null;
  })();
  const selectedAssignmentDetail = selectedAssignment?.id
    ? await safe(() => canvasGet(`/courses/${id}/assignments/${selectedAssignment.id}`))
    : { value: null, error: 'no assignment visible in selected course' };
  const section = await safe(() => canvasPaginate<any>(`/courses/${id}/sections`, {
    'include[]': ['total_students', 'passback_status'],
  }));
  const sectionValue = (section.value as any[]) ?? [];
  const selectedSection = requestedSectionId
    ? sectionValue.find((one: any) => String(one?.id ?? '') === requestedSectionId) ?? { id: requestedSectionId }
    : sectionValue.find((one: any) => one?.id) ?? null;
  const selectedSubmission = selectedAssignment?.id
    ? await safe(() => canvasGet(`/courses/${id}/assignments/${selectedAssignment.id}/submissions/self`, { 'include[]': 'submission_history' }))
    : { value: null, error: 'no assignment visible in selected course' };
  const selectedSubmissionAttachment = Array.isArray((selectedSubmission.value as any)?.attachments)
    ? (selectedSubmission.value as any).attachments[0]
    : null;
  const quiz = await safe(() => canvasPaginate<any>(`/courses/${id}/quizzes`));
  const quizValue = (quiz.value as any[]) ?? [];
  const selectedQuiz = (() => {
    if (args.quiz_id) return quizValue.find((one: any) => String(one.id) === String(args.quiz_id)) ?? { id: args.quiz_id };
    return quizValue[0] ?? null;
  })();
  const quizSubmission = selectedQuiz?.id
    ? await safe(() => canvasGet(`/courses/${id}/quizzes/${selectedQuiz.id}/submission`, { 'include[]': ['submission', 'quiz', 'user'] }))
    : { value: null, error: 'no classic quiz visible in selected course' };
  const selectedQuizSubmission = compactQuizSubmission(quizSubmission.value);
  const quizQuestionGroup = selectedQuiz?.id
    ? await safe(() => canvasGet(`/courses/${id}/quizzes/${selectedQuiz.id}/groups`))
    : { value: null, error: 'no classic quiz visible in selected course' };
  const selectedQuizQuestionGroup = unwrapCanvasArray(quizQuestionGroup.value, 'quiz_groups').find((one: any) => one?.id) ?? null;
  const poll = await safe(() => canvasGet('/polls'));
  const pollValue = unwrapCanvasArray(poll.value, 'polls');
  const selectedPoll = pollValue.find((one: any) => one?.id) ?? null;
  const [openedPollSession, closedPollSession] = await Promise.all([
    safe(() => canvasGet('/poll_sessions/opened')),
    safe(() => canvasGet('/poll_sessions/closed')),
  ]);
  const pollSessionValue = [
    ...unwrapCanvasArray(openedPollSession.value, 'poll_sessions'),
    ...unwrapCanvasArray(closedPollSession.value, 'poll_sessions'),
  ].filter((one: any) => !one?.course_id || String(one.course_id) === id);
  const selectedPollSubmissionTarget = pollSessionValue.flatMap((one: any) => (
    unwrapCanvasArray(one?.poll_submissions, 'poll_submissions').map((submission: any) => ({
      poll_id: one?.poll_id,
      poll_session_id: one?.id,
      poll_submission_id: submission?.id,
    }))
  )).find((one: any) => one.poll_id && one.poll_session_id && one.poll_submission_id) ?? null;
  const module = await safe(() => canvasPaginate<any>(`/courses/${id}/modules`, { 'include[]': ['items', 'content_details'] }));
  const moduleValue = (module.value as any[]) ?? [];
  const selectedModule = moduleValue[0] ?? null;
  const selectedModuleItem = moduleValue
    .flatMap((one: any) => Array.isArray(one?.items) ? one.items : [])
    .find((one: any) => one?.id) ?? null;
  const selectedExternalModuleItem = moduleValue
    .flatMap((one: any) => Array.isArray(one?.items) ? one.items : [])
    .find((one: any) => String(one?.type ?? '').toLowerCase() === 'externaltool') ?? null;
  const externalTool = await safe(() => canvasPaginate<any>(`/courses/${id}/external_tools`, { include_parents: true }));
  const externalToolValue = (externalTool.value as any[]) ?? [];
  const selectedExternalTool = externalToolValue[0] ?? null;
  const communicationChannel = await safe(() => canvasPaginate<any>('/users/self/communication_channels'));
  const communicationChannelValue = (communicationChannel.value as any[]) ?? [];
  const selectedCommunicationChannel = communicationChannelValue[0] ?? null;
  const accountNotification = accountId
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/account_notifications`, { show_is_closed: true }))
    : { value: [], error: null };
  const accountNotificationValue = (accountNotification.value as any[]) ?? [];
  const selectedAccountNotification = requestedAccountNotificationId
    ? accountNotificationValue.find((one: any) => String(one?.id ?? '') === requestedAccountNotificationId) ?? { id: requestedAccountNotificationId }
    : accountNotificationValue.find((one: any) => one?.id) ?? null;
  const temporaryEnrollmentPairing = accountId
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/temporary_enrollment_pairings`))
    : { value: [], error: null };
  const temporaryEnrollmentPairingValue = (temporaryEnrollmentPairing.value as any[]) ?? [];
  const selectedTemporaryEnrollmentPairing = requestedTemporaryEnrollmentPairingId
    ? temporaryEnrollmentPairingValue.find((one: any) => String(one?.id ?? '') === requestedTemporaryEnrollmentPairingId) ?? { id: requestedTemporaryEnrollmentPairingId }
    : temporaryEnrollmentPairingValue.find((one: any) => one?.id) ?? null;
  const role = accountId
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/roles`, { 'state[]': ['active', 'inactive'] }))
    : { value: [], error: null };
  const roleValue = (role.value as any[]) ?? [];
  const selectedRole = requestedRoleId
    ? roleValue.find((one: any) => String(one?.id ?? '') === requestedRoleId) ?? { id: requestedRoleId }
    : roleValue.find((one: any) => one?.id) ?? null;
  const sisImport = accountId
    ? await safe(() => canvasPaginate<any>(`/accounts/${accountId}/sis_imports`, {
      created_since: pageViewStartTime,
      created_before: pageViewEndTime,
    }))
    : { value: [], error: null };
  const sisImportValue = (sisImport.value as any[]) ?? [];
  const selectedSisImport = requestedSisImportId
    ? sisImportValue.find((one: any) => String(one?.id ?? '') === requestedSisImportId) ?? { id: requestedSisImportId }
    : sisImportValue.find((one: any) => one?.id) ?? null;
  const userAccessToken = await safe(() => canvasPaginate<any>(`/users/${user.id}/user_generated_tokens`));
  const userAccessTokenValue = (userAccessToken.value as any[]) ?? [];
  const selectedAccessToken = userAccessTokenValue.find((one: any) => one?.id) ?? null;
  const eportfolio = await safe(() => canvasPaginate<any>(`/users/${user.id}/eportfolios`));
  const eportfolioValue = (eportfolio.value as any[]) ?? [];
  const selectedEportfolio = eportfolioValue[0] ?? null;
  const customGradebookColumn = await safe(() => canvasPaginate<any>(`/courses/${id}/custom_gradebook_columns`));
  const customGradebookColumnValue = (customGradebookColumn.value as any[]) ?? [];
  const selectedCustomGradebookColumn = customGradebookColumnValue.find((one: any) => one?.id) ?? null;
  const questionBank = await safe(() => canvasPaginate<any>(`/courses/${id}/question_banks`));
  const questionBankValue = (questionBank.value as any[]) ?? [];
  const selectedQuestionBank = requestedQuestionBankId
    ? questionBankValue.find((one: any) => String(one?.id ?? '') === requestedQuestionBankId) ?? { id: requestedQuestionBankId }
    : questionBankValue.find((one: any) => one?.id) ?? null;
  const rubric = await safe(() => canvasPaginate<any>(`/courses/${id}/rubrics`));
  const rubricValue = (rubric.value as any[]) ?? [];
  const selectedAssignmentRubricId = (selectedAssignmentDetail.value as any)?.rubric_settings?.id
    ? String((selectedAssignmentDetail.value as any).rubric_settings.id)
    : null;
  const selectedRubric = rubricValue.find((one: any) => one?.id) ?? (selectedAssignmentRubricId ? { id: selectedAssignmentRubricId } : null);
  const liveAssessment = await safe(() => canvasGet(`/courses/${id}/live_assessments`));
  const liveAssessmentValue = unwrapCanvasArray(liveAssessment.value, 'assessments');
  const selectedLiveAssessment = liveAssessmentValue.find((one: any) => one?.id) ?? null;
  const ownGroup = await safe(() => canvasPaginate<any>(`/courses/${id}/groups`, {
    only_own_groups: true,
    'include[]': 'tabs',
  }));
  const ownGroupValue = (ownGroup.value as any[]) ?? [];
  const selectedGroup = ownGroupValue[0] ?? null;
  const groupCategory = await safe(() => canvasPaginate<any>(`/courses/${id}/group_categories`, {
    collaboration_state: 'all',
  }));
  const groupCategoryValue = (groupCategory.value as any[]) ?? [];
  const selectedGroupCategory = groupCategoryValue[0] ?? null;
  const courseCollaboration = await safe(() => canvasPaginate<any>(`/courses/${id}/collaborations`));
  const courseCollaborationValue = (courseCollaboration.value as any[]) ?? [];
  const groupCollaboration = selectedGroup?.id
    ? await safe(() => canvasPaginate<any>(`/groups/${selectedGroup.id}/collaborations`))
    : { value: null, error: 'no own group visible in selected course' };
  const groupCollaborationValue = (groupCollaboration.value as any[]) ?? [];
  const selectedCollaboration = courseCollaborationValue[0] ?? groupCollaborationValue[0] ?? null;
  const calendarEvent = await safe(() => canvasPaginate<any>('/calendar_events', {
    type: 'event',
    start_date: startDate,
    end_date: endDate,
    'context_codes[]': `course_${id}`,
  }));
  const calendarEventValue = (calendarEvent.value as any[]) ?? [];
  const selectedCalendarEvent = calendarEventValue.find((one: any) => /^\d+$/.test(String(one?.id ?? ''))) ?? null;
  const courseFile = await safe(() => canvasPaginate<any>(`/courses/${id}/files`, { 'include[]': ['user', 'usage_rights'] }));
  const courseFileValue = (courseFile.value as any[]) ?? [];
  const selectedCourseFile = courseFileValue.find((one: any) => one?.id) ?? null;
  const appointmentGroup = await safe(() => canvasPaginate<any>('/appointment_groups', {
    scope: 'reservable',
    'context_codes[]': `course_${id}`,
    'include[]': ['appointments', 'reserved_times', 'participant_count'],
  }));
  const appointmentGroupValue = (appointmentGroup.value as any[]) ?? [];
  const selectedAppointmentGroup = appointmentGroupValue.find((one: any) => one?.id) ?? null;
  const conversation = await safe(() => canvasPaginate<any>('/conversations', {
    scope: 'unread',
    'filter[]': `course_${id}`,
  }));
  const conversationValue = (conversation.value as any[]) ?? [];
  const selectedConversation = conversationValue[0] ?? null;
  const [courseExport, userExport, epubExport, contentMigration] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/content_exports`)),
    safe(() => canvasPaginate<any>('/users/self/content_exports')),
    safe(() => canvasGet('/epub_exports')),
    safe(() => canvasPaginate<any>(`/courses/${id}/content_migrations`)),
  ]);
  const contentShare = await safe(() => canvasPaginate<any>('/users/self/content_shares/received'));
  const contentShareValue = (contentShare.value as any[]) ?? [];
  const selectedContentShare = contentShareValue[0] ?? null;
  const contentMigrationValue = (contentMigration.value as any[]) ?? [];
  const selectedContentMigration = requestedMigrationId
    ? contentMigrationValue.find((one: any) => String(one?.id ?? '') === requestedMigrationId) ?? { id: requestedMigrationId }
    : contentMigrationValue.find((one: any) => one?.id) ?? null;
  const migrationIssue = selectedContentMigration?.id
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/content_migrations/${selectedContentMigration.id}/migration_issues`))
    : { value: [], error: null };
  const migrationIssueValue = (migrationIssue.value as any[]) ?? [];
  const selectedMigrationIssue = requestedMigrationIssueId
    ? migrationIssueValue.find((one: any) => String(one?.id ?? '') === requestedMigrationIssueId) ?? { id: requestedMigrationIssueId }
    : migrationIssueValue.find((one: any) => one?.id) ?? null;
  const rawEpubExport = epubExport.value as any;
  const epubExportValue = Array.isArray(rawEpubExport)
    ? rawEpubExport
    : Array.isArray(rawEpubExport?.courses)
      ? rawEpubExport.courses
      : rawEpubExport
        ? [rawEpubExport]
        : [];
  const selectedProgressTarget = [
    ...((courseExport.value as any[]) ?? []).map((one: any) => one?.progress_url),
    ...((userExport.value as any[]) ?? []).map((one: any) => one?.progress_url),
    ...epubExportValue.map((one: any) => one?.epub_export?.progress_url ?? one?.export?.progress_url),
    ...contentMigrationValue.map((one: any) => one?.progress_url),
  ].map((one) => progressTargetFromValue(one, id)).find(Boolean) ?? null;
  const accountDomain = requestedAccountDomain ?? (() => {
    try {
      return new URL(BASE_URL).hostname;
    } catch {
      return null;
    }
  })();
  const context = {
    user_id: String(user.id),
    course_id: id,
    assignment_id: selectedAssignment ? String(selectedAssignment.id) : null,
    rubric_id: selectedRubric?.id ? String(selectedRubric.id) : null,
    live_assessment_id: selectedLiveAssessment?.id ? String(selectedLiveAssessment.id) : null,
    assessment_question_bank_id: selectedQuestionBank?.id ? String(selectedQuestionBank.id) : null,
    course_file_id: selectedCourseFile ? String(selectedCourseFile.id) : null,
    account_id: accountId,
    account_calendar_id: accountId,
    account_notification_id: selectedAccountNotification?.id ? String(selectedAccountNotification.id) : null,
    section_id: selectedSection?.id ? String(selectedSection.id) : null,
    temporary_enrollment_pairing_id: selectedTemporaryEnrollmentPairing?.id ? String(selectedTemporaryEnrollmentPairing.id) : null,
    role_id: selectedRole?.id ? String(selectedRole.id) : null,
    sis_import_id: selectedSisImport?.id ? String(selectedSisImport.id) : null,
    access_token_id: selectedAccessToken?.id ? String(selectedAccessToken.id) : null,
    blueprint_migration_id: null,
    grading_period_id: null,
    anonymous_id: null,
    account_domain: accountDomain,
    enrollment_term_id: enrollmentTermId,
    quiz_id: selectedQuiz ? String(selectedQuiz.id) : null,
    quiz_question_group_id: selectedQuizQuestionGroup?.id ? String(selectedQuizQuestionGroup.id) : null,
    quiz_submission_id: selectedQuizSubmission?.quiz_submission_id ? String(selectedQuizSubmission.quiz_submission_id) : null,
    poll_id: selectedPoll ? String(selectedPoll.id) : null,
    poll_session_id: selectedPollSubmissionTarget ? String(selectedPollSubmissionTarget.poll_session_id) : null,
    poll_submission_id: selectedPollSubmissionTarget ? String(selectedPollSubmissionTarget.poll_submission_id) : null,
    course_report_type: courseReportType,
    course_report_id: courseReportId,
    content_migration_id: selectedContentMigration?.id ? String(selectedContentMigration.id) : null,
    migration_issue_id: selectedMigrationIssue?.id ? String(selectedMigrationIssue.id) : null,
    progress_id: selectedProgressTarget?.kind === 'canvas' ? selectedProgressTarget.progress_id : null,
    lti_progress_id: selectedProgressTarget?.kind === 'lti' ? selectedProgressTarget.progress_id : null,
    module_id: selectedModule ? String(selectedModule.id) : null,
    module_item_id: selectedModuleItem ? String(selectedModuleItem.id) : null,
    external_module_item_id: selectedExternalModuleItem ? String(selectedExternalModuleItem.id) : null,
    external_tool_id: selectedExternalTool ? String(selectedExternalTool.id) : null,
    group_id: selectedGroup ? String(selectedGroup.id) : null,
    group_category_id: selectedGroupCategory ? String(selectedGroupCategory.id) : null,
    collaboration_id: selectedCollaboration ? String(selectedCollaboration.id) : null,
    appointment_group_id: selectedAppointmentGroup ? String(selectedAppointmentGroup.id) : null,
    content_share_id: selectedContentShare ? String(selectedContentShare.id) : null,
    eportfolio_id: selectedEportfolio ? String(selectedEportfolio.id) : null,
    custom_gradebook_column_id: selectedCustomGradebookColumn ? String(selectedCustomGradebookColumn.id) : null,
    calendar_event_id: selectedCalendarEvent ? String(selectedCalendarEvent.id) : null,
    submission_file_id: selectedSubmissionAttachment?.id ?? selectedSubmissionAttachment?.file_id
      ? String(selectedSubmissionAttachment.id ?? selectedSubmissionAttachment.file_id)
      : null,
    communication_channel_id: selectedCommunicationChannel ? String(selectedCommunicationChannel.id) : null,
    conversation_id: selectedConversation ? String(selectedConversation.id) : null,
    start_date: startDate,
    end_date: endDate,
    page_view_start_time: pageViewStartTime,
    page_view_end_time: pageViewEndTime,
  };
  const selectedProbeId = new Set(normalizeStringArray(args.probe_id, 'probe_id'));
  const definition = capabilityProbeDefinition();
  const unknownProbeId = [...selectedProbeId].filter((one) => !definition.some((entry) => entry.id === one));
  if (unknownProbeId.length > 0) {
    throw new Error(`Unknown capability probe_id: ${unknownProbeId.join(', ')}`);
  }
  const selectedDefinition = selectedProbeId.size > 0
    ? definition.filter((entry) => selectedProbeId.has(entry.id))
    : definition;
  const probe = await pool(selectedDefinition, (entry) => readCapabilityEndpoint(entry, context), 8);
  const summary = {
    ok_count: probe.filter((one) => one.status === 'ok').length,
    blocked_or_absent_count: probe.filter((one) => one.status === 'blocked_or_absent').length,
    skipped_count: probe.filter((one) => one.status === 'skipped').length,
    error_count: probe.filter((one) => one.status === 'error').length,
  };
  return {
    ok: summary.error_count === 0,
    generated_at: new Date().toISOString(),
    base_url: BASE_URL,
    date_window: { start_date: startDate, end_date: endDate },
    user: { user_id: context.user_id },
    course: {
      course_id: id,
      course_code: selectedCourse.course_code ?? null,
      term: selectedCourse.term?.name ?? null,
    },
    assignment: selectedAssignment ? {
      assignment_id: String(selectedAssignment.id),
      name: selectedAssignment.name ?? null,
    } : null,
    quiz: selectedQuiz ? {
      quiz_id: String(selectedQuiz.id),
      title: selectedQuiz.title ?? null,
    } : null,
    module: selectedModule ? {
      module_id: String(selectedModule.id),
      name: selectedModule.name ?? null,
    } : null,
    external_module_item: selectedExternalModuleItem ? {
      module_item_id: String(selectedExternalModuleItem.id),
      title: selectedExternalModuleItem.title ?? null,
    } : null,
    external_tool: selectedExternalTool ? {
      external_tool_id: String(selectedExternalTool.id),
      name: selectedExternalTool.name ?? null,
    } : null,
    group: selectedGroup ? {
      group_id: String(selectedGroup.id),
      name: selectedGroup.name ?? null,
    } : null,
    appointment_group: selectedAppointmentGroup ? {
      appointment_group_id: String(selectedAppointmentGroup.id),
      title: selectedAppointmentGroup.title ?? null,
    } : null,
    course_file: selectedCourseFile ? {
      file_id: String(selectedCourseFile.id),
      display_name: selectedCourseFile.display_name ?? selectedCourseFile.filename ?? null,
      content_type: selectedCourseFile['content-type'] ?? selectedCourseFile.content_type ?? null,
    } : null,
    collaboration: selectedCollaboration ? {
      collaboration_id: String(selectedCollaboration.id),
      title: selectedCollaboration.title ?? null,
    } : null,
    calendar_event: selectedCalendarEvent ? {
      event_id: String(selectedCalendarEvent.id),
      title: selectedCalendarEvent.title ?? null,
    } : null,
    probe_id: [...selectedProbeId],
    summary,
    probe,
  };
}

async function getUserCanvasContext(args: {
  course_id?: string | number;
  include_bookmark?: boolean;
  include_dashboard_card?: boolean;
  include_observee?: boolean;
  include_user_preference?: boolean;
  include_graded_submission?: boolean;
  include_login?: boolean;
  include_access_token?: boolean;
  access_token_id?: string | number;
  max_bookmark?: number;
  max_dashboard_card?: number;
  max_favorite_course?: number;
  max_observee?: number;
  max_graded_submission?: number;
  max_login?: number;
  max_access_token?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeBookmark = args.include_bookmark !== false;
  const includeDashboardCard = args.include_dashboard_card !== false;
  const includeObservee = args.include_observee !== false;
  const includeUserPreference = args.include_user_preference !== false;
  const includeGradedSubmission = args.include_graded_submission !== false;
  const includeLogin = args.include_login !== false;
  const includeAccessToken = args.include_access_token !== false;
  const maxBookmark = Math.max(0, Number(args.max_bookmark ?? 80));
  const maxDashboardCard = Math.max(0, Number(args.max_dashboard_card ?? 80));
  const maxFavoriteCourse = Math.max(0, Number(args.max_favorite_course ?? 80));
  const maxObservee = Math.max(0, Number(args.max_observee ?? 20));
  const maxGradedSubmission = Math.max(0, Number(args.max_graded_submission ?? 20));
  const maxLogin = Math.max(0, Number(args.max_login ?? 20));
  const maxAccessToken = Math.max(0, Number(args.max_access_token ?? 20));

  const [
    self,
    profile,
    userLogin,
    userAccessToken,
    favoriteCourse,
    courseNickname,
    dashboardCard,
    customColor,
    selectedCustomColor,
    dashboardPosition,
    bookmark,
    observee,
    gradedSubmission,
    coursePreference,
  ] = await Promise.all([
    safe(() => canvasGet('/users/self')),
    safe(() => canvasGet('/users/self/profile')),
    includeLogin
      ? safe(() => canvasPaginate<any>('/users/self/logins'))
      : Promise.resolve({ value: null, error: null }),
    includeAccessToken
      ? safe(() => canvasPaginate<any>('/users/self/user_generated_tokens'))
      : Promise.resolve({ value: null, error: null }),
    safe(() => canvasPaginate<any>('/users/self/favorites/courses')),
    safe(() => canvasGet(`/users/self/course_nicknames/${id}`)),
    includeDashboardCard
      ? safe(() => canvasPaginate<any>('/dashboard/dashboard_cards'))
      : Promise.resolve({ value: null, error: null }),
    includeUserPreference
      ? safe(() => canvasGet('/users/self/colors'))
      : Promise.resolve({ value: null, error: null }),
    includeUserPreference
      ? safe(() => canvasGet(`/users/self/colors/course_${id}`))
      : Promise.resolve({ value: null, error: null }),
    includeUserPreference
      ? safe(() => canvasGet('/users/self/dashboard_positions'))
      : Promise.resolve({ value: null, error: null }),
    includeBookmark
      ? safe(() => canvasPaginate<any>('/users/self/bookmarks'))
      : Promise.resolve({ value: null, error: null }),
    includeObservee
      ? safe(() => canvasPaginate<any>('/users/self/observees'))
      : Promise.resolve({ value: null, error: null }),
    includeGradedSubmission
      ? safe(() => canvasPaginate<any>('/users/self/graded_submissions', { 'include[]': 'assignment' }))
      : Promise.resolve({ value: null, error: null }),
    safe(() => canvasGet(`/courses/${id}`, {
      'include[]': [
        'term',
        'sections',
        'course_progress',
        'tabs',
        'favorites',
        'teachers',
        'course_image',
        'banner_image',
        'concluded',
        'total_scores',
      ],
    })),
  ]);

  const userLoginValue = limitRow((userLogin.value as any[]) ?? [], maxLogin);
  const userAccessTokenValue = limitRow((userAccessToken.value as any[]) ?? [], maxAccessToken);
  const selfUserId = (self.value as any)?.id ? String((self.value as any).id) : 'self';
  const requestedAccessTokenId = args.access_token_id ? String(args.access_token_id) : null;
  const selectedAccessToken = requestedAccessTokenId
    ? userAccessTokenValue.find((one: any) => String(one?.id ?? '') === requestedAccessTokenId) ?? { id: requestedAccessTokenId }
    : userAccessTokenValue.find((one: any) => one?.id) ?? null;
  const accessTokenDetail = selectedAccessToken?.id && includeAccessToken
    ? await safe(() => canvasGet(`/users/${selfUserId}/tokens/${selectedAccessToken.id}`))
    : { value: null, error: includeAccessToken ? 'no user access token visible for detail' : 'access token lookup skipped by caller' };
  const favoriteCourseValue = limitRow((favoriteCourse.value as any[]) ?? [], maxFavoriteCourse);
  const dashboardCardValue = limitRow((dashboardCard.value as any[]) ?? [], maxDashboardCard);
  const bookmarkValue = limitRow((bookmark.value as any[]) ?? [], maxBookmark);
  const observeeValue = limitRow((observee.value as any[]) ?? [], maxObservee);
  const colorValue = limitRow(compactUserColor(customColor.value), maxDashboardCard);
  const dashboardPositionValue = limitRow(compactDashboardPosition(dashboardPosition.value), maxDashboardCard);
  const gradedSubmissionValue = limitRow((gradedSubmission.value as any[]) ?? [], maxGradedSubmission);
  const selectedFavoriteCourse = favoriteCourseValue.find((one: any) => String(one?.id ?? one?.course_id ?? '') === id) ?? null;
  const selectedDashboardCard = dashboardCardValue.find((one: any) => String(one?.id ?? one?.course_id ?? '') === id) ?? null;
  const selectedDashboardPosition = dashboardPositionValue.find((one: any) => String(one?.asset_string ?? '') === `course_${id}`) ?? null;

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    user: compactUser(self.value),
    profile_status: profile.error ? endpointStatus(profile.error) : 'ok',
    profile: compactProfile(profile.value),
    profile_error: profile.error,
    user_login_status: userLogin.error ? endpointStatus(userLogin.error) : (includeLogin ? 'ok' : 'skipped'),
    user_login_count: rowCount(userLogin.value),
    returned_user_login_count: userLoginValue.length,
    user_login: userLoginValue.map(compactLogin),
    user_login_error: userLogin.error,
    user_access_token_status: userAccessToken.error ? endpointStatus(userAccessToken.error) : (includeAccessToken ? 'ok' : 'skipped'),
    user_access_token_count: rowCount(userAccessToken.value),
    returned_user_access_token_count: userAccessTokenValue.length,
    selected_access_token_id: selectedAccessToken?.id ? String(selectedAccessToken.id) : null,
    user_access_token: userAccessTokenValue.map(compactAccessToken),
    user_access_token_error: userAccessToken.error,
    access_token_detail_status: accessTokenDetail.error?.includes('no user access token visible') || accessTokenDetail.error?.includes('skipped by caller')
      ? 'skipped'
      : endpointStatus(accessTokenDetail.error),
    access_token_detail: accessTokenDetail.value ? compactAccessToken(accessTokenDetail.value) : null,
    access_token_detail_error: accessTokenDetail.error,
    favorite_course_status: favoriteCourse.error ? endpointStatus(favoriteCourse.error) : 'ok',
    favorite_course_count: rowCount(favoriteCourse.value),
    favorite_course: favoriteCourseValue.map(compactCoursePreference),
    selected_favorite_course: selectedFavoriteCourse ? compactCoursePreference(selectedFavoriteCourse) : null,
    favorite_course_error: favoriteCourse.error,
    course_nickname_status: courseNickname.error ? endpointStatus(courseNickname.error) : 'ok',
    course_nickname: courseNickname.value ?? null,
    course_nickname_error: courseNickname.error,
    dashboard_card_status: dashboardCard.error ? endpointStatus(dashboardCard.error) : (includeDashboardCard ? 'ok' : 'skipped'),
    dashboard_card_count: rowCount(dashboardCard.value),
    dashboard_card: dashboardCardValue.map(compactDashboardCard),
    selected_dashboard_card: selectedDashboardCard ? compactDashboardCard(selectedDashboardCard) : null,
    dashboard_card_error: dashboardCard.error,
    custom_color_status: customColor.error ? endpointStatus(customColor.error) : (includeUserPreference ? 'ok' : 'skipped'),
    custom_color_count: colorValue.length,
    custom_color: colorValue,
    selected_custom_color_status: selectedCustomColor.error ? endpointStatus(selectedCustomColor.error) : (includeUserPreference ? 'ok' : 'skipped'),
    selected_custom_color: selectedCustomColor.value ?? null,
    custom_color_error: customColor.error,
    selected_custom_color_error: selectedCustomColor.error,
    dashboard_position_status: dashboardPosition.error ? endpointStatus(dashboardPosition.error) : (includeUserPreference ? 'ok' : 'skipped'),
    dashboard_position_count: dashboardPositionValue.length,
    dashboard_position: dashboardPositionValue,
    selected_dashboard_position: selectedDashboardPosition ?? null,
    dashboard_position_error: dashboardPosition.error,
    bookmark_status: bookmark.error ? endpointStatus(bookmark.error) : (includeBookmark ? 'ok' : 'skipped'),
    bookmark_count: rowCount(bookmark.value),
    bookmark: bookmarkValue.map(compactBookmark),
    bookmark_error: bookmark.error,
    observee_status: observee.error ? endpointStatus(observee.error) : (includeObservee ? 'ok' : 'skipped'),
    observee_count: rowCount(observee.value),
    observee: observeeValue.map(compactUser),
    observee_error: observee.error,
    graded_submission_status: gradedSubmission.error ? endpointStatus(gradedSubmission.error) : (includeGradedSubmission ? 'ok' : 'skipped'),
    graded_submission_count: rowCount(gradedSubmission.value),
    returned_graded_submission_count: gradedSubmissionValue.length,
    graded_submission: gradedSubmissionValue.map(compactGradedSubmission),
    graded_submission_error: gradedSubmission.error,
    course_preference_status: coursePreference.error ? endpointStatus(coursePreference.error) : 'ok',
    course_preference: coursePreference.value ? {
      ...compactCoursePreference(coursePreference.value),
      progress: compactCourseProgress(coursePreference.value),
      tab_count: Array.isArray((coursePreference.value as any)?.tabs) ? (coursePreference.value as any).tabs.length : null,
      teacher_count: Array.isArray((coursePreference.value as any)?.teachers) ? (coursePreference.value as any).teachers.length : null,
      enrollment_count: Array.isArray((coursePreference.value as any)?.enrollments) ? (coursePreference.value as any).enrollments.length : null,
      is_concluded: (coursePreference.value as any)?.concluded ?? null,
    } : null,
    course_preference_error: coursePreference.error,
    endpoint: [
      ['user_self', self],
      ['user_profile', profile],
      ['user_login', userLogin],
      ['user_access_token', userAccessToken],
      ['access_token_detail', accessTokenDetail],
      ['favorite_course', favoriteCourse],
      ['course_nickname', courseNickname],
      ['dashboard_card', dashboardCard],
      ['custom_color', customColor],
      ['selected_custom_color', selectedCustomColor],
      ['dashboard_position', dashboardPosition],
      ['bookmark', bookmark],
      ['observee', observee],
      ['graded_submission', gradedSubmission],
      ['course_preference', coursePreference],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    note: 'This context is read-only user/course preference, sanitized login/access-token visibility, and recent-grade evidence. It does not create favorites, bookmarks, course nicknames, access tokens, login changes, color changes, dashboard changes, or user edits. Login output omits raw unique_id, SIS user ID, and integration ID values; access-token output omits token, token_hint, and visible_token values; observee rows are only returned when Canvas exposes them to the current token.',
  };
}

async function getUserPageViewContext(args: {
  start_time?: string;
  end_time?: string;
  max_page_view?: number;
} = {}): Promise<unknown> {
  const maxPageView = Math.min(100, Math.max(0, Number(args.max_page_view ?? 25)));
  const param: Record<string, CanvasParamValue> = { per_page: maxPageView };
  if (args.start_time) param.start_time = args.start_time;
  if (args.end_time) param.end_time = args.end_time;
  const pageView = maxPageView > 0
    ? await safe(() => canvasGet('/users/self/page_views', param))
    : { value: [], error: null };
  const pageViewValue = limitRow(unwrapCanvasArray(pageView.value, 'page_views'), maxPageView);

  return {
    generated_at: new Date().toISOString(),
    start_time: args.start_time ?? null,
    end_time: args.end_time ?? null,
    endpoint: [
      {
        name: 'page_view',
        status: pageView.error ? endpointStatus(pageView.error) : 'ok',
        count: rowCount(pageView.value),
        key: keySample(pageView.value),
        error: pageView.error,
      },
    ],
    page_view_status: pageView.error ? endpointStatus(pageView.error) : 'ok',
    page_view_count: rowCount(pageView.value),
    returned_page_view_count: pageViewValue.length,
    page_view: pageViewValue.map(compactPageView),
    page_view_error: pageView.error,
    note: 'Canvas page views are best-effort weak activity context, not proof of submission or a high-stakes audit source. Raw remote IP and user-agent values are not returned by this tool.',
  };
}

async function listMySubmissions(args: { course_id?: string | number; include_assignment?: boolean; include_history?: boolean }): Promise<unknown> {
  const include = submissionInclude(args);
  return canvasPaginate(`/courses/${courseId(args)}/students/submissions`, {
    'student_ids[]': 'self',
    grouped: false,
    ...(include.length > 0 ? { 'include[]': include } : {}),
  });
}

async function getMySubmission(args: { course_id?: string | number; assignment_id: string | number; include_history?: boolean }): Promise<unknown> {
  const include = args.include_history ? ['submission_history', 'rubric_assessment', 'submission_comments'] : ['submission_comments'];
  return canvasGet(`/courses/${courseId(args)}/assignments/${args.assignment_id}/submissions/self`, {
    'include[]': include,
  });
}

async function getSubmissionFeedbackContext(args: {
  course_id?: string | number;
  assignment_id: string | number;
  max_comment_chars?: number;
  max_history?: number;
  max_originality_report?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const maxCommentChar = Number(args.max_comment_chars ?? 300);
  const maxHistory = Number(args.max_history ?? 12);
  const maxOriginalityReport = Math.max(0, Number(args.max_originality_report ?? 8));
  const include = ['submission_history', 'rubric_assessment', 'submission_comments'];
  const [assignment, submission, rubricRead, annotationRead] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/assignments/${args.assignment_id}`)),
    safe(() => canvasGet(`/courses/${id}/assignments/${args.assignment_id}/submissions/self`, { 'include[]': include })),
    safe(() => canvasGet(`/courses/${id}/assignments/${args.assignment_id}/submissions/self/rubric_assessments/read`)),
    safe(() => canvasGet(`/courses/${id}/assignments/${args.assignment_id}/submissions/self/document_annotations/read`)),
  ]);
  const submissionValue = submission.value as any;
  const comment = Array.isArray(submissionValue?.submission_comments)
    ? submissionValue.submission_comments
    : Array.isArray(submissionValue?.comments)
      ? submissionValue.comments
      : [];
  const history = Array.isArray(submissionValue?.submission_history)
    ? submissionValue.submission_history
    : [];
  const rubricAssessment = compactRubricAssessment(submissionValue?.rubric_assessment);
  const attachment = Array.isArray(submissionValue?.attachments) ? submissionValue.attachments : [];
  const originalityReportSource: string[] = limitRow(attachment
    .map((one: any) => one?.id ?? one?.file_id)
    .filter((one: any) => one !== undefined && one !== null)
    .map((one: any) => String(one)), maxOriginalityReport) as string[];
  const originalityReportResult = originalityReportSource.length > 0
    ? await pool(originalityReportSource, async (fileId: string) => {
      const result = await safe(() => canvasApiGet(`/api/lti/assignments/${args.assignment_id}/files/${fileId}/originality_report`));
      return { file_id: fileId, value: result.value, error: result.error };
    })
    : [];
  const originalityReport = originalityReportResult
    .filter((one: any) => !one.error && one.value)
    .map((one: any) => compactOriginalityReport(one.value))
    .filter(Boolean);

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    assignment_id: String(args.assignment_id),
    assignment: compactAssignmentLike(assignment.value),
    submission_status: submission.error ? endpointStatus(submission.error) : 'ok',
    submission_error: submission.error,
    state: submissionState(submission.value),
    submission: submissionValue ? {
      submission_id: submissionValue?.id ?? null,
      attempt: submissionValue?.attempt ?? null,
      workflow_state: submissionValue?.workflow_state ?? null,
      submitted_at: submissionValue?.submitted_at ?? null,
      graded_at: submissionValue?.graded_at ?? null,
      posted_at: submissionValue?.posted_at ?? null,
      late: !!submissionValue?.late,
      missing: !!submissionValue?.missing,
      grade: submissionValue?.grade ?? null,
      score: submissionValue?.score ?? null,
      submission_type: submissionValue?.submission_type ?? null,
      url: submissionValue?.url ?? null,
      attachment_count: attachment.length,
    } : null,
    comment_count: comment.length,
    comment: comment.map((one: any) => compactSubmissionComment(one, maxCommentChar)),
    rubric_assessment_count: rubricAssessment.length,
    rubric_assessment: rubricAssessment,
    history_count: history.length,
    history: limitRow(history.map(compactSubmissionHistory), maxHistory),
    attachment: attachment.map((one: any) => ({
      file_id: one?.id ?? one?.file_id ?? null,
      display_name: one?.display_name ?? one?.filename ?? null,
      content_type: one?.['content-type'] ?? one?.content_type ?? null,
      size_byte: one?.size ?? null,
      url: one?.url ?? one?.download_url ?? null,
    })),
    originality_report_status: originalityReportSource.length === 0
      ? 'skipped'
      : originalityReportResult.some((one: any) => one.error && endpointStatus(one.error) === 'error')
        ? 'error'
        : originalityReportResult.some((one: any) => !one.error)
          ? 'ok'
          : 'blocked_or_absent',
    originality_report_count: originalityReport.length,
    originality_report: originalityReport,
    originality_report_error: originalityReportResult
      .filter((one: any) => one.error)
      .map((one: any) => ({ file_id: one.file_id, status: endpointStatus(one.error), error: one.error })),
    rubric_read_state_status: rubricRead.error ? endpointStatus(rubricRead.error) : 'ok',
    rubric_read_state: rubricRead.value,
    rubric_read_state_error: rubricRead.error,
    annotation_read_state_status: annotationRead.error ? endpointStatus(annotationRead.error) : 'ok',
    annotation_read_state: annotationRead.value,
    annotation_read_state_error: annotationRead.error,
    endpoint: [
      ['assignment', assignment],
      ['submission', submission],
      ['rubric_read_state', rubricRead],
      ['annotation_read_state', annotationRead],
      ...(
        originalityReportSource.length > 0
          ? originalityReportResult.map((one: any) => [`originality_report:${one.file_id}`, { value: one.value, error: one.error }])
          : [['originality_report', { value: null, error: 'no submitted file attachment visible; originality report skipped' }]]
      ),
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('skipped') ? 'skipped' : endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
  };
}

async function getPeerReviewContext(args: {
  course_id?: string | number;
  assignment_id: string | number;
  submission_id?: string | number;
  include_user?: boolean;
  include_submission_comment?: boolean;
  max_comment_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const include: string[] = [];
  if (args.include_submission_comment !== false) include.push('submission_comments');
  if (args.include_user !== false) include.push('user');
  const param = include.length > 0 ? { 'include[]': include } : undefined;
  const [self, assignment, submission, peerReview] = await Promise.all([
    safe(() => canvasGet('/users/self')),
    safe(() => canvasGet(`/courses/${id}/assignments/${args.assignment_id}`)),
    safe(() => canvasGet(`/courses/${id}/assignments/${args.assignment_id}/submissions/self`, { 'include[]': ['submission_comments'] })),
    safe(() => canvasPaginate<any>(`/courses/${id}/assignments/${args.assignment_id}/peer_reviews`, param)),
  ]);
  const userId = (self.value as any)?.id ? String((self.value as any).id) : null;
  const submissionValue = submission.value as any;
  const submissionId = args.submission_id ?? submissionValue?.id ?? null;
  const submissionPeerReview = submissionId
    ? await safe(() => canvasPaginate<any>(`/courses/${id}/assignments/${args.assignment_id}/submissions/${submissionId}/peer_reviews`, param))
    : { value: null, error: 'submission id unavailable; submission peer review skipped' };
  const maxCommentChar = Number(args.max_comment_chars ?? 240);
  const peerReviewValue = ((peerReview.value as any[]) ?? []).map((one) => compactPeerReview(one, maxCommentChar));
  const submissionPeerReviewValue = ((submissionPeerReview.value as any[]) ?? []).map((one) => compactPeerReview(one, maxCommentChar));
  const assignedPeerReview = userId
    ? peerReviewValue.filter((one: any) => String(one.assessor_id ?? '') === userId)
    : [];
  const receivedPeerReview = userId
    ? peerReviewValue.filter((one: any) => String(one.user_id ?? '') === userId)
    : [];
  const incompleteAssignedPeerReview = assignedPeerReview.filter((one: any) => one.workflow_state !== 'completed');

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    assignment_id: String(args.assignment_id),
    current_user_id: userId,
    assignment: compactAssignmentLike(assignment.value),
    submission: {
      submission_id: submissionId ? String(submissionId) : null,
      status: submission.error ? endpointStatus(submission.error) : 'ok',
      state: submissionState(submission.value),
      error: submission.error,
    },
    peer_review_status: peerReview.error ? endpointStatus(peerReview.error) : 'ok',
    peer_review_count: peerReviewValue.length,
    peer_review: peerReviewValue,
    submission_peer_review_status: submissionPeerReview.error ? endpointStatus(submissionPeerReview.error) : 'ok',
    submission_peer_review_count: submissionPeerReviewValue.length,
    submission_peer_review: submissionPeerReviewValue,
    assigned_peer_review_count: assignedPeerReview.length,
    assigned_peer_review: assignedPeerReview,
    incomplete_assigned_peer_review_count: incompleteAssignedPeerReview.length,
    received_peer_review_count: receivedPeerReview.length,
    received_peer_review: receivedPeerReview,
    include: {
      user: args.include_user !== false,
      submission_comment: args.include_submission_comment !== false,
    },
    endpoint: [
      ['user_self', self],
      ['assignment', assignment],
      ['submission_self', submission],
      ['peer_review', peerReview],
      ['submission_peer_review', submissionPeerReview],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
  };
}

async function getDiscussionContext(args: {
  course_id?: string | number;
  discussion_id: string | number;
  include_entry_body?: boolean;
  max_entry?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const [topic, view, self] = await Promise.all([
    canvasGet(`/courses/${id}/discussion_topics/${args.discussion_id}`),
    safe(() => canvasGet(`/courses/${id}/discussion_topics/${args.discussion_id}/view`)),
    safe(() => canvasGet('/users/self')),
  ]);
  const userId = (self.value as any)?.id ?? null;
  const rootEntry = Array.isArray((view.value as any)?.view) ? (view.value as any).view : [];
  const entry = flattenDiscussionEntry(rootEntry);
  const myEntry = userId === null ? [] : entry.filter((one: any) => Number(one?.user_id) === Number(userId));
  const myLastAt = myEntry
    .map((one: any) => one?.created_at)
    .filter(Boolean)
    .sort()
    .at(-1) ?? null;
  const otherEntryAfterMyLastPost = myLastAt
    ? entry.filter((one: any) => Number(one?.user_id) !== Number(userId) && String(one?.created_at ?? '') > myLastAt)
    : [];
  const unreadEntryId = Array.isArray((view.value as any)?.unread_entries) ? (view.value as any).unread_entries : [];
  const maxEntry = Math.max(0, Number(args.max_entry ?? 50));
  const maxChar = Number(args.max_chars ?? 400);

  const requirement = mergeRequirement(
    requirementFromCanvas({ is_require_initial_post: !!(topic as any)?.require_initial_post }),
    requirementFromPrompt(`${(topic as any)?.title ?? ''} ${(topic as any)?.message ?? ''}`),
  ).map((one) => meetRequirement(one, userId === null ? null : {
    my_top_level_post_count: myEntry.filter((entry: any) => entry?.parent_id == null).length,
    my_reply_count: myEntry.filter((entry: any) => entry?.parent_id != null).length,
  }));

  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    topic,
    view_status: view.error ? endpointStatus(view.error) : 'ok',
    view_error: view.error,
    participant_count: Array.isArray((view.value as any)?.participants) ? (view.value as any).participants.length : null,
    entry_count: entry.length,
    top_level_entry_count: rootEntry.length,
    reply_count: entry.filter((one: any) => one?.parent_id != null).length,
    unread_entry_count: unreadEntryId.length,
    my_entry_count: myEntry.length,
    my_top_level_post_count: myEntry.filter((one: any) => one?.parent_id == null).length,
    my_reply_count: myEntry.filter((one: any) => one?.parent_id != null).length,
    my_first_post_at: myEntry.map((one: any) => one?.created_at).filter(Boolean).sort()[0] ?? null,
    my_last_post_at: myLastAt,
    other_entry_after_my_last_post_count: otherEntryAfterMyLastPost.length,
    requirement,
    unmet_requirement: requirement.filter((one) => one.is_met === false),
    entry: limitRow(entry, maxEntry).map((one: any) => compactDiscussionEntry(one, !!args.include_entry_body, maxChar)),
  };
}

async function getCourseRequirementGraph(args: {
  course_id?: string | number;
  include_view?: boolean;
  max_discussion_view?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeView = args.include_view !== false;
  const maxView = Math.max(0, Number(args.max_discussion_view ?? 20));
  const [discussionResult, assignmentResult, quizResult, announcementResult, pageResult, self] = await Promise.all([
    safe(() => canvasPaginate(`/courses/${id}/discussion_topics`)),
    safe(() => canvasPaginate(`/courses/${id}/assignments`)),
    safe(() => canvasPaginate(`/courses/${id}/quizzes`)),
    safe(() => canvasPaginate('/announcements', { 'context_codes[]': `course_${id}` })),
    safe(() => canvasGet(`/courses/${id}/pages`, { per_page: '20', 'include[]': 'body' })),
    safe(() => canvasGet('/users/self')),
  ]);
  const userId = (self.value as any)?.id ?? null;
  const row: Record<string, unknown>[] = [];
  let viewCount = 0;

  for (const topic of asArray(discussionResult.value)) {
    const hit = mergeRequirement(
      requirementFromCanvas({ is_require_initial_post: !!topic?.require_initial_post }),
      requirementFromPrompt(`${topic?.title ?? ''} ${topic?.message ?? ''}`),
    );
    if (!hit.length) continue;
    const wantsView = includeView && viewCount < maxView && userId !== null && hit.some((one) => (
      one.requirement_kind === 'initial_post'
      || one.requirement_kind === 'peer_reply'
      || one.requirement_kind === 'comment'
      || one.requirement_kind === 'feedback'
      || one.requirement_kind === 'attendance'
    ));
    let progress: { my_top_level_post_count: number; my_reply_count: number } | null = null;
    let viewStatus = 'skipped';
    if (wantsView) {
      viewCount += 1;
      const view = await safe(() => canvasGet(`/courses/${id}/discussion_topics/${topic.id}/view`));
      viewStatus = view.error ? endpointStatus(view.error) : 'ok';
      if (!view.error) {
        const entry = flattenDiscussionEntry(asArray((view.value as any)?.view));
        const mine = entry.filter((one: any) => Number(one?.user_id) === Number(userId));
        progress = {
          my_top_level_post_count: mine.filter((one: any) => one?.parent_id == null).length,
          my_reply_count: mine.filter((one: any) => one?.parent_id != null).length,
        };
      }
    }
    const requirement = hit.map((one) => meetRequirement(one, progress));
    row.push({
      source: 'discussion',
      source_id: topic?.id ?? null,
      title: topic?.title ?? null,
      url: topic?.html_url ?? null,
      view_status: viewStatus,
      requirement,
      unmet_requirement: requirement.filter((one) => one.is_met === false),
    });
  }

  for (const assignment of asArray(assignmentResult.value)) {
    const toolUrl = String(assignment?.external_tool_tag_attributes?.url ?? assignment?.url ?? '');
    const hit = mergeRequirement(
      requirementFromCanvas({
        is_lockdown_browser: /lockdown|respondus/i.test(toolUrl),
      }),
      requirementFromPrompt(`${assignment?.name ?? ''} ${assignment?.description ?? ''} ${toolUrl}`),
    );
    if (!hit.length) continue;
    const requirement = hit.map((one) => meetRequirement(one, null));
    row.push({
      source: 'assignment',
      source_id: assignment?.id ?? null,
      title: assignment?.name ?? null,
      url: assignment?.html_url ?? null,
      due_at: assignment?.due_at ?? null,
      requirement,
      unmet_requirement: requirement.filter((one) => one.is_met === false),
    });
  }

  for (const quiz of asArray(quizResult.value)) {
    const hit = mergeRequirement(
      requirementFromCanvas({ is_lockdown_browser: !!quiz?.require_lockdown_browser }),
      requirementFromPrompt(`${quiz?.title ?? ''} ${quiz?.description ?? ''}`),
    );
    if (!hit.length) continue;
    const requirement = hit.map((one) => meetRequirement(one, null));
    row.push({
      source: 'quiz',
      source_id: quiz?.id ?? null,
      title: quiz?.title ?? null,
      url: quiz?.html_url ?? null,
      requirement,
      unmet_requirement: requirement.filter((one) => one.is_met === false),
    });
  }

  for (const page of asArray(pageResult.value)) {
    const hit = requirementFromPrompt(`${page?.title ?? ''} ${page?.body ?? ''}`);
    if (!hit.length) continue;
    const requirement = hit.map((one) => meetRequirement(one, null));
    row.push({
      source: 'page',
      source_id: page?.page_id ?? page?.url ?? null,
      title: page?.title ?? null,
      url: page?.html_url ?? null,
      requirement,
      unmet_requirement: requirement.filter((one) => one.is_met === false),
    });
  }

  for (const announcement of asArray(announcementResult.value)) {
    const hit = requirementFromPrompt(`${announcement?.title ?? ''} ${announcement?.message ?? ''}`);
    if (!hit.length) continue;
    const requirement = hit.map((one) => meetRequirement(one, null));
    row.push({
      source: 'announcement',
      source_id: announcement?.id ?? null,
      title: announcement?.title ?? null,
      url: announcement?.html_url ?? null,
      requirement,
      unmet_requirement: requirement.filter((one) => one.is_met === false),
    });
  }

  const requirement = row.flatMap((one) => asArray(one.requirement));
  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    discussion_status: discussionResult.error ? endpointStatus(discussionResult.error) : 'ok',
    assignment_status: assignmentResult.error ? endpointStatus(assignmentResult.error) : 'ok',
    quiz_status: quizResult.error ? endpointStatus(quizResult.error) : 'ok',
    announcement_status: announcementResult.error ? endpointStatus(announcementResult.error) : 'ok',
    page_status: pageResult.error ? endpointStatus(pageResult.error) : 'ok',
    discussion_view_count: viewCount,
    discussion_view_cap: maxView,
    item: row,
    unmet_requirement: requirement.filter((one: any) => one.is_met === false),
    unknown_requirement: requirement.filter((one: any) => one.is_met === null),
    requirement_count: requirement.length,
  };
}

async function getModuleItemContext(args: {
  course_id?: string | number;
  module_id?: string | number;
  item_id: string | number;
  extract_file?: boolean;
  include_assignment_context?: boolean;
  include_discussion_context?: boolean;
  include_sequence?: boolean;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const item = args.module_id
    ? await canvasGet(`/courses/${id}/modules/${args.module_id}/items/${args.item_id}`) as any
    : await canvasGet(`/courses/${id}/modules/items/${args.item_id}`) as any;
  const maxChar = Number(args.max_chars ?? 1200);
  const includeSequence = args.include_sequence !== false;
  const type = String(item?.type ?? '').toLowerCase();
  const contentId = item?.content_id ?? item?.contentId ?? null;
  const pageUrl = item?.page_url ?? item?.url?.match(/\/pages\/([^/?#]+)/)?.[1] ?? null;
  const link = [item?.html_url, item?.url, item?.external_url].filter(Boolean).map((url: string) => ({
    kind: classify(url),
    url,
    source: { type: 'module_item', id: item?.id, title: item?.title },
  }));

  const response = async (): Promise<Record<string, unknown>> => {
    if (type === 'assignment' && contentId) {
      const target = args.include_assignment_context
        ? await getAssignmentContext({
          course_id: id,
          assignment_id: contentId,
          extract_attachment: args.extract_file,
          extract_submission_attachment: args.extract_file,
          max_chars: maxChar,
        })
        : await canvasGet(`/courses/${id}/assignments/${contentId}`);
      return { target_kind: 'assignment', resolution_status: 'ok', target };
    }
    if (type === 'page' && pageUrl) {
      const target = await canvasGet(`/courses/${id}/pages/${encodeURIComponent(pageUrl)}`);
      return {
        target_kind: 'page',
        resolution_status: 'ok',
        target,
        link: extractEmbeds((target as any)?.body, { type: 'page', id: pageUrl, title: (target as any)?.title }),
      };
    }
    if (type === 'file' && contentId) {
      const target = args.extract_file
        ? await extractFileText({ file_id: contentId, max_chars: maxChar })
        : await canvasGet(`/files/${contentId}`);
      return {
        target_kind: 'file',
        resolution_status: 'ok',
        target,
        extraction_mode: (target as any)?.extraction ?? 'metadata-only',
        link: (target as any)?.link ?? [],
      };
    }
    if (type === 'discussion' && contentId) {
      const target = args.include_discussion_context
        ? await getDiscussionContext({
          course_id: id,
          discussion_id: contentId,
          include_entry_body: true,
          max_chars: maxChar,
        })
        : await canvasGet(`/courses/${id}/discussion_topics/${contentId}`);
      return { target_kind: 'discussion', resolution_status: 'ok', target };
    }
    if (type === 'quiz' && contentId) {
      const target = await canvasGet(`/courses/${id}/quizzes/${contentId}`);
      return { target_kind: 'quiz', resolution_status: 'ok', target };
    }
    if (['externalurl', 'externaltool'].includes(type)) {
      return {
        target_kind: type === 'externaltool' ? 'external_tool' : 'external_url',
        resolution_status: 'link_only',
        reason: 'External module targets are returned as links only; this MCP does not bypass LTI or third-party permissions.',
        target: null,
      };
    }
    if (type === 'subheader') {
      return {
        target_kind: 'subheader',
        resolution_status: 'skipped',
        reason: 'SubHeader module items do not have a Canvas content target.',
        target: null,
      };
    }
    return {
      target_kind: item?.type ?? 'unknown',
      resolution_status: 'unsupported',
      reason: 'No read-only resolver branch matched this module item type.',
      target: null,
    };
  };

  const resolved = await response();
  const sequence = includeSequence
    ? await safe(() => canvasGet(`/courses/${id}/module_item_sequence`, {
      asset_type: 'ModuleItem',
      asset_id: args.item_id,
    }))
    : { value: null, error: 'include_sequence false; module item sequence skipped' };
  const sequenceValue = compactModuleItemSequence(sequence.value);
  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    module_id: args.module_id ? String(args.module_id) : item?.module_id ?? null,
    item_id: String(args.item_id),
    module_item: item,
    sequence_status: sequence.error?.includes('include_sequence false')
      ? 'skipped'
      : (sequence.error ? endpointStatus(sequence.error) : 'ok'),
    previous_item: sequenceValue.previous_item,
    current_item: sequenceValue.current_item,
    next_item: sequenceValue.next_item,
    mastery_path: sequenceValue.mastery_path,
    sequence_key: sequenceValue.key,
    sequence: sequence.value,
    sequence_error: sequence.error,
    link,
    ...resolved,
  };
}

async function getCourseExternalToolContext(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  include_parent?: boolean;
  include_tool_detail?: boolean;
  include_sessionless_launch?: boolean;
  max_tool?: number;
  max_module_item?: number;
  max_tab?: number;
  max_launch?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeParent = args.include_parent !== false;
  const includeToolDetail = args.include_tool_detail !== false;
  const includeLaunch = !!args.include_sessionless_launch;
  const maxTool = Math.max(0, Number(args.max_tool ?? 80));
  const maxModuleItem = Math.max(0, Number(args.max_module_item ?? 80));
  const maxTab = Math.max(0, Number(args.max_tab ?? 50));
  const maxLaunch = Math.max(0, Number(args.max_launch ?? 10));
  const maxChar = Number(args.max_chars ?? 600);

  const [externalTool, courseTab, module] = await Promise.all([
    safe(() => canvasPaginate<any>(`/courses/${id}/external_tools`, { include_parents: includeParent })),
    safe(() => canvasPaginate<any>(`/courses/${id}/tabs`)),
    safe(() => canvasPaginate<any>(`/courses/${id}/modules`, { 'include[]': ['items', 'content_details'] })),
  ]);
  const toolValue = limitRow((externalTool.value as any[]) ?? [], maxTool);
  const tabValue = limitRow(((courseTab.value as any[]) ?? [])
    .filter((one: any) => /external/i.test(String(one?.type ?? one?.id ?? ''))), maxTab);
  const moduleExternalToolValue = limitRow(((module.value as any[]) ?? []).flatMap((one: any) => (
    Array.isArray(one?.items)
      ? one.items
        .filter((item: any) => String(item?.type ?? '').toLowerCase() === 'externaltool')
        .map((item: any) => compactExternalToolModuleItem(item, one))
      : []
  )), maxModuleItem);

  const toolDetail = includeToolDetail
    ? await pool(toolValue, async (one: any) => {
      const toolId = one?.id ?? null;
      if (!toolId) return { external_tool_id: null, value: null, error: 'external tool id unavailable' };
      const result = await safe(() => canvasGet(`/courses/${id}/external_tools/${toolId}`));
      return { external_tool_id: toolId, value: result.value, error: result.error };
    })
    : [];

  const moduleLaunchTarget = includeLaunch
    ? limitRow(moduleExternalToolValue, maxLaunch).map((one: any) => ({
      source_type: 'module_item',
      module_item_id: one.module_item_id,
      title: one.title,
      param: { launch_type: 'module_item', module_item_id: one.module_item_id },
    }))
    : [];
  const assignmentLaunchTarget = includeLaunch && args.assignment_id
    ? [{
      source_type: 'assignment',
      assignment_id: String(args.assignment_id),
      title: null,
      param: { launch_type: 'assessment', assignment_id: String(args.assignment_id) },
    }]
    : [];
  const launch = await pool([...moduleLaunchTarget, ...assignmentLaunchTarget], async (one: any) => {
    const result = await safe(() => canvasGet(`/courses/${id}/external_tools/sessionless_launch`, one.param));
    return {
      source_type: one.source_type,
      module_item_id: one.module_item_id ?? null,
      assignment_id: one.assignment_id ?? null,
      title: one.title ?? null,
      status: result.error ? endpointStatus(result.error) : 'ok',
      response: result.value ? compactSessionlessLaunch(result.value) : null,
      error: result.error,
    };
  });

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    include_parent: includeParent,
    include_tool_detail: includeToolDetail,
    include_sessionless_launch: includeLaunch,
    endpoint: [
      ['external_tool', externalTool],
      ['course_tab', courseTab],
      ['course_module', module],
      ...toolDetail.map((one: any) => [`external_tool_detail:${one.external_tool_id}`, { value: one.value, error: one.error }]),
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    external_tool_status: externalTool.error ? endpointStatus(externalTool.error) : 'ok',
    external_tool_count: rowCount(externalTool.value),
    returned_external_tool_count: toolValue.length,
    external_tool: toolValue.map((one: any) => compactExternalTool(one, maxChar)),
    external_tool_detail_count: toolDetail.filter((one: any) => one.value).length,
    external_tool_detail: toolDetail.map((one: any) => ({
      external_tool_id: one.external_tool_id,
      status: one.error ? endpointStatus(one.error) : 'ok',
      tool: one.value ? compactExternalTool(one.value, maxChar) : null,
      error: one.error,
    })),
    tool_tab_status: courseTab.error ? endpointStatus(courseTab.error) : 'ok',
    tool_tab_count: tabValue.length,
    tool_tab: tabValue.map(compactTab),
    module_external_tool_status: module.error ? endpointStatus(module.error) : 'ok',
    module_external_tool_count: moduleExternalToolValue.length,
    module_external_tool: moduleExternalToolValue,
    launch_status: includeLaunch ? (launch.some((one: any) => one.status === 'error') ? 'error' : 'ok') : 'skipped',
    launch_count: launch.length,
    launch,
    note: 'External tool context maps Canvas-visible LTI surfaces only. It does not fetch third-party content, submit work, or bypass LTI permissions.',
  };
}

async function getCourseQuizLtiContext(args: {
  course_id?: string | number;
  assignment_id?: string | number;
  include_item?: boolean;
  max_quiz?: number;
  max_item?: number;
  max_line_item?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const assignmentId = args.assignment_id ? String(args.assignment_id) : null;
  const includeItem = args.include_item !== false;
  const maxQuiz = Math.max(0, Number(args.max_quiz ?? 30));
  const maxItem = Math.max(0, Number(args.max_item ?? 50));
  const maxLineItem = Math.max(0, Number(args.max_line_item ?? 50));
  const maxChar = Math.max(0, Number(args.max_chars ?? 500));

  const [assignment, newQuiz, newQuizDetail, newQuizItem, newQuizOverride, ltiLineItem] = await Promise.all([
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/assignments/${assignmentId}`))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; assignment lookup skipped' }),
    safe(() => canvasApiPaginate<any>(`/api/quiz/v1/courses/${id}/quizzes`)),
    assignmentId
      ? safe(() => canvasApiGet(`/api/quiz/v1/courses/${id}/quizzes/${assignmentId}`))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; New Quiz detail skipped' }),
    assignmentId && includeItem
      ? safe(() => canvasApiPaginate<any>(`/api/quiz/v1/courses/${id}/quizzes/${assignmentId}/items`))
      : Promise.resolve({ value: null, error: includeItem ? 'assignment_id not provided; New Quiz item skipped' : 'include_item false; New Quiz item skipped' }),
    assignmentId
      ? safe(() => canvasGet(`/courses/${id}/new_quizzes/assignment_overrides`, {
        'quiz_assignment_overrides[][quiz_ids][]': assignmentId,
      }))
      : Promise.resolve({ value: null, error: 'assignment_id not provided; New Quiz override skipped' }),
    safe(() => canvasApiPaginate<any>(`/api/lti/courses/${id}/line_items`)),
  ]);

  const newQuizValue = limitRow((newQuiz.value as any[]) ?? [], maxQuiz);
  const rawItem = newQuizItem.value as any;
  const itemSource = Array.isArray(rawItem)
    ? rawItem
    : Array.isArray(rawItem?.items)
      ? rawItem.items
      : rawItem
        ? [rawItem]
        : [];
  const newQuizItemValue = limitRow(itemSource, maxItem);
  const lineItemValue = limitRow((ltiLineItem.value as any[]) ?? [], maxLineItem);
  const newQuizOverrideValue = Array.isArray((newQuizOverride.value as any)?.quiz_assignment_overrides)
    ? (newQuizOverride.value as any).quiz_assignment_overrides
    : [];
  const assignmentValue = assignment.value as any;
  const detailValue = newQuizDetail.value as any;
  const selectedNewQuiz = detailValue ?? newQuizValue.find((one: any) => String(one?.id) === String(assignmentId) || String(one?.assignment_id) === String(assignmentId)) ?? null;
  const isAmbiguousTool = !!assignmentValue && (
    assignmentValue.submission_types?.includes?.('external_tool') ||
    assignmentValue.submission_types?.includes?.('online_quiz') ||
    assignmentValue.quiz_lti ||
    assignmentValue.external_tool_tag_attributes
  );

  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    assignment_id: assignmentId,
    endpoint: [
      ['assignment', assignment],
      ['new_quiz', newQuiz],
      ['new_quiz_detail', newQuizDetail],
      ['new_quiz_item', newQuizItem],
      ['new_quiz_assignment_override', newQuizOverride],
      ['lti_line_item', ltiLineItem],
    ].map(([name, result]) => {
      const one = result as { value: unknown; error: string | null };
      return {
        name,
        status: one.error?.includes('skipped') || one.error?.includes('not provided') || one.error?.includes('include_item false') ? 'skipped' : endpointStatus(one.error),
        count: rowCount(one.value),
        key: keySample(one.value),
        error: one.error,
      };
    }),
    assignment_status: assignment.error?.includes('not provided') ? 'skipped' : (assignment.error ? endpointStatus(assignment.error) : 'ok'),
    assignment: assignmentValue ? compactAssignmentLike(assignmentValue) : null,
    submission_type: assignmentValue?.submission_types ?? [],
    external_tool_tag: assignmentValue?.external_tool_tag_attributes ? {
      url: assignmentValue.external_tool_tag_attributes.url ?? null,
      content_id: assignmentValue.external_tool_tag_attributes.content_id ?? null,
      external_tool_id: assignmentValue.external_tool_tag_attributes.external_tool_id ?? null,
      new_tab: assignmentValue.external_tool_tag_attributes.new_tab ?? null,
    } : null,
    new_quiz_status: newQuiz.error ? endpointStatus(newQuiz.error) : 'ok',
    new_quiz_count: rowCount(newQuiz.value),
    returned_new_quiz_count: newQuizValue.length,
    new_quiz: newQuizValue.map((one: any) => compactNewQuiz(one, maxChar)),
    new_quiz_detail_status: newQuizDetail.error?.includes('not provided') ? 'skipped' : (newQuizDetail.error ? endpointStatus(newQuizDetail.error) : 'ok'),
    new_quiz_detail: selectedNewQuiz ? compactNewQuiz(selectedNewQuiz, maxChar) : null,
    new_quiz_item_status: newQuizItem.error?.includes('skipped') || newQuizItem.error?.includes('not provided') || newQuizItem.error?.includes('include_item false')
      ? 'skipped'
      : (newQuizItem.error ? endpointStatus(newQuizItem.error) : 'ok'),
    new_quiz_item_count: rowCount(newQuizItem.value),
    returned_new_quiz_item_count: newQuizItemValue.length,
    new_quiz_item: newQuizItemValue.map((one: any) => compactNewQuizItem(one, maxChar)),
    new_quiz_override_status: newQuizOverride.error?.includes('skipped') || newQuizOverride.error?.includes('not provided')
      ? 'skipped'
      : (newQuizOverride.error ? endpointStatus(newQuizOverride.error) : 'ok'),
    new_quiz_override_count: newQuizOverrideValue.length,
    new_quiz_override: newQuizOverrideValue.map(compactQuizAssignmentOverride),
    new_quiz_override_error: newQuizOverride.error,
    lti_line_item_status: ltiLineItem.error ? endpointStatus(ltiLineItem.error) : 'ok',
    lti_line_item_count: rowCount(ltiLineItem.value),
    returned_lti_line_item_count: lineItemValue.length,
    lti_line_item: lineItemValue.map((one: any) => compactLtiLineItem(one, maxChar)),
    is_quiz_lti_ambiguous: isAmbiguousTool && (newQuizDetail.error || newQuizItem.error || ltiLineItem.error) ? true : false,
    ambiguity_reason: isAmbiguousTool && (newQuizDetail.error || newQuizItem.error || ltiLineItem.error)
      ? 'Assignment uses online_quiz or external_tool surfaces, but at least one New Quiz/LTI internal endpoint is not readable by this PAT. Treat submission classification as UI-verification-needed unless submissions/self proves completion.'
      : null,
    note: 'Quiz/LTI context is read-only. It reports Canvas-visible New Quiz and LTI line-item status without fetching third-party tools, launching LTI, submitting work, or treating blocked internals as completion proof.',
  };
}

async function getQuizContext(args: {
  course_id?: string | number;
  quiz_id?: string | number;
  include_question?: boolean;
  include_submission_event?: boolean;
  include_submission_time?: boolean;
  include_submission_list?: boolean;
  include_submission_question?: boolean;
  include_report_statistic?: boolean;
  include_ip_filter?: boolean;
  include_question_group?: boolean;
  question_group_id?: string | number;
  max_question?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const includeQuestion = args.include_question !== false;
  const includeQuestionGroup = args.include_question_group !== false;
  const includeSubmissionQuestion = args.include_submission_question !== false;
  const includeSubmissionTime = args.include_submission_time !== false;
  const includeSubmissionList = args.include_submission_list !== false;
  const includeReportStatistic = args.include_report_statistic !== false;
  const includeIpFilter = args.include_ip_filter !== false;
  const maxQuestion = Math.max(0, Number(args.max_question ?? 50));
  const quizList = await safe(() => canvasPaginate<any>(`/courses/${id}/quizzes`));
  const quizValue = (quizList.value as any[]) ?? [];
  const selected = (() => {
    if (args.quiz_id) return quizValue.find((one: any) => String(one?.id) === String(args.quiz_id)) ?? { id: args.quiz_id };
    return quizValue[0] ?? null;
  })();

  if (!selected?.id) {
    return {
      course_id: id,
      generated_at: new Date().toISOString(),
      resolution_status: 'skipped',
      reason: quizList.error ? `quiz list blocked: ${quizList.error}` : 'no Classic Quiz visible in selected course',
      quiz_list_status: quizList.error ? endpointStatus(quizList.error) : 'ok',
      quiz_count: quizValue.length,
      quiz_list_error: quizList.error,
    };
  }

  const quizIdValue = String(selected.id);
  const [quiz, question, questionGroup, submission, submissionList, assignment, override, ipFilter, report, statistic] = await Promise.all([
    safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}`)),
    includeQuestion
      ? safe(() => canvasPaginate<any>(`/courses/${id}/quizzes/${quizIdValue}/questions`))
      : Promise.resolve({ value: null, error: null }),
    includeQuestionGroup
      ? safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/groups`))
      : Promise.resolve({ value: null, error: 'include_question_group false; question group skipped' }),
    safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/submission`, { 'include[]': ['submission', 'quiz', 'user'] })),
    includeSubmissionList
      ? safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/submissions`, { 'include[]': ['submission', 'quiz', 'user'] }))
      : Promise.resolve({ value: null, error: 'include_submission_list false; submission list skipped' }),
    selected?.assignment_id
      ? safe(() => canvasGet(`/courses/${id}/assignments/${selected.assignment_id}`))
      : Promise.resolve({ value: null, error: null }),
    safe(() => canvasGet(`/courses/${id}/quizzes/assignment_overrides`, {
      'quiz_assignment_overrides[][quiz_ids][]': quizIdValue,
    })),
    includeIpFilter
      ? safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/ip_filters`))
      : Promise.resolve({ value: null, error: 'include_ip_filter false; ip filter skipped' }),
    includeReportStatistic
      ? safe(() => canvasPaginate<any>(`/courses/${id}/quizzes/${quizIdValue}/reports`))
      : Promise.resolve({ value: null, error: 'include_report_statistic false; report skipped' }),
    includeReportStatistic
      ? safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/statistics`, { all_versions: true }))
      : Promise.resolve({ value: null, error: 'include_report_statistic false; statistic skipped' }),
  ]);
  const quizRow = quiz.value ?? selected;
  const compactSubmission = compactQuizSubmission(submission.value);
  const submissionId = compactSubmission?.quiz_submission_id ?? null;
  const [event, submissionQuestion, submissionTime] = await Promise.all([
    args.include_submission_event && submissionId
      ? safe(() => canvasPaginate<any>(`/courses/${id}/quizzes/${quizIdValue}/submissions/${submissionId}/events`))
      : Promise.resolve({ value: null, error: args.include_submission_event ? 'quiz submission id unavailable; events skipped' : null }),
    includeSubmissionQuestion && submissionId
      ? safe(() => canvasPaginate<any>(`/quiz_submissions/${submissionId}/questions`, { 'include[]': 'quiz_question' }))
      : Promise.resolve({ value: null, error: includeSubmissionQuestion ? 'quiz submission id unavailable; submission questions skipped' : 'include_submission_question false; submission questions skipped' }),
    includeSubmissionTime && submissionId
      ? safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/submissions/${submissionId}/time`))
      : Promise.resolve({ value: null, error: includeSubmissionTime ? 'quiz submission id unavailable; submission time skipped' : 'include_submission_time false; submission time skipped' }),
  ]);
  const questionValue = limitRow((question.value as any[]) ?? [], maxQuestion);
  const questionGroupValue = limitRow(unwrapCanvasArray(questionGroup.value, 'quiz_groups'), maxQuestion);
  const requestedQuestionGroupId = args.question_group_id ? String(args.question_group_id) : null;
  const selectedQuestionGroup = requestedQuestionGroupId
    ? questionGroupValue.find((one: any) => String(one?.id ?? '') === requestedQuestionGroupId) ?? { id: requestedQuestionGroupId }
    : questionGroupValue.find((one: any) => one?.id) ?? null;
  const questionGroupDetail = selectedQuestionGroup?.id && includeQuestionGroup
    ? await safe(() => canvasGet(`/courses/${id}/quizzes/${quizIdValue}/groups/${selectedQuestionGroup.id}`))
    : { value: null, error: selectedQuestionGroup?.id ? 'include_question_group false; question group detail skipped' : 'no quiz question group visible; question group detail skipped' };
  const overrideValue = Array.isArray((override.value as any)?.quiz_assignment_overrides)
    ? (override.value as any).quiz_assignment_overrides
    : [];
  const ipFilterValue = unwrapCanvasArray(ipFilter.value, 'quiz_ip_filters');
  const reportValue = (report.value as any[]) ?? [];
  const submissionListValue = quizSubmissionList(submissionList.value);
  const submissionQuestionValue = limitRow((submissionQuestion.value as any[]) ?? [], maxQuestion);
  const quizLink = extractEmbeds((quizRow as any)?.description, { type: 'quiz', id: quizIdValue, title: (quizRow as any)?.title });
  const questionLink = questionValue.flatMap((one: any) => extractEmbeds(one?.question_text, { type: 'quiz-question', id: one?.id, title: (quizRow as any)?.title }));

  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    resolution_status: 'ok',
    quiz_list_status: quizList.error ? endpointStatus(quizList.error) : 'ok',
    quiz_count: quizValue.length,
    quiz_id: quizIdValue,
    quiz_status: quiz.error ? endpointStatus(quiz.error) : 'ok',
    quiz: compactQuiz(quizRow),
    assignment_status: assignment.error ? endpointStatus(assignment.error) : (assignment.value ? 'ok' : 'skipped'),
    assignment: assignment.value ? compactAssignmentLike(assignment.value) : null,
    question_status: question.error ? endpointStatus(question.error) : 'ok',
    question_count: rowCount(question.value),
    returned_question_count: questionValue.length,
    question: questionValue.map(compactQuizQuestion),
    question_group_status: questionGroup.error?.includes('include_question_group false') ? 'skipped' : (questionGroup.error ? endpointStatus(questionGroup.error) : 'ok'),
    question_group_count: rowCount(questionGroup.value),
    returned_question_group_count: questionGroupValue.length,
    selected_question_group_id: selectedQuestionGroup?.id ? String(selectedQuestionGroup.id) : null,
    question_group: questionGroupValue.map(compactQuizQuestionGroup),
    question_group_detail_status: questionGroupDetail.error?.includes('no quiz question group visible') || questionGroupDetail.error?.includes('include_question_group false') ? 'skipped' : (questionGroupDetail.error ? endpointStatus(questionGroupDetail.error) : 'ok'),
    question_group_detail: questionGroupDetail.value ? compactQuizQuestionGroup(questionGroupDetail.value) : null,
    question_group_error: questionGroup.error,
    question_group_detail_error: questionGroupDetail.error,
    submission_status: submission.error ? endpointStatus(submission.error) : 'ok',
    submission: compactSubmission,
    submission_error: submission.error,
    submission_list_status: submissionList.error?.includes('include_submission_list false')
      ? 'skipped'
      : (submissionList.error ? endpointStatus(submissionList.error) : 'ok'),
    submission_list_count: rowCount(submissionList.value),
    returned_submission_list_count: submissionListValue.length,
    submission_list: submissionListValue.map(compactQuizSubmission).filter(Boolean),
    submission_list_error: submissionList.error,
    override_status: override.error ? endpointStatus(override.error) : 'ok',
    override_count: overrideValue.length,
    override: overrideValue.map(compactQuizAssignmentOverride),
    override_error: override.error,
    ip_filter_status: ipFilter.error?.includes('include_ip_filter false') ? 'skipped' : (ipFilter.error ? endpointStatus(ipFilter.error) : 'ok'),
    ip_filter_count: ipFilterValue.length,
    ip_filter: ipFilterValue.map(compactQuizIpFilter),
    ip_filter_error: ipFilter.error,
    report_status: report.error?.includes('include_report_statistic false') ? 'skipped' : (report.error ? endpointStatus(report.error) : 'ok'),
    report_count: rowCount(report.value),
    report: reportValue.map(compactQuizReport),
    report_error: report.error,
    statistic_status: statistic.error?.includes('include_report_statistic false') ? 'skipped' : (statistic.error ? endpointStatus(statistic.error) : 'ok'),
    statistic: statistic.value ? compactQuizStatistic(statistic.value) : null,
    statistic_error: statistic.error,
    submission_question_status: submissionQuestion.error?.includes('skipped') || submissionQuestion.error?.includes('include_submission_question false')
      ? 'skipped'
      : (submissionQuestion.error ? endpointStatus(submissionQuestion.error) : 'ok'),
    submission_question_count: rowCount(submissionQuestion.value),
    returned_submission_question_count: submissionQuestionValue.length,
    submission_question: submissionQuestionValue.map(compactQuizSubmissionQuestion),
    submission_question_error: submissionQuestion.error,
    submission_time_status: submissionTime.error?.includes('skipped') || submissionTime.error?.includes('include_submission_time false')
      ? 'skipped'
      : (submissionTime.error ? endpointStatus(submissionTime.error) : 'ok'),
    submission_time: submissionTime.value ? {
      end_at: (submissionTime.value as any)?.end_at ?? null,
      time_left: (submissionTime.value as any)?.time_left ?? null,
    } : null,
    submission_time_error: submissionTime.error,
    event_status: event.error ? endpointStatus(event.error) : (args.include_submission_event ? 'ok' : 'skipped'),
    event_count: rowCount(event.value),
    event: limitRow(((event.value as any[]) ?? []).map((one: any) => ({
      created_at: one?.created_at ?? null,
      event_type: one?.event_type ?? null,
      event_data_key: keySample(one?.event_data),
    })), 100),
    event_error: event.error,
    link: [...quizLink, ...questionLink],
  };
}

async function getLockdownQuizAccess(args: {
  course_id?: string | number;
  include_question_preview?: boolean;
  include_question_text?: boolean;
}): Promise<unknown> {
  const id = courseId(args);
  const includePreview = args.include_question_preview !== false;
  const includeText = args.include_question_text !== false;
  const ACCESS_NOTE =
    'The Lockdown Browser client check guards the web take flow, while quiz metadata, the current-user submission, and its score stay readable through this token without the official client. The question bank is served to a student token only during an active attempt, so a preview here reports what Canvas actually permits rather than a guess. The server never answers or submits; the agent prepares answers for the student.';

  const quizList = await safe(() => canvasPaginate<any>(`/courses/${id}/quizzes`));
  if (quizList.error) {
    return {
      course_id: id,
      generated_at: new Date().toISOString(),
      resolution_status: 'skipped',
      reason: `quiz list blocked: ${quizList.error}`,
      quiz_list_status: endpointStatus(quizList.error),
      access_note: ACCESS_NOTE,
    };
  }
  const all = (quizList.value as any[]) ?? [];
  const flagged = all.filter(
    (one: any) =>
      one?.require_lockdown_browser ||
      one?.require_lockdown_browser_for_monitoring ||
      one?.respondus_lock_down_browser === true,
  );

  const row = await Promise.all(
    flagged.map(async (one: any) => {
      const quizId = String(one.id);
      const submission = await safe(() =>
        canvasGet(`/courses/${id}/quizzes/${quizId}/submission`, { 'include[]': ['submission', 'quiz'] }),
      );
      const submissionValue = compactQuizSubmission(submission.value);
      const submissionId = submissionValue?.quiz_submission_id ?? null;
      const [question, submissionQuestion] = await Promise.all([
        includePreview
          ? safe(() => canvasPaginate<any>(`/courses/${id}/quizzes/${quizId}/questions`))
          : Promise.resolve({ value: null as unknown as any[], error: 'include_question_preview false; question preview skipped' }),
        includePreview && submissionId
          ? safe(() => canvasPaginate<any>(`/quiz_submissions/${submissionId}/questions`, { 'include[]': 'quiz_question' }))
          : Promise.resolve({ value: null as unknown as any[], error: submissionId ? null : 'no submission; submission questions skipped' }),
      ]);
      const questionValue = (question.value as any[]) ?? [];
      const bankBlocked = includePreview && questionValue.length === 0 && !!question.error;
      const submissionQuestionValue = ((submissionQuestion.value as any[]) ?? []).map((one: any) => one?.quiz_question ?? one);
      return {
        quiz_id: quizId,
        title: one?.title ?? null,
        points_possible: one?.points_possible ?? null,
        due_at: one?.due_at ?? null,
        allowed_attempt_count: one?.allowed_attempts ?? null,
        question_count: one?.question_count ?? null,
        is_monitor_required: !!one?.require_lockdown_browser_for_monitoring,
        has_monitor_settings: !!one?.lockdown_browser_monitor_to_settings,
        has_access_code: typeof one?.access_code === 'string' ? one.access_code.length > 0 : null,
        question_readable: includePreview
          ? (questionValue.length > 0 ? 'ok' : (submissionQuestionValue.length > 0 ? 'via_submission' : endpointStatus(question.error)))
          : 'skipped',
        returned_question_count: includePreview ? (questionValue.length || submissionQuestionValue.length) : 0,
        question_source: bankBlocked && submissionQuestionValue.length > 0 ? 'submission' : (questionValue.length > 0 ? 'question_bank' : null),
        question: includePreview
          ? (questionValue.length > 0 ? questionValue : submissionQuestionValue).slice(0, 50).map((item: any) => ({
              question_id: item?.id ?? item?.question_id ?? null,
              position: item?.position ?? null,
              question_type: item?.question_type ?? null,
              points_possible: item?.points_possible ?? null,
              question_text: includeText ? stripHtml(item?.question_text ?? '') : null,
            }))
          : [],
        submission_readable: submission.error ? endpointStatus(submission.error) : (submissionValue ? 'ok' : 'blocked_or_absent'),
        question_note: bankBlocked
          ? 'Canvas serves the question bank to a student token only during an active attempt; metadata and the current-user submission with its score stay readable.'
          : null,
        submission: submissionValue,
        score: submissionValue?.kept_score ?? submissionValue?.score ?? null,
      };
    }),
  );

  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    resolution_status: 'ok',
    quiz_list_status: 'ok',
    quiz_count: all.length,
    lockdown_quiz_count: row.length,
    quiz: row,
    access_note: ACCESS_NOTE,
  };
}

async function getAssignmentContext(args: {
  course_id?: string | number;
  assignment_id: string | number;
  include_history?: boolean;
  extract_attachment?: boolean;
  extract_submission_attachment?: boolean;
  max_submission_attachment?: number;
  max_chars?: number;
}): Promise<unknown> {
  const id = courseId(args);
  const assignment = await canvasGet(`/courses/${id}/assignments/${args.assignment_id}`, {
    'include[]': ['all_dates', 'overrides'],
  }) as any;
  const submission = await safe(() => getMySubmission({
    course_id: id,
    assignment_id: args.assignment_id,
    include_history: args.include_history,
  }));
  const peerReview = await safe(() => canvasPaginate(`/courses/${id}/assignments/${args.assignment_id}/peer_reviews`));
  const assignmentOverride = await safe(() => canvasPaginate(`/courses/${id}/assignments/${args.assignment_id}/overrides`));
  const self = await safe(() => canvasGet('/users/self'));
  const userId = (self.value as any)?.id ? String((self.value as any).id) : null;
  const assignmentGroupMember = userId
    ? await safe(() => canvasPaginate(`/courses/${id}/assignments/${args.assignment_id}/users/${userId}/group_members`))
    : { value: null, error: 'users/self unavailable; assignment group member skipped' };
  const quizSubmission = assignment.quiz_id
    ? await safe(() => canvasGet(`/courses/${id}/quizzes/${assignment.quiz_id}/submission`, { 'include[]': ['submission', 'quiz'] }))
    : { value: null, error: null };
  const outcomeAlignment = userId
    ? await safe(() => canvasPaginate(`/courses/${id}/outcome_alignments`, {
      student_id: userId,
      assignment_id: args.assignment_id,
    }))
    : { value: null, error: 'users/self unavailable; outcome alignment skipped' };
  const fileId = extractFileId(assignment.description);
  const descriptionLink = extractEmbeds(assignment.description, {
    type: 'assignment',
    id: assignment.id,
    title: assignment.name,
  });
  const attachment = await pool(fileId, async (one) => {
    if (!args.extract_attachment) {
      const file = await safe(() => canvasGet(`/files/${one}`));
      return { file_id: one, file: file.value, error: file.error };
    }
    const extracted = await safe(() => extractFileText({ file_id: one, max_chars: args.max_chars ?? 4000 }));
    return { file_id: one, extraction: extracted.value, error: extracted.error };
  }, 4);
  const attachmentLink = attachment.flatMap((one: any) => one.extraction?.link ?? []);
  const submissionAttachmentSource = Array.isArray((submission.value as any)?.attachments)
    ? (submission.value as any).attachments.slice(0, Math.max(0, Number(args.max_submission_attachment ?? 4)))
    : [];
  const submissionAttachment = await pool(submissionAttachmentSource, async (one: any) => {
    const fileIdValue = one?.id ?? one?.file_id ?? null;
    const downloadUrl = one?.url ?? one?.download_url ?? null;
    if (!args.extract_submission_attachment) {
      return {
        file_id: fileIdValue,
        file: one,
        extraction: null,
        error: null,
      };
    }
    const extracted = await safe(() => extractFileText({
      ...(fileIdValue ? { file_id: fileIdValue } : {}),
      ...(downloadUrl ? { download_url: downloadUrl } : {}),
      max_chars: args.max_chars ?? 4000,
    }));
    return {
      file_id: fileIdValue,
      source_file: one,
      extraction: extracted.value,
      error: extracted.error,
    };
  }, 3);
  const submissionAttachmentLink = submissionAttachment.flatMap((one: any) => one.extraction?.link ?? []);
  const allDate = Array.isArray(assignment?.all_dates) ? assignment.all_dates : [];
  const override = (assignmentOverride.value as any[]) ?? [];
  const dateCandidate = [
    ...allDate.map((one: any) => one?.due_at).filter(Boolean),
    ...override.map((one: any) => one?.due_at).filter(Boolean),
    assignment?.due_at,
  ].filter(Boolean);
  const effectiveDueAt = dateCandidate[0] ?? null;

  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    assignment,
    submission: submission.value,
    submission_error: submission.error,
    date_context: {
      effective_due_at: effectiveDueAt,
      base_due_at: assignment?.due_at ?? null,
      unlock_at: assignment?.unlock_at ?? null,
      lock_at: assignment?.lock_at ?? null,
      all_date_status: allDate.length > 0 ? 'ok' : 'empty_or_unavailable',
      all_date_count: allDate.length,
      all_date: allDate.map((one: any) => ({
        due_at: one?.due_at ?? null,
        unlock_at: one?.unlock_at ?? null,
        lock_at: one?.lock_at ?? null,
        title: one?.title ?? one?.base ?? null,
        set_type: one?.set_type ?? null,
        set_id: one?.set_id ?? null,
      })),
      override_status: assignmentOverride.error ? endpointStatus(assignmentOverride.error) : 'ok',
      override_count: override.length,
      override: override.map((one: any) => ({
        assignment_override_id: one?.id ?? null,
        title: one?.title ?? null,
        due_at: one?.due_at ?? null,
        unlock_at: one?.unlock_at ?? null,
        lock_at: one?.lock_at ?? null,
        course_section_id: one?.course_section_id ?? null,
        group_id: one?.group_id ?? null,
        student_id_count: Array.isArray(one?.student_ids) ? one.student_ids.length : null,
      })),
      override_error: assignmentOverride.error,
      source: effectiveDueAt && effectiveDueAt !== assignment?.due_at ? 'override_or_all_date' : 'assignment',
    },
    peer_review: peerReview.value ?? [],
    peer_review_error: peerReview.error,
    group_member_context: {
      status: assignmentGroupMember.error ? endpointStatus(assignmentGroupMember.error) : 'ok',
      member_count: rowCount(assignmentGroupMember.value),
      member: ((assignmentGroupMember.value as any[]) ?? []).map(compactGroupMember),
      error: assignmentGroupMember.error,
    },
    quiz_submission: compactQuizSubmission(quizSubmission.value),
    quiz_submission_error: quizSubmission.error,
    rubric_context: {
      rubric_count: Array.isArray(assignment.rubric) ? assignment.rubric.length : 0,
      rubric: compactRubric(assignment.rubric),
      rubric_settings_key: keySample(assignment.rubric_settings),
    },
    outcome_context: {
      outcome_alignment_status: outcomeAlignment.error ? endpointStatus(outcomeAlignment.error) : 'ok',
      outcome_alignment_count: rowCount(outcomeAlignment.value),
      outcome_alignment: compactOutcomeAlignment(outcomeAlignment.value),
      outcome_alignment_error: outcomeAlignment.error,
    },
    state: submissionState(submission.value),
    file_id: fileId,
    attachment,
    submission_attachment: submissionAttachment,
    link: [...descriptionLink, ...attachmentLink.map((url: string) => ({
      kind: classify(url),
      url,
      source: { type: 'attachment', id: assignment.id, title: assignment.name },
    })), ...submissionAttachmentLink.map((url: string) => ({
      kind: classify(url),
      url,
      source: { type: 'submission_attachment', id: assignment.id, title: assignment.name },
    }))],
  };
}

async function extractFileText(args: { file_id?: string | number; download_url?: string; max_chars?: number }): Promise<unknown> {
  let file: any = null;
  if (args.file_id) file = await canvasGet(`/files/${args.file_id}`);
  const downloadUrl = args.download_url ?? file?.url;
  if (!downloadUrl) throw new Error('No download_url provided and file metadata did not include url');

  const { buffer, contentType } = await canvasDownload(downloadUrl);
  const fileName = String(file?.display_name ?? file?.filename ?? args.file_id ?? 'canvas-file');
  const safeFileName = fileName.replace(/[^a-z0-9._-]+/gi, '_');
  const maxChar = Number(args.max_chars ?? 12000);
  const mime = String(file?.['content-type'] ?? file?.content_type ?? contentType);
  const linkFromText = (text: string): string[] => [...new Set(text.match(RAW_URL_RE) ?? [])];

  if (/pdf/i.test(mime) || /\.pdf$/i.test(fileName)) {
    const dir = await mkdtemp(join(tmpdir(), 'canvas-mcp-'));
    const pdfPath = join(dir, safeFileName.endsWith('.pdf') ? safeFileName : 'file.pdf');
    try {
      await writeFile(pdfPath, buffer);
      const { stdout } = await execFileAsync('pdftotext', ['-layout', '-nopgbrk', pdfPath, '-'], {
        maxBuffer: Math.max(maxChar * 4, 1024 * 1024),
      });
      return {
        file,
        content_type: mime,
        extraction: 'pdf-text',
        text: String(stdout).replace(/\s+/g, ' ').trim().slice(0, maxChar),
        link: linkFromText(String(stdout)),
        truncated: String(stdout).length > maxChar,
      };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  if (/wordprocessingml|officedocument\.wordprocessingml|msword/i.test(mime) || /\.docx$/i.test(fileName)) {
    const dir = await mkdtemp(join(tmpdir(), 'canvas-mcp-'));
    const docxPath = join(dir, safeFileName.endsWith('.docx') ? safeFileName : 'file.docx');
    try {
      await writeFile(docxPath, buffer);
      const { stdout } = await execFileAsync('unzip', ['-p', docxPath, 'word/document.xml'], {
        maxBuffer: Math.max(maxChar * 8, 1024 * 1024),
      });
      const text = String(stdout)
        .replace(/<w:tab\/>/g, ' ')
        .replace(/<\/w:p>/g, '\n')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, ' ')
        .trim();
      return {
        file,
        content_type: mime,
        extraction: 'docx-text',
        text: text.slice(0, maxChar),
        link: linkFromText(text),
        truncated: text.length > maxChar,
      };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  if (/^(text\/|application\/(json|xml|csv)|.*html)/i.test(mime) || /\.(txt|md|csv|json|html?)$/i.test(fileName)) {
    const text = buffer.toString('utf8');
    return {
      file,
      content_type: mime,
      extraction: 'plain-text',
      text: text.slice(0, maxChar),
      link: linkFromText(text),
      truncated: text.length > maxChar,
    };
  }

  if (/^image\/(png|jpe?g|tiff|bmp)$/i.test(mime) || /\.(png|jpe?g|tiff?|bmp)$/i.test(fileName)) {
    const dir = await mkdtemp(join(tmpdir(), 'canvas-mcp-'));
    const imagePath = join(dir, safeFileName || 'file-image');
    try {
      await writeFile(imagePath, buffer);
      const { stdout } = await execFileAsync('tesseract', [imagePath, 'stdout'], {
        maxBuffer: Math.max(maxChar * 4, 1024 * 1024),
      });
      const text = String(stdout).replace(/\s+/g, ' ').trim();
      return {
        file,
        content_type: mime,
        extraction: 'image-ocr',
        text: text.slice(0, maxChar),
        link: linkFromText(text),
        truncated: text.length > maxChar,
      };
    } catch (err: any) {
      if (err?.code !== 'ENOENT') throw err;
      return {
        file,
        content_type: mime,
        extraction: 'unsupported-binary',
        byte_length: buffer.length,
        note: 'Downloaded successfully, but image OCR requires tesseract to be installed.',
      };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  return {
    file,
    content_type: mime,
    extraction: 'unsupported-binary',
    byte_length: buffer.length,
    note: 'Downloaded successfully, but this MCP only extracts text-like files, PDFs, DOCX, and OCR-supported images.',
  };
}

async function resolveCanvasLink(args: {
  url: string;
  extract_file?: boolean;
  include_assignment_context?: boolean;
  include_discussion_context?: boolean;
  max_chars?: number;
}): Promise<unknown> {
  const link = normalizeCanvasLink(args.url);
  if (!link.is_canvas_url) {
    return {
      generated_at: new Date().toISOString(),
      original_url: link.original_url,
      normalized_url: link.normalized_url,
      kind: 'external',
      external_host: link.external_host,
      resolution_status: 'skipped',
      reason: 'resolve_canvas_link only fetches URLs from the configured Canvas host',
    };
  }

  const path = decodeURIComponent(link.path);
  const maxChar = Number(args.max_chars ?? 1200);
  const baseResponse = {
    generated_at: new Date().toISOString(),
    original_url: link.original_url,
    normalized_url: link.normalized_url,
  };

  if (path.startsWith('/api/')) {
    const response = await requestCanvasApi({ path: `${link.path}${link.search}` });
    return { ...baseResponse, kind: 'api', resolution_status: 'ok', response };
  }

  const fileMatch = path.match(/\/files\/(\d+)/);
  if (fileMatch) {
    const fileId = fileMatch[1];
    const file = args.extract_file
      ? await extractFileText({ file_id: fileId, max_chars: maxChar })
      : await canvasGet(`/files/${fileId}`);
    return {
      ...baseResponse,
      kind: 'file',
      resolution_status: 'ok',
      file_id: fileId,
      extraction_mode: (file as any)?.extraction ?? 'metadata-only',
      link: (file as any)?.link ?? [],
      response: file,
    };
  }

  const courseAssignment = path.match(/\/courses\/(\d+)\/assignments\/(\d+)/);
  if (courseAssignment) {
    const [, id, assignmentId] = courseAssignment;
    const response = args.include_assignment_context
      ? await getAssignmentContext({
        course_id: id,
        assignment_id: assignmentId,
        extract_attachment: args.extract_file,
        extract_submission_attachment: args.extract_file,
        max_chars: maxChar,
      })
      : await canvasGet(`/courses/${id}/assignments/${assignmentId}`);
    return {
      ...baseResponse,
      kind: 'assignment',
      resolution_status: 'ok',
      course_id: id,
      assignment_id: assignmentId,
      response,
    };
  }

  const courseDiscussion = path.match(/\/courses\/(\d+)\/discussion_topics\/(\d+)/);
  if (courseDiscussion) {
    const [, id, discussionId] = courseDiscussion;
    const response = args.include_discussion_context
      ? await getDiscussionContext({
        course_id: id,
        discussion_id: discussionId,
        include_entry_body: true,
        max_chars: maxChar,
      })
      : await canvasGet(`/courses/${id}/discussion_topics/${discussionId}`);
    return {
      ...baseResponse,
      kind: 'discussion',
      resolution_status: 'ok',
      course_id: id,
      discussion_id: discussionId,
      link: extractEmbeds((response as any)?.message, { type: 'discussion', id: discussionId, title: (response as any)?.title }),
      response,
    };
  }

  const coursePage = path.match(/\/courses\/(\d+)\/pages\/(.+)$/);
  if (coursePage) {
    const [, id, pageUrl] = coursePage;
    const response = await canvasGet(`/courses/${id}/pages/${encodeURIComponent(pageUrl)}`);
    return {
      ...baseResponse,
      kind: 'page',
      resolution_status: 'ok',
      course_id: id,
      page_url: pageUrl,
      link: extractEmbeds((response as any)?.body, { type: 'page', id: pageUrl, title: (response as any)?.title }),
      response,
    };
  }

  const courseQuiz = path.match(/\/courses\/(\d+)\/quizzes\/(\d+)/);
  if (courseQuiz) {
    const [, id, quizId] = courseQuiz;
    const response = await canvasGet(`/courses/${id}/quizzes/${quizId}`);
    return {
      ...baseResponse,
      kind: 'quiz',
      resolution_status: 'ok',
      course_id: id,
      quiz_id: quizId,
      response,
    };
  }

  const moduleItem = path.match(/\/courses\/(\d+)\/modules\/items\/(\d+)/);
  if (moduleItem) {
    const [, id, itemId] = moduleItem;
    const response = await getModuleItemContext({
      course_id: id,
      item_id: itemId,
      extract_file: args.extract_file,
      include_assignment_context: args.include_assignment_context,
      include_discussion_context: args.include_discussion_context,
      max_chars: maxChar,
    });
    return {
      ...baseResponse,
      kind: 'module_item',
      resolution_status: 'ok',
      course_id: id,
      item_id: itemId,
      response,
    };
  }

  const moduleScopedItem = path.match(/\/courses\/(\d+)\/modules\/(\d+)\/items\/(\d+)/);
  if (moduleScopedItem) {
    const [, id, moduleId, itemId] = moduleScopedItem;
    const response = await getModuleItemContext({
      course_id: id,
      module_id: moduleId,
      item_id: itemId,
      extract_file: args.extract_file,
      include_assignment_context: args.include_assignment_context,
      include_discussion_context: args.include_discussion_context,
      max_chars: maxChar,
    });
    return {
      ...baseResponse,
      kind: 'module_item',
      resolution_status: 'ok',
      course_id: id,
      module_id: moduleId,
      item_id: itemId,
      response,
    };
  }

  const courseHome = path.match(/\/courses\/(\d+)$/);
  if (courseHome) {
    const [, id] = courseHome;
    const response = await canvasGet(`/courses/${id}`, { 'include[]': 'syllabus_body' });
    return {
      ...baseResponse,
      kind: 'course',
      resolution_status: 'ok',
      course_id: id,
      link: extractEmbeds((response as any)?.syllabus_body, { type: 'syllabus', id, title: (response as any)?.name }),
      response,
    };
  }

  return {
    ...baseResponse,
    kind: classify(link.normalized_url),
    resolution_status: 'unsupported',
    reason: 'No read-only resolver branch matched this Canvas URL. Use request_canvas_api for explicit /api/... paths.',
  };
}

const handler: Record<string, (args: any) => Promise<unknown>> = {
  list_course: (args) => canvasPaginate('/courses', courseParam(args ?? {})),
  get_user_self: () => canvasGet('/users/self'),
  get_user_canvas_context: (args) => getUserCanvasContext(args),
  get_user_page_view_context: (args) => getUserPageViewContext(args),
  get_user_file_context: (args) => getUserFileContext(args),
  get_user_eportfolio_context: (args) => getUserEportfolioContext(args),
  get_user_content_share_context: (args) => getUserContentShareContext(args),
  request_canvas_api: (args) => requestCanvasApi(args),
  get_canvas_api_capability: (args) => getCanvasApiCapability(args),
  list_canvas_api_endpoint: () => Promise.resolve(listCanvasApiEndpoint()),
  resolve_canvas_link: (args) => resolveCanvasLink(args),
  get_course: (args) => canvasGet(`/courses/${courseId(args)}`, { 'include[]': 'syllabus_body' }),
  get_course_action_context: (args) => getCourseActionContext(args),
  get_course_planner_context: (args) => getCoursePlannerContext(args),
  get_course_due_date_context: (args) => getCourseDueDateContext(args),
  get_course_outcome_context: (args) => getCourseOutcomeContext(args),
  get_course_assessment_context: (args) => getCourseAssessmentContext(args),
  get_assignment_moderation_context: (args) => getAssignmentModerationContext(args),
  get_course_roster_context: (args) => getCourseRosterContext(args),
  get_course_group_context: (args) => getCourseGroupContext(args),
  get_course_collaboration_context: (args) => getCourseCollaborationContext(args),
  get_course_calendar_context: (args) => getCourseCalendarContext(args),
  get_course_term_context: (args) => getCourseTermContext(args),
  get_course_grade_context: (args) => getCourseGradeContext(args),
  get_course_activity_context: (args) => getCourseActivityContext(args),
  get_course_analytics_context: (args) => getCourseAnalyticsContext(args),
  get_course_material_context: (args) => getCourseMaterialContext(args),
  get_course_syllabus_context: (args) => getCourseSyllabusContext(args),
  get_course_search_context: (args) => getCourseSearchContext(args),
  get_course_media_context: (args) => getCourseMediaContext(args),
  get_course_conference_context: (args) => getCourseConferenceContext(args),
  get_course_export_context: (args) => getCourseExportContext(args),
  get_canvas_progress_context: (args) => getCanvasProgressContext(args),
  get_course_pacing_context: (args) => getCoursePacingContext(args),
  get_course_poll_context: (args) => getCoursePollContext(args),
  get_user_notification_context: (args) => getUserNotificationContext(args),
  get_user_comm_message_context: (args) => getUserCommMessageContext(args),
  get_course_account_context: (args) => getCourseAccountContext(args),
  get_course_brand_context: (args) => getCourseBrandContext(args),
  get_course_account_calendar_context: (args) => getCourseAccountCalendarContext(args),
  get_course_blueprint_context: (args) => getCourseBlueprintContext(args),
  get_course_grading_period_context: (args) => getCourseGradingPeriodContext(args),
  get_course_feature_context: (args) => getCourseFeatureContext(args),
  get_course_module_context: (args) => getCourseModuleContext(args),
  list_module: (args) => canvasPaginate(`/courses/${courseId(args)}/modules`, { 'include[]': 'items' }),
  get_module_item: (args) => canvasGet(`/courses/${courseId(args)}/modules/${args.module_id}/items/${args.item_id}`),
  get_module_item_context: (args) => getModuleItemContext(args),
  get_course_external_tool_context: (args) => getCourseExternalToolContext(args),
  get_course_quiz_lti_context: (args) => getCourseQuizLtiContext(args),
  list_assignment: (args) => canvasPaginate(`/courses/${courseId(args)}/assignments`, args.include_submission ? { 'include[]': 'submission' } : undefined),
  get_assignment: (args) => canvasGet(`/courses/${courseId(args)}/assignments/${args.assignment_id}`),
  get_assignment_context: (args) => getAssignmentContext(args),
  get_peer_review_context: (args) => getPeerReviewContext(args),
  list_announcement: (args) => canvasPaginate(`/announcements`, { 'context_codes[]': `course_${courseId(args)}` }),
  get_course_announcement_context: (args) => getCourseAnnouncementContext(args),
  get_course_feed_context: (args) => getCourseFeedContext(args),
  get_page: (args) => canvasGet(`/courses/${courseId(args)}/pages/${args.page_url}`),
  get_course_page_context: (args) => getCoursePageContext(args),
  list_file: (args) => canvasPaginate(`/courses/${courseId(args)}/files`),
  get_file: (args) => canvasGet(`/files/${args.file_id}`),
  get_course_file_context: (args) => getCourseFileContext(args),
  extract_file_text: (args) => extractFileText(args),
  list_my_submission: (args) => listMySubmissions(args),
  get_my_submission: (args) => getMySubmission(args),
  get_submission_feedback_context: (args) => getSubmissionFeedbackContext(args),
  list_discussion: (args) => canvasPaginate(`/courses/${courseId(args)}/discussion_topics`),
  get_discussion: (args) => canvasGet(`/courses/${courseId(args)}/discussion_topics/${args.discussion_id}`),
  get_discussion_context: (args) => getDiscussionContext(args),
  get_course_requirement_graph: (args) => getCourseRequirementGraph(args),
  list_quiz: (args) => canvasPaginate(`/courses/${courseId(args)}/quizzes`),
  get_quiz: (args) => canvasGet(`/courses/${courseId(args)}/quizzes/${args.quiz_id}`),
  get_quiz_question: (args) => canvasPaginate(`/courses/${courseId(args)}/quizzes/${args.quiz_id}/questions`),
  get_quiz_context: (args) => getQuizContext(args),
  get_lockdown_quiz_access: (args) => getLockdownQuizAccess(args),
  get_lockdown_quiz_take: (args) => getLockdownQuizTake(args),
  get_lockdown_quiz_launch: (args) => getLockdownQuizLaunch(args),
  request_canvas_write: (args) => requestCanvasWrite(args),
  extract_course: (args) => extractCourse(courseId(args)),
};

async function getLockdownQuizLaunch(args: {
  course_id?: string | number;
  quiz_id: string | number;
  session_cookie?: string;
}): Promise<unknown> {
  const id = courseId(args);
  const quizId = String(args.quiz_id);
  const takeUrl = `${BASE_URL}/courses/${id}/quizzes/${quizId}/take`;
  let launchHref: string | null = null;
  const sessionCookie = args.session_cookie?.trim();
  const cookieHeader = sessionCookie
    ? `canvas_session=${sessionCookie.replace(/^canvas_session=/i, '').replace(/;.*$/, '')}`
    : null;
  const extracted = await extractCanvasSessionCookie();
  const resolvedCookie = cookieHeader ?? (extracted.cookie_value ? `canvas_session=${extracted.cookie_value}` : null);
  if (resolvedCookie) {
    const page = await safe(() =>
      canvasFetch(
        new URL(`/courses/${id}/quizzes/${quizId}/lockdown_browser_launch`, BASE_URL),
        {
          headers: {
            Accept: 'text/html',
            Cookie: resolvedCookie,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36 CLDB 2.1.5.06',
          },
        },
      ).then((r) => r.text()),
    );
    const html = typeof page.value === 'string' ? page.value : null;
    if (html) {
      const match = html.match(/rldb:[^"'\s<]+/i);
      if (match) launchHref = match[0].replace(/&amp;/g, '&');
    }
  }
  const platform = process.platform;
  const launchUrl = launchHref ?? takeUrl;
  let launched = false;
  let launchCommand: string | null = null;
  if (launchUrl && (platform === 'darwin' || platform === 'win32' || platform === 'linux')) {
    const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
    launchCommand = `${command} ${JSON.stringify(launchUrl)}`;
    try {
      if (platform === 'win32') {
        await execFileAsync('cmd', ['/c', 'start', '', launchUrl]);
      } else {
        await execFileAsync(command, [launchUrl]);
      }
      launched = true;
    } catch (err) {
      launched = false;
      return {
        generated_at: new Date().toISOString(),
        course_id: id,
        quiz_id: quizId,
        ok: false,
        reason: `could not launch the Lockdown Browser: ${err instanceof Error ? err.message : String(err)}`,
        launch_url: launchUrl,
        launch_command: launchCommand,
      };
    }
  }
  return {
    generated_at: new Date().toISOString(),
    course_id: id,
    quiz_id: quizId,
    ok: launched,
    launch_url: launchUrl,
    launch_command: launchCommand,
    client_check: 'the official Lockdown Browser client verifies this launch; this server does not answer or submit',
    session_source: sessionCookie ? 'explicit' : (extracted.store ? `${extracted.store} (auto)` : null),
    tried_stores: extracted.tried,
  };
}

async function getLockdownQuizTake(args: {
  course_id?: string | number;
  quiz_id: string | number;
  session_cookie?: string;
  preview?: boolean;
}): Promise<unknown> {
  const id = courseId(args);
  const quizId = String(args.quiz_id);
  const preview = args.preview !== false;
  const includeTextFlag = (value: unknown): string | null => (typeof value === 'string' ? stripHtml(value).slice(0, 400) : null);  let sessionCookie = args.session_cookie?.trim();
  let sessionSource: string | null = sessionCookie ? 'explicit' : null;
  let triedStores: string[] | null = null;
  if (!preview && !sessionCookie) {
    const extracted = await extractCanvasSessionCookie();
    triedStores = extracted.tried;
    if (extracted.cookie_value) {
      sessionCookie = extracted.cookie_value;
      sessionSource = `${extracted.store} (auto)`;
    }
  }
  const LDB_UA =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36 CLDB 2.1.5.06';

  const quiz = await safe(() => canvasGet(`/courses/${id}/quizzes/${quizId}`));
  if (quiz.error) {
    return {
      course_id: id,
      generated_at: new Date().toISOString(),
      resolution_status: 'skipped',
      reason: `quiz not readable: ${quiz.error}`,
      quiz_status: endpointStatus(quiz.error),
    };
  }
  const quizRow = quiz.value as any;

  const existing = await safe(() =>
    canvasGet(`/courses/${id}/quizzes/${quizId}/submission`, { 'include[]': ['submission', 'quiz'] }),
  );
  const existingSubmission = compactQuizSubmission(existing.value);
  if (existingSubmission && existingSubmission.workflow_state === 'complete') {
    return {
      course_id: id,
      generated_at: new Date().toISOString(),
      resolution_status: 'skipped',
      reason: 'the current user already has a completed attempt for this quiz',
      quiz: compactQuiz(quizRow),
      submission: existingSubmission,
      score: existingSubmission.score,
      start_status: 'not_attempted',
    };
  }

  const headers: Record<string, string> = { 'User-Agent': LDB_UA };
  if (sessionCookie) {
    const bare = sessionCookie.replace(/^canvas_session=/i, '').replace(/;.*$/, '');
    headers.Cookie = `canvas_session=${bare}`;
  }
  let attemptQuestions: Array<{ question_id: string | null; question_type: string | null; points_possible: number | null; question_text: string | null }> = [];
  let attemptQuestionError: string | null = null;
  let startRaw: { status: number; body: string } | null = null;
  const attemptStart = await (async (): Promise<{ value: { status: number; body: string } | string | null; error: string | null }> => {
    const res = await safe(async () => {
      const response = await canvasFetch(
        new URL(`/api/v1/courses/${id}/quizzes/${quizId}/submissions`, BASE_URL),
        { method: 'POST', headers: { ...headers, Accept: 'application/json' } },
      );
      return { status: response.status, body: await response.text() };
    });
    startRaw = res.error ? null : (res.value as { status: number; body: string });
    const ok = startRaw != null && startRaw.status >= 200 && startRaw.status < 300;
    if (!ok) {
      if (!sessionCookie) return res;
      const takePage = await safe(() =>
        canvasFetch(
          new URL(`/courses/${id}/quizzes/${quizId}/take`, BASE_URL),
          { headers: { ...headers, Accept: 'text/html' } },
        ).then((r) => r.text()),
      );
      return takePage.error ? res : takePage;
    }
    let submissionId: string | null = null;
    try {
      submissionId = JSON.parse(startRaw!.body)?.quiz_submissions?.[0]?.id ?? null;
    } catch {
      submissionId = null;
    }
    if (!submissionId) {
      attemptQuestionError = `attempt start returned no submission id (HTTP ${startRaw?.status})`;
      return res;
    }
    const opened = await safe(() =>
      canvasFetch(
        new URL(`/api/v1/quiz_submissions/${submissionId}/questions?include%5B%5D=quiz_question`, BASE_URL),
        { headers: { ...headers, Accept: 'application/json' } },
      ).then((r) => r.text()),
    );
    try {
      const openedBody = JSON.parse((opened.value as string) ?? '{}');
      const list = Array.isArray(openedBody?.quiz_submission_questions) ? openedBody.quiz_submission_questions : [];
      attemptQuestions = list.map((item: any) => {
        const question = item?.quiz_question ?? item ?? {};
        return {
          question_id: question?.id ?? question?.question_id ?? null,
          question_type: question?.question_type ?? null,
          points_possible: question?.points_possible ?? null,
          question_text: includeTextFlag(question?.question_text) ?? null,
        };
      });
      if (!list.length) attemptQuestionError = 'attempt open but Canvas returned no questions';
    } catch {
      attemptQuestionError = 'attempt questions unreadable after start';
    }
    return res;
  })();
  const takeBody = attemptStart.value;
  const takeHtml = typeof takeBody === 'string' ? takeBody : null;
  const questionHtml = takeHtml
    ? Array.from(takeHtml.matchAll(/<div[^>]*class="[^"]*question[^"]*"[^>]*>[\s\S]*?<\/div>/g))
        .map((match) => match[0])
        .slice(0, 60)
    : [];
  const parsed = questionHtml
    .map((block) => {
      const questionId = block.match(/question[_-]?[iI]d="(\d+)"/)?.[1] ?? block.match(/id="question_(\d+)"/)?.[1] ?? null;
      const text = block.match(/class="[^"]*question_text[^"]*"[^>]*>([\s\S]*?)<\/div>/)?.[1] ?? block.replace(/<[^>]+>/g, ' ');
      const choice = Array.from(block.matchAll(/<input[^>]*name="question\[(\d+)\]"\s*[^>]*value="([^"]*)"/g)).map((m) => ({
        question_id: m[1],
        answer_id: m[2],
      }));
      return { question_id: questionId ?? choice[0]?.question_id ?? null, question_text: stripHtml(text).slice(0, 400), choice };
    })
    .filter((one) => one.question_id || one.question_text);

  return {
    course_id: id,
    generated_at: new Date().toISOString(),
    resolution_status: 'ok',
    preview,
    session_source: sessionSource,
    session_store_candidates: triedStores,
    quiz: compactQuiz(quizRow),
    existing_submission: existingSubmission,
    start_status: preview
      ? 'not_attempted'
      : (attemptStart.error
          ? endpointStatus(attemptStart.error)
          : (attemptStart.value && typeof attemptStart.value !== 'string' && attemptStart.value.status != null
              ? `http_${attemptStart.value.status}`
              : 'unknown')),
    start_http: (attemptStart.value && typeof attemptStart.value !== 'string' ? attemptStart.value.status : null) ?? null,
    start_body_excerpt:
      attemptStart.value && typeof attemptStart.value !== 'string' && attemptStart.value.status != null && attemptStart.value.status >= 400
        ? attemptStart.value.body.slice(0, 200)
        : null,
    start_note: preview
      ? 'preview true: the attempt was not started. Set preview false to begin an attempt with the token\'s own session; a time-limited quiz starts its timer the moment the attempt is opened.'
      : null,
    start_error: attemptStart.error,
    html_flow_used: takeHtml != null,
    returned_question_count: preview ? 0 : parsed.length,
    question: preview ? [] : parsed,
    answer_note:
      'The server never answers or submits. With preview false the attempt is opened and its questions returned; the student answers in whatever client they choose, including the official Lockdown Browser, which resumes the open attempt.',
  };
}


Object.assign(handler, {
  // Legacy aliases kept for existing saved MCP calls; listTools exposes the canonical names above.
  list_courses: handler.list_course,
  whoami: handler.get_user_self,
  list_modules: handler.list_module,
  list_assignments: handler.list_assignment,
  list_announcements: handler.list_announcement,
  list_files: handler.list_file,
  list_my_submissions: handler.list_my_submission,
  list_discussions: handler.list_discussion,
  list_quizzes: handler.list_quiz,
  get_quiz_questions: handler.get_quiz_question,
});

// ============================================================================
// Server bootstrap
// ============================================================================

const server = new Server(
  { name: 'better-canvas-mcp', version: "0.7.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tool.map((item) => ({
    ...item,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const selectedHandler = handler[name];
  if (!selectedHandler) {
    return { content: [{ type: 'text', text: `Tool "${name}" not implemented` }], isError: true };
  }
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
  console.error(`[Canvas MCP] Server started — course ${DEFAULT_COURSE_ID ?? '(none)'} @ ${BASE_URL}`);
}

main().catch((err) => {
  console.error('[Canvas MCP] Fatal:', err);
  process.exit(1);
});
