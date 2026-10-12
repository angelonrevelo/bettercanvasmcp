/**
 * Deterministic requirement graph.
 *
 * Canvas fields and prompt keywords decide what a student owes. No model call.
 * A missing count stays null: the graph says the requirement exists and that
 * completion is unknown, instead of inventing "done".
 */

export type RequirementKind =
  | 'initial_post'
  | 'peer_reply'
  | 'comment'
  | 'feedback'
  | 'attendance'
  | 'form'
  | 'lockdown_browser';

export type RequirementDetector = 'canvas_field' | 'prompt' | 'url';

export interface RequirementHit {
  requirement_kind: RequirementKind;
  is_required: true;
  count_required: number | null;
  evidence: string;
  detector: RequirementDetector;
}

export interface RequirementProgress {
  my_top_level_post_count: number;
  my_reply_count: number;
}

export interface RequirementVerdict extends RequirementHit {
  is_met: boolean | null;
  current_count: number | null;
  unmet_reason: string | null;
}

const COUNT_WORD: Record<string, number> = {
  a: 1,
  an: 1,
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
};

const COUNT = String.raw`(\d+|a|an|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)`;
const PEOPLE = String.raw`(?:classmate|peer|student|groupmate|person|people|post|reply|replies|thread)s?`;

const FORM_URL = /https?:\/\/(?:docs\.google\.com\/forms|forms\.gle|forms\.office\.com|forms\.microsoft\.com)[^\s<>"']*/gi;

const PROMPT_RULE: Array<{ kind: RequirementKind; regex: RegExp; countGroup: number | null }> = [
  {
    kind: 'peer_reply',
    regex: new RegExp(String.raw`\b(?:reply|respond) to (?:at least |a minimum of )?${COUNT} (?:of (?:your )?)?(?:other |fellow )?${PEOPLE}\b`, 'i'),
    countGroup: 1,
  },
  {
    kind: 'peer_reply',
    regex: /\b(?:reply|respond) to (?:at least |a minimum of )?(?:other|fellow) (?:classmate|peer|student|groupmate)s?\b/i,
    countGroup: null,
  },
  {
    kind: 'peer_reply',
    regex: /\b(?:reply|respond)(?:ing)? to (?:the |your classmates'? )?(?:posts?|replies|comments?) of (?:your |the )?classmates?\b/i,
    countGroup: null,
  },
  {
    kind: 'comment',
    regex: /\bon your classmate'?s (?:sharing|share|post|response|answer|work)\b/i,
    countGroup: null,
  },
  {
    kind: 'comment',
    regex: new RegExp(String.raw`\bcomment on (?:at least |a minimum of )?${COUNT} (?:of (?:your )?)?${PEOPLE}\b`, 'i'),
    countGroup: 1,
  },
  {
    kind: 'comment',
    regex: new RegExp(String.raw`\b(?:leave|post|write) (?:at least |a minimum of )?${COUNT} comments?\b`, 'i'),
    countGroup: 1,
  },
  {
    kind: 'comment',
    regex: /\bcomment on (?:a |your )?(?:peer|classmate|groupmate)'?s? (?:post|work|draft)\b/i,
    countGroup: null,
  },
  {
    kind: 'feedback',
    regex: new RegExp(String.raw`\b(?:give|provide|leave|write) (?:at least |a minimum of )?${COUNT} (?:peer )?feedback\b`, 'i'),
    countGroup: 1,
  },
  {
    kind: 'feedback',
    regex: /\b(?:give|provide|leave|write) (?:peer |constructive )?feedback\b/i,
    countGroup: null,
  },
  {
    kind: 'feedback',
    regex: /\bfeedback (?:to|on|for) (?:a |your )?(?:peer|classmate|groupmate)\b/i,
    countGroup: null,
  },
  {
    kind: 'initial_post',
    regex: /\b(?:initial post|first post|post first|must post before|post before (?:you can |seeing |viewing )|before seeing replies|reply before viewing)\b/i,
    countGroup: null,
  },
  {
    kind: 'initial_post',
    regex: /\bmust (?:make |write |create )?(?:an |a )?initial post\b/i,
    countGroup: null,
  },
  {
    kind: 'attendance',
    regex: /\b(?:attendance|roll call|sign[- ]in|check[- ]in|present today|i am here)\b/i,
    countGroup: null,
  },
  {
    kind: 'form',
    regex: /\b(?:google form|microsoft form|fill (?:out |in )?(?:the |this )?form|submit (?:the |this )?form)\b/i,
    countGroup: null,
  },
  {
    kind: 'lockdown_browser',
    regex: /\b(?:lock ?down browser|respondus)\b/i,
    countGroup: null,
  },
];

export function stripRequirementHtml(value: string): string {
  return value
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function countFrom(raw: string | undefined): number | null {
  if (!raw) return null;
  const text = raw.trim().toLowerCase();
  if (/^\d+$/.test(text)) return Number(text);
  return COUNT_WORD[text] ?? null;
}

function excerpt(text: string, index: number): string {
  const start = Math.max(0, index - 60);
  const end = Math.min(text.length, index + 180);
  return text.slice(start, end).trim();
}

function pushHit(hit: RequirementHit[], next: RequirementHit): void {
  const existing = hit.find((one) => one.requirement_kind === next.requirement_kind && one.detector === next.detector);
  if (!existing) {
    hit.push(next);
    return;
  }
  if (existing.count_required == null && next.count_required != null) {
    existing.count_required = next.count_required;
    existing.evidence = next.evidence;
  }
}

export function requirementFromPrompt(value: string): RequirementHit[] {
  const text = stripRequirementHtml(value);
  const hit: RequirementHit[] = [];
  if (!text) return hit;

  for (const rule of PROMPT_RULE) {
    const match = text.match(rule.regex);
    if (!match) continue;
    const count = rule.countGroup == null ? null : countFrom(match[rule.countGroup]);
    pushHit(hit, {
      requirement_kind: rule.kind,
      is_required: true,
      count_required: rule.kind === 'initial_post' ? (count ?? 1) : count,
      evidence: excerpt(text, match.index ?? 0),
      detector: 'prompt',
    });
  }

  for (const match of text.matchAll(FORM_URL)) {
    pushHit(hit, {
      requirement_kind: 'form',
      is_required: true,
      count_required: null,
      evidence: match[0],
      detector: 'url',
    });
  }

  return hit;
}

export function requirementFromCanvas(input: {
  is_require_initial_post?: boolean;
  is_lockdown_browser?: boolean;
}): RequirementHit[] {
  const hit: RequirementHit[] = [];
  if (input.is_require_initial_post) {
    hit.push({
      requirement_kind: 'initial_post',
      is_required: true,
      count_required: 1,
      evidence: 'Canvas require_initial_post is true',
      detector: 'canvas_field',
    });
  }
  if (input.is_lockdown_browser) {
    hit.push({
      requirement_kind: 'lockdown_browser',
      is_required: true,
      count_required: null,
      evidence: 'Canvas require_lockdown_browser is true. The official Lockdown Browser client is still an option, and the quiz content plus the current-user score are readable via get_lockdown_quiz_access.',
      detector: 'canvas_field',
    });
  }
  return hit;
}

export function mergeRequirement(canvasHit: RequirementHit[], promptHit: RequirementHit[]): RequirementHit[] {
  const hit = [...canvasHit];
  for (const one of promptHit) {
    if (one.requirement_kind === 'initial_post' && hit.some((item) => item.requirement_kind === 'initial_post' && item.detector === 'canvas_field')) {
      continue;
    }
    if (one.requirement_kind === 'lockdown_browser' && hit.some((item) => item.requirement_kind === 'lockdown_browser' && item.detector === 'canvas_field')) {
      continue;
    }
    pushHit(hit, one);
  }
  return hit;
}

export function meetRequirement(hit: RequirementHit, progress: RequirementProgress | null): RequirementVerdict {
  if (hit.requirement_kind === 'lockdown_browser' || hit.requirement_kind === 'form') {
    return {
      ...hit,
      is_met: null,
      current_count: null,
      unmet_reason: hit.requirement_kind === 'lockdown_browser'
        ? 'Completion stays unknown until the student takes the exam in the official Lockdown Browser client. The content and score stay readable via get_lockdown_quiz_access.'
        : 'Form completion is outside Canvas, so this server cannot mark it done.',
    };
  }
  if (!progress) {
    return { ...hit, is_met: null, current_count: null, unmet_reason: 'No discussion view was loaded, so completion is unknown.' };
  }
  if (hit.requirement_kind === 'attendance') {
    const current = progress.my_top_level_post_count;
    const needed = hit.count_required ?? 1;
    const isMet = current >= needed;
    return {
      ...hit,
      is_met: isMet,
      current_count: current,
      unmet_reason: isMet ? null : `Attendance check-in needs ${needed} post. Current count is ${current}.`,
    };
  }
  if (hit.requirement_kind === 'initial_post') {
    const current = progress.my_top_level_post_count;
    const needed = hit.count_required ?? 1;
    const isMet = current >= needed;
    return {
      ...hit,
      is_met: isMet,
      current_count: current,
      unmet_reason: isMet ? null : `Initial post needs ${needed}. Current top-level count is ${current}.`,
    };
  }
  if (hit.count_required == null) {
    return {
      ...hit,
      is_met: null,
      current_count: hit.requirement_kind === 'peer_reply' || hit.requirement_kind === 'comment' || hit.requirement_kind === 'feedback'
        ? progress.my_reply_count
        : null,
      unmet_reason: 'The prompt names this requirement without a count, so completion stays unknown.',
    };
  }
  const current = progress.my_reply_count;
  const isMet = current >= hit.count_required;
  return {
    ...hit,
    is_met: isMet,
    current_count: current,
    unmet_reason: isMet ? null : `${hit.requirement_kind} needs ${hit.count_required}. Current reply count is ${current}.`,
  };
}
