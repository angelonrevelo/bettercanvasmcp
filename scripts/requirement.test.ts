import assert from 'node:assert/strict';
import { test } from 'node:test';
import { meetRequirement, mergeRequirement, requirementFromCanvas, requirementFromPrompt } from '../src/requirement.ts';

test('a plain discussion mention is not a requirement', () => {
  assert.deepEqual(requirementFromPrompt('Read the discussion board for context.'), []);
});

test('peer reply counts words and digits', () => {
  const two = requirementFromPrompt('Reply to at least two classmates before Friday.');
  assert.equal(two[0]?.requirement_kind, 'peer_reply');
  assert.equal(two[0]?.count_required, 2);
  const three = requirementFromPrompt('Respond to 3 peers.');
  assert.equal(three[0]?.count_required, 3);
});

test('comment and feedback stay distinct', () => {
  const comment = requirementFromPrompt('Comment on 3 posts in this thread.');
  assert.equal(comment[0]?.requirement_kind, 'comment');
  assert.equal(comment[0]?.count_required, 3);
  const feedback = requirementFromPrompt('Give feedback on a peer draft.');
  assert.equal(feedback.some((one) => one.requirement_kind === 'feedback'), true);
});

test('attendance and a form url are both kept', () => {
  const hit = requirementFromPrompt(
    'Attendance check-in: https://docs.google.com/forms/d/e/abc/viewform',
  );
  const kind = hit.map((one) => one.requirement_kind).sort();
  assert.deepEqual(kind, ['attendance', 'form']);
  assert.equal(hit.find((one) => one.requirement_kind === 'form')?.detector, 'url');
});

test('canvas fields outrank prompt wording', () => {
  const hit = mergeRequirement(
    requirementFromCanvas({ is_require_initial_post: true, is_lockdown_browser: true }),
    requirementFromPrompt('Post before you can see replies. Use LockDown Browser.'),
  );
  assert.equal(hit.filter((one) => one.requirement_kind === 'initial_post').length, 1);
  assert.equal(hit.find((one) => one.requirement_kind === 'initial_post')?.detector, 'canvas_field');
  assert.equal(hit.find((one) => one.requirement_kind === 'lockdown_browser')?.detector, 'canvas_field');
});

test('reply progress is met only at the required count', () => {
  const [hit] = requirementFromPrompt('Reply to at least 2 classmates.');
  assert.ok(hit);
  const short = meetRequirement(hit, { my_top_level_post_count: 1, my_reply_count: 1 });
  assert.equal(short.is_met, false);
  const done = meetRequirement(hit, { my_top_level_post_count: 1, my_reply_count: 2 });
  assert.equal(done.is_met, true);
});

test('classmate reply wording from a real prompt is a peer reply without a count', () => {
  const hit = requirementFromPrompt('Make sure you respond to the posts of your classmates by liking their posts or by replying.');
  assert.equal(hit[0]?.requirement_kind, 'peer_reply');
  assert.equal(hit[0]?.count_required, null);
  const verdict = meetRequirement(hit[0], { my_top_level_post_count: 1, my_reply_count: 3 });
  assert.equal(verdict.is_met, null);
});

test('a comment on a classmate share is a comment, and course content is not', () => {
  const share = requirementFromPrompt('Write respectfully on your classmate\'s sharing.');
  assert.equal(share.some((one) => one.requirement_kind === 'comment'), true);
  assert.deepEqual(requirementFromPrompt('Positive Feedback Loop and iterative feedback processes.'), []);
  assert.deepEqual(requirementFromPrompt('I will not review or comment on any draft before the deadline.'), []);
});

test('lockdown and forms are never marked done', () => {
  const lockdown = meetRequirement(
    requirementFromCanvas({ is_lockdown_browser: true })[0],
    { my_top_level_post_count: 5, my_reply_count: 5 },
  );
  assert.equal(lockdown.is_met, null);
  assert.match(lockdown.unmet_reason ?? '', /official/i);
  const form = meetRequirement(requirementFromPrompt('Fill out the form.')[0], null);
  assert.equal(form.is_met, null);
});
