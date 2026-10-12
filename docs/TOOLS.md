# Tools

Every read tool takes an optional `course_id` and otherwise uses `CANVAS_COURSE_ID`. A denial from Canvas is `blocked_or_absent` or an error string. It is not an empty success.

## Reads

| Tool | What it returns |
|---|---|
| `list_course` | List Canvas courses visible to the current user, including term/enrollment metadata. Use this to decide whether a shell is relevant to the current term before treating assignments as actionable. |
| `get_user_self` | Return the Canvas user resolved by the API token. |
| `get_user_canvas_context` | Fetch bounded current-user Canvas context: profile, safe login and access-token visibility, favorite courses, course nicknames, dashboard cards/positions, custom colors, bookmarks, observees, recent graded submissions, and selected current-course progress/preference includes. Read-only; it does not create bookmarks, favorites, login changes, access tokens, or nickname changes. |
| `get_user_page_view_context` | Fetch bounded current-user Canvas page-view history as weak activity evidence. Read-only; uses only the GET page-view endpoint for users/self and does not create async page-view query jobs. |
| `get_user_file_context` | Fetch bounded current-user Canvas file storage context: user files, folders, root folder, and quota. Read-only; does not create folders, upload files, copy files, or change usage rights. |
| `get_user_eportfolio_context` | Fetch bounded current-user Canvas ePortfolio context: ePortfolio list, optional detail, and page metadata/content when Canvas permits it. Read-only; does not delete, restore, or moderate ePortfolios. |
| `get_user_content_share_context` | Fetch bounded current-user Canvas Content Share context: sent shares, received shares, unread count, and optional detail for a visible share. Read-only; does not create, update, delete, mark read/unread, or add receivers. |
| `request_canvas_api` | Read any Canvas API GET path the token can access, including non-/api/v1 namespaces such as /api/quiz/v1. This is a read-only escape hatch for endpoint probing; use specialized tools when they exist. |
| `get_canvas_api_capability` | Probe a bounded read-only Canvas API capability matrix through the MCP and report ok/blocked/skipped/error per endpoint family. Returns only status, row counts, sample keys, paths, and source docs; it does not persist raw private content. |
| `list_canvas_api_endpoint` | List the Canvas endpoint families known to this MCP capability matrix, including probe IDs, method, pagination shape, required context, and documentation links. |
| `resolve_canvas_link` | Resolve a Canvas web URL, Canvas API path, or Canvas file link into the matching read-only MCP/API response. Can extract text from linked Canvas files and returns links found inside extracted text. |
| `get_course` | Get Canvas course metadata and the syllabus body. |
| `get_course_action_context` | Fetch sanitized course-level action context for owed-work checks: planner/todo/missing queues, calendar, grade/weight keys, own groups, tabs, appointments, outcomes, activity summary, and recent history. This is cross-check context; use submissions/self for completion truth. |
| `get_course_planner_context` | Fetch bounded course planner context: planner items, planner notes, planner overrides, linked-object URLs, marked-complete/dismissed signals, and reminder text. This is user-visible planning context, not submission truth. |
| `get_course_due_date_context` | Fetch bounded current-user course due-date and policy context: assignment all_dates/overrides, effective due dates for the token user only, course todo, course settings, and selected course permissions. |
| `get_course_outcome_context` | Fetch bounded read-only course outcome context: root outcome group, outcome groups, outcome links, current-user outcome alignments/results/rollups, and assignment-scoped outcome evidence when an assignment_id is provided. |
| `get_course_assessment_context` | Fetch bounded read-only rubric catalog/detail/used-location context, LiveAssessments, assessment question banks/questions, assignment-embedded rubric, learning-object date detail, and current-user rubric/document read-state context. Catalog/detail/live/date/question-bank endpoints may be blocked under a student PAT. |
| `get_assignment_moderation_context` | Fetch read-only Moderated Grading visibility for one assignment: moderated-student rows and current-user provisional-grade status when Canvas permits them. It never selects, publishes, or mutates provisional grades. |
| `get_course_roster_context` | Fetch bounded read-only course roster/scope context: sections, current-user enrollment, compact visible course users, group categories, groups in categories, category-user visibility, and LTI Names and Role membership visibility. This is section/group scope evidence, not assignment completion proof. |
| `get_course_group_context` | Fetch bounded current-user group workspace context for one course: own groups, group tabs, permissions, memberships, members, files/folders, pages, discussions, activity stream/summary, embedded links/files, and requirement signals. This does not pull broad course rosters or change group membership. |
| `get_course_collaboration_context` | Fetch bounded read-only collaboration context for a course and the current user own groups: course collaborations, own-group collaborations, collaboration members, provider/document links, and group-work signals. This does not scan broad potential collaborator rosters. |
| `get_course_calendar_context` | Fetch bounded course calendar context: event rows, assignment-event rows, event details, appointment groups, embedded links/files, location/online/onsite/device/deadline signals, and optional linked-file extraction. This is read-only and does not reserve slots. |
| `get_course_term_context` | Fetch current-user course term/section/enrollment context: term, section dates, grading periods, concluded/course-date flags, teachers when Canvas includes them, and own enrollment rows. Use this to decide whether a Canvas shell is relevant before classifying work. |
| `get_course_grade_context` | Fetch bounded read-only current-user grade, assignment-group weight, grading-period, and grading-standard context. Grade context is cross-check evidence and never overrides submission truth. |
| `get_course_activity_context` | Fetch bounded read-only activity, course audit-log, recent-history, unread inbox, and optional sanitized conversation-detail context for a course. Raw conversation bodies are never returned. |
| `get_course_analytics_context` | Fetch bounded read-only course and current-user analytics visibility for a course. Analytics is cross-check evidence only and may be blocked under a student PAT. |
| `get_course_material_context` | Build a compact coursework material graph for one course: readings, attached files, source surfaces, deadlines, submission types, reply signals, group-work signals, modules, and queue/calendar cross-checks. |
| `get_course_syllabus_context` | Fetch bounded read-only course syllabus context: syllabus body text, embedded links/files, requirement signals, term/section hints, and optional extraction for syllabus-linked Canvas files. |
| `get_course_search_context` | Search Canvas course content with the official Smart Search API when available, across pages, assignments, announcements, and discussion topics. This beta endpoint may be disabled by Canvas; blocked/absent status is returned as evidence. |
| `get_course_media_context` | Fetch bounded read-only Canvas media attachment context for a course and current-user own groups, including audio/video metadata and links when Canvas exposes them. |
| `get_course_conference_context` | Fetch bounded read-only Canvas Conferences context for current user, course, and current-user own groups. Useful for class meeting or recording context; does not start, join, or manage conferences. |
| `get_course_export_context` | Fetch bounded read-only Canvas content/ePub export context, optional Course Report status, and existing Progress rows exposed by export progress_url values. Does not create/cancel export or report jobs. |
| `get_canvas_progress_context` | Fetch read-only Canvas async Progress status by progress_id/progress_url or LTI progress id. Does not cancel Progress jobs. |
| `get_course_pacing_context` | Fetch bounded read-only course pacing context: course blackout dates and optional Course Pace details when a course_pace_id is known. Does not create, update, or delete pacing records. |
| `get_course_poll_context` | Fetch bounded read-only Canvas Polls context for current-user polls plus opened/closed poll sessions visible to the current user. Does not create polls or submit poll choices. |
| `get_user_notification_context` | Fetch bounded read-only current-user communication channel and notification preference context. Does not create channels or update notification preferences. |
| `get_user_comm_message_context` | Fetch bounded read-only Canvas notification message metadata for the current user. Raw message bodies are not returned; only short deadline-like excerpts are included. |
| `get_course_account_context` | Fetch read-only account-scoped context for the selected course, including active global account notifications, account domain lookup rows, admin-role visibility, API token scope metadata, and safe authentication provider metadata visible to the current user. |
| `get_course_brand_context` | Fetch read-only Canvas Brand Config variables for the root domain, selected course account, and selected course when Canvas permits them. |
| `get_course_account_calendar_context` | Fetch read-only Account Calendar visibility for the selected course account and current user. |
| `get_course_blueprint_context` | Fetch read-only Blueprint Course/subscription/import context for the selected course when Canvas permits it. |
| `get_course_grading_period_context` | Fetch read-only account/course grading-period visibility for the selected course, including course grading-period detail when Canvas exposes an ID. |
| `get_course_feature_context` | Fetch bounded read-only Canvas late-policy, CSP setting, and feature-flag context for a course/current user. Does not set feature flags, change late policy, or mutate CSP domains. |
| `get_course_module_context` | Fetch bounded course module context: module state, prerequisites, sequential progress, completion requirements, module items with content details, embedded links/files, requirement tags, and reading/reply/deadline/device/group/submission signals. |
| `list_module` | List all modules in the course with their items (titles, types, ids, urls). |
| `get_module_item` | Fetch a single module item by id (page body, assignment, quiz, file, external url, etc). |
| `get_module_item_context` | Fetch a module item and resolve its Canvas target when possible: assignment, page, file, discussion, quiz, or external/tool link. Keeps external/LTI targets as links only. |
| `get_course_external_tool_context` | Fetch bounded read-only external tool/LTI context for a course: installed course/parent tools when visible, external-tool tabs, external-tool module items, optional assignment launch metadata, and optional sessionless launch URL checks. This does not fetch third-party content or bypass LTI permissions. |
| `get_course_quiz_lti_context` | Fetch read-only New Quiz and LTI line-item visibility for one course/assignment. Use this to explain quiz/external-tool ambiguity without treating blocked internals as submission proof. |
| `list_assignment` | List all assignments in the course (name, due_at, points_possible, description). Optionally asks Canvas to include the current user submission object when Canvas honors include[]=submission. |
| `get_assignment` | Fetch a single assignment with its full description/instructions HTML. |
| `get_assignment_context` | Fetch one assignment plus the current user submission state, linked Canvas file ids, optional attachment text extraction, and discovered nested links. This is the preferred read for owed-work checks. |
| `get_peer_review_context` | Fetch read-only peer-review context for one assignment: all readable peer review rows, current-user submission peer reviews when resolvable, assigned-to-me and reviewing-my-submission counts, and included comment/user evidence when Canvas permits it. |
| `list_announcement` | List all announcements posted to the course. |
| `get_course_announcement_context` | Fetch bounded course announcement context: announcements over a date window, embedded links/files, requirement tags, reading/reply/deadline/device/group/submission signals, and optional linked-file extraction. |
| `get_course_feed_context` | Fetch read-only Announcement External Feed context for the course and current-user own groups, showing RSS/Atom feeds that can auto-create announcements. |
| `get_page` | Fetch the body of a wiki page by url-slug. Note: pages may be disabled for some courses. |
| `get_course_page_context` | Fetch a bounded read-only page/wiki context for a course: page index, front page when readable, selected page bodies, module placement, embedded links/files, requirement tags, and optional linked-file extraction. |
| `list_file` | List files in the course. Note: may return 403 if files area is restricted. |
| `get_file` | Fetch Canvas file metadata by file id. The returned url is usually the authenticated download URL. |
| `get_course_file_context` | Build a bounded course file/folder context: root folder, all readable folders, course files with folder placement, usage-right keys, reading-like file types, and optional extraction for selected file IDs. |
| `extract_file_text` | Download a Canvas file and extract text when possible. Supports text/html/JSON/CSV, DOCX via unzip, PDFs via pdftotext, and images via tesseract OCR when installed. Binary files return metadata plus an explicit unsupported note. |
| `list_my_submission` | List the current user submission state for a course via /students/submissions?student_ids[]=self. Use this before classifying assignment work as missing or done. |
| `get_my_submission` | Fetch the current user submission state for one assignment, including submitted_at, workflow_state, late, missing, grade/score, attachments, and optional history. |
| `get_submission_feedback_context` | Fetch read-only feedback context for the current-user assignment submission: comments, rubric assessment keys, submission history summary, attachment count, and rubric/document annotation read-state endpoints when Canvas permits them. |
| `list_discussion` | List all discussion topics in the course. |
| `get_discussion` | Fetch a single discussion topic with its message body. |
| `get_discussion_context` | Fetch one discussion topic plus its Canvas entry tree/view, flattened counts, current-user post/reply counts, unread entry count, and optional bounded entry bodies. |
| `list_quiz` | List all quizzes in the course (may 404 if disabled at course level). |
| `get_quiz` | Fetch a single quiz with metadata + description. |
| `get_quiz_question` | List all questions for a quiz (may 403 if you lack permission). |
| `get_quiz_context` | Fetch Classic Quiz context in one read-only call: quiz metadata, questions/question groups when readable, current-user quiz submission, optional submission events, linked files/URLs, and assignment mapping. |
| `extract_course` | Extract everything in the course (modules, pages, assignments, discussions, quizzes, announcements, files, plus categorized embeds — youtube/gsheets/gforms/etc). Single efficient call. Returns the same structure as the canvas-toolkit extractor. |


## Engagement

| Tool | What it returns |
|---|---|
| `get_user_self` | Return the current Canvas user (self) and engagement-MCP config (base URL, state dir). Useful for verifying the token resolves. |

