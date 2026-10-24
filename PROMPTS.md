# TrustVault – AI Prompt Log

## Entry 1: Setting Up the Flask Backend

- **Date:** 22 October 2026
- **Task:** Create the initial Flask application and test it.
- **Prompt I used:** I asked ChatGPT to guide me step by step in setting up the Flask backend in VS Code and writing my first automated test.
- **What I did:** I created the Flask application using an application factory, added a `/health` endpoint, and wrote a pytest test to check the response.
- **What I learned:** I learned how to create a basic Flask application, return JSON responses, and test an endpoint without starting a separate server.
- **Testing:** The health endpoint test passed, and I checked the endpoint in my browser.
- **My reflection:** Starting with a small feature helped me understand the project structure before moving on to the security-related features.
- **Commit:** 8bbebfc — add Flask application and health check test.

## Entry 2: Debugging Authentication Tests

- **Date:** 22 October 2026
- **Task:** Fix the authentication tests and complete the initial authentication foundation.
- **Prompt I used:** I shared my pytest output with ChatGPT and asked for help understanding why two authentication tests failed.
- **Problem:** Flask-Login returned a `302` redirect when an unauthenticated user tried to access the profile endpoint, while my tests expected `401 Unauthorized`.
- **What I changed:** I configured the application to return a JSON `401` response for unauthenticated requests and prepared the shared database extension and user model.
- **What I learned:** I learned why API endpoints should return appropriate HTTP status codes and why the same database extension must be shared by the application, models, and tests.
- **Testing:** The final test run reported `6 passed`.
- **Relevant fix commit:** `dfd6bc4` — `fix: return unauthorized responses for protected routes`
- **Authentication foundation commit:** Add the actual commit ID after committing the model and dependency changes.

## Entry 3: Improving Session and CSRF Security

- **Date:** 22 October 2026
- **Task:** Improve the security of the Flask authentication system.
- **Prompt I used:** I asked ChatGPT to provide the complete updated file contents so I could copy them into VS Code without merging code snippets manually.
- **What I worked on:** I updated the Flask extensions, application configuration, user model, dependencies, and automated tests.
- **What I learned:** I learned why the application needs a secret key, how session-cookie settings help protect sessions, and why CSRF protection matters for browser-based authentication.
- **Testing:** The final test run reported 8 passed.
- **My reflection:** Testing the security changes helped me understand that authentication features need automated checks, not just a successful login in the browser.
- **Commit Id:**  `3e58941` 


### Entry 4 — Document ownership and permission testing
**Date:** 22 October 2026

**Prompt:** Help me implement document ownership, per-user READ and EDIT permissions, permission revocation, and tests that prevent unauthorized document access.

**Work completed:** Added document metadata and permission models, owner-controlled permission grants and revocation, and authorization checks for reading and editing documents. Updated the test fixture to correctly isolate Flask application contexts and CSRF sessions.

**Security considerations:** Unapproved users cannot access documents, READ permission does not allow editing, EDIT permission allows editing, and revoked permissions block subsequent requests. CSRF protection remains enabled in the application and test suite.

**Validation:** Ran `python -m pytest -q`. Result: 14 passed in 2.16 seconds.

**Commit:** `4f5c087` — feat: add document permissions and secure test coverage


### Entry 5 — Tamper-evident audit log foundation
**Date:** 22 October 2026

**Prompt:** Help me implement an audit log with SHA-256 hash chaining and automated integrity tests for TrustVault.

**Work completed:** Added the AuditLog model, an audit-event recording helper, canonical event serialization, SHA-256 event hashing, and a chain-verification function.

**Security considerations:** Audit events retain historical actor and document identifiers without foreign-key deletion cascades. The hash chain detects event modification, but it is not immutable against an attacker who can rewrite the entire database and recompute the chain.

**Validation:** Ran `python -m pytest -q`. Result: 16 passed in 2.22 seconds.

**Commit:** `cc7347d `



### Entry 6 — Audit logging integration

**Date:** 22 October 2026

**Prompt:** Help me integrate the tamper-evident audit log into the TrustVault Flask API and test the security events.

**Work completed:** Integrated audit events into document creation, document updates, denied document reads and edits, permission grants, permission changes, permission revocations, and denied permission-grant attempts. Added integration tests for successful and denied operations and audit-chain integrity.

**Security considerations:** Successful document and permission changes are recorded in the same database transaction as their audit events. The hash chain detects event modification, but does not guarantee immutability if an attacker can rewrite the entire database and recompute the chain.

**Validation:** `python -m pytest -q` — 20 tests passed.  
**Commit:** `861cedf`


### Entry 7 — Admin audit endpoint and access isolation

**Date:** 23 October 2026

**Prompt:** Help me implement a protected administrator audit-log endpoint and test that administrative access does not bypass document permissions.

**Work completed:** Added a paginated admin audit-log endpoint, access controls for unauthenticated users and non-admin users, pagination validation, and tests confirming that administrators cannot read another user's private document without explicit permission.

**Security considerations:** Audit-log access is restricted to administrators. Audit metadata access does not automatically grant access to document contents. Document authorization remains enforced separately.

**Validation:** `python -m pytest -q` — 25 tests passed in 3.80 seconds.

**Commit:** `242b08e`

### Entry 8 — Email service foundation

**Date:** 23 October 2026

**Prompt:** Help me set up a reusable email service in the TrustVault Flask backend with environment-based SMTP configuration and safe automated tests.

**Work completed:** Added `backend/email_service.py` using Python's standard email and SMTP libraries. Added environment-based email settings to the Flask application and updated `.env.example`. Added tests to verify that email sending is suppressed during development and that missing SMTP configuration raises an error.

**Security considerations:** Email credentials are configured through environment variables and should never be committed to Git. Email delivery is suppressed during development and testing. Real SMTP delivery and OTP authentication have not yet been implemented or verified.

**Validation:** `python -m pytest -q` — 27 tests passed in 3.76 seconds.

**Commit:** `6eb8895 `


### Entry 9  — Company workspace isolation and test fixes

**Date:** 23 October 2026

**Prompt:** Help me update TrustVault's Flask application to enforce company workspace isolation, prevent document permissions from being granted across companies, and correct the tests without weakening the security rules.

**Work completed:** Updated the document access logic to check company membership, restricted document listings to the user's workspace, and updated the tests so users who need to share documents belong to the same workspace. Also corrected the administrator audit-access test setup.

**Validation:** Ran `python -m pytest -q`. Result: **27 passed in 3.98 seconds**.

**Learning:** Company membership must be checked in addition to document permissions. A user from another company should not gain access simply because a document permission exists.


### Entry 10 — SMTP email configuration and workspace invitation troubleshooting

**Date:** 24 October 2026

**Prompt:** Help me troubleshoot TrustVault's Flask email invitation flow, identify why email delivery was being skipped due to the `MAIL_SUPPRESS_SEND` configuration, verify the application's environment settings, and confirm successful SMTP email delivery without exposing credentials.

**Work completed:** Investigated the HTTP 503 response from the `/admin/members` endpoint. Checked the `.env` configuration and PowerShell environment variables, verified that `TESTING` was `False` and `MAIL_SUPPRESS_SEND` was `False`, and improved email error logging to identify the cause of delivery failures. Restarted Flask and successfully tested sending an invitation email.

**Validation:** Confirmed that the invitation email was received and the invited user was able to join the workspace.

**Learning:** Environment variables can override values loaded from `.env`. Verifying the effective Flask configuration and logging SMTP exceptions helps diagnose email delivery failures without exposing sensitive credentials.

---

### Entry 11 — Google OAuth configuration handling and backend test fixes

**Date:** 24 October 2026

**Prompt:** Help me fix the failing TrustVault test for Google login when OAuth credentials are missing, ensure the login endpoint reports a configuration error instead of redirecting to Google's authorization page, and validate the changes without weakening authentication security.

**Work completed:** Investigated `test_google_login_reports_missing_configuration` and identified that the Google OAuth client could remain registered even after the test cleared the configured credentials. Updated the `/auth/google` route to check the current `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` values before attempting OAuth authorization.

**Validation:** Ran `python -m pytest -q`. Result: **35 passed in 13.23 seconds**. Also ran `npm run build` successfully, confirming that TypeScript compilation and the Vite production build completed without errors.

**Learning:** OAuth configuration should be validated using the application's current settings before initiating authorization. Tests should verify missing-credential handling while preserving the normal Google sign-in flow when valid credentials are configured.

## Authentication update (email OTP + password recovery)
- Email/password sign-in now requires a short-lived email OTP before a Flask-Login session is created. Google OAuth remains a separate, unchanged flow.
- Forgot-password returns a generic response to avoid revealing whether an email is registered. Reset codes expire after five minutes, are stored as keyed hashes, and are limited to five verification attempts.
- Configure SMTP using the variables in `.env.example`; do not commit `.env`.
- Apply migrations with `python -m flask --app backend.app db upgrade`.
- The frontend Vite proxy includes `/forgot-password` and `/reset-password`.
- In tests only, `test_otp` is returned to allow exercising OTP flows without an SMTP server. It is never returned when `app.testing` is false.
