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

