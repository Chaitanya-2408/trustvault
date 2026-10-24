# TrustVault API and authorization notes

All request/response bodies are JSON unless the route uploads or downloads a file. State-changing requests require a valid CSRF token in `X-CSRFToken`; first call `GET /csrf-token`. Routes requiring login return `401` when unauthenticated. Authorization failures return `403`; missing resources may return `404`.

## Authentication and workspace selection

| Method | Route | Access | Notes |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| GET | `/csrf-token` | Public | Gets CSRF token |
| POST | `/register` | Public | JSON: `email`, `password`, `company_name`; creates the first workspace admin |
| POST | `/login` | Public | JSON: `email`, `password`; selects a workspace automatically only if the account has one |
| POST | `/logout` | Login | Ends session |
| GET | `/me` | Login | User metadata, workspace memberships and active workspace |
| GET | `/companies` | Login | Lists only the caller's memberships |
| POST | `/companies/active` | Login + membership check | JSON: `company_id`; switches active workspace |
| GET | `/admin/members` | Active workspace admin | Lists member metadata for active workspace |
| POST | `/admin/members` | Active workspace admin | JSON: `email`; adds an existing account as a member of active workspace; duplicate membership returns `409` |
| GET | `/admin/audit-logs` | Active workspace admin | Paginated workspace audit metadata; `page` and `per_page` (maximum 100) |

## Documents

| Method | Route | Access |
|---|---|---|
| POST | `/documents` | Active workspace member; creates owned document |
| GET | `/documents` | Active workspace member with owner/grant visibility |
| GET | `/documents/<id>` | Owner or `READ`/`EDIT` grant in active workspace |
| PATCH | `/documents/<id>` | Owner or `EDIT` grant |
| DELETE | `/documents/<id>` | Owner only |
| POST | `/documents/<id>/upload` | Owner or `EDIT` grant |
| GET | `/documents/<id>/download` | Owner or `READ`/`EDIT` grant |
| POST | `/documents/<id>/permissions` | Owner only; JSON: `email`, `permission_level` (`READ` or `EDIT`) |
| DELETE | `/documents/<id>/permissions/<user_id>` | Owner only |

`GET /documents` supports optional filters: `title`, `owner` (owner email substring), `category`, `date_from`, `date_to` (`YYYY-MM-DD`). Filters are applied after the active-workspace and permission predicates, so search does not expand visibility.

## Authorization rules

1. Every document route resolves the active workspace and checks the document belongs to it.
2. A user must be a member of the active workspace. Membership in another workspace is not enough to access a document while a different workspace is active.
3. Document owners have full document access and alone may delete or grant/revoke permissions.
4. `READ` allows metadata read and download. `EDIT` allows read, download, metadata update, and file upload. Neither grants delete or permission-management rights.
5. Permission changes take effect on the next request; authorization is rechecked from the database.
6. Workspace admins can see audit metadata for their active workspace, but admin role does not bypass document permissions.
7. Audit records retain `company_id` snapshots so deletion events remain visible without relying on a document row that no longer exists.

## Error examples

```json
{"error": "Authentication required"}
```

```json
{"error": "Document access denied"}
```

```json
{"error": "You are not a member of that workspace"}
```

## Audit fields

Audit responses include event ID, actor snapshot, action, outcome (`SUCCESS` or `DENIED`), document ID, target user ID, safe metadata, timestamp, previous hash, and event hash. Do not put document contents, passwords, session cookies, CSRF tokens, or secrets in audit details.


## Identity and workspace onboarding endpoints

- `GET /auth/google` — begin Google OpenID Connect sign-in (requires Google OAuth credentials).
- `GET /auth/google/callback` — OAuth callback.
- `POST /companies` — create the first workspace for a newly authenticated Google user, or request approval to join an existing company when no workspace membership exists.
- `POST /admin/members` — add an existing account or email an invitation to a new account. Accepts `email` and `role` (`member` or `viewer`).
- `GET /invites/validate?token=...` — validate a pending invitation.
- `POST /invites/accept` — accept an invitation and set an initial password.
- `DELETE /admin/members/<user_id>` — remove a user's membership from the active workspace without deleting the account.
- `GET /admin/join-requests` — list pending requests to become a workspace administrator.
- `POST /admin/join-requests/<request_id>/decision` — approve or reject a request using `{"decision":"approve"}` or `{"decision":"reject"}`.

All state-changing endpoints remain subject to the application's CSRF protection. Administrator endpoints require an active workspace administrator session.
