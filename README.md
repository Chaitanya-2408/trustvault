# TrustVault

TrustVault is a secure document-sharing application built with Flask. It provides workspace-scoped document access, per-document `READ`/`EDIT` permissions, immediate revocation, private file storage, and a tamper-evident audit trail.

## Current backend capabilities

- Account registration and login with password hashing and CSRF protection.
- One account can belong to multiple workspaces and select an active workspace.
- Workspace administrators can add existing registered accounts to their workspace.
- Document lists, direct reads, uploads, downloads, edits, deletes, and permission changes are authorized server-side.
- A document is accessible only while its workspace is active and the user is a member of that workspace with an applicable grant.
- Owner-only document deletion and owner-controlled `READ`/`EDIT` grants.
- Search filters: `title`, `owner`, `category`, `date_from`, `date_to`.
- Private uploads are stored under the Flask instance directory with random server-generated names; allowed extensions and a 10 MB limit are enforced.
- Audit records include workspace snapshots, success/denied outcomes, and a SHA-256 hash chain. Workspace snapshots preserve deletion history without cross-workspace audit leakage.

## Technology

- Python, Flask, Flask-Login, Flask-WTF, Flask-SQLAlchemy, Flask-Migrate
- SQLite for local development; PostgreSQL supported when a PostgreSQL driver and `DATABASE_URL` are configured
- pytest
- Planned frontend: React + TypeScript + Vite

## Local setup (Windows / PowerShell)

Run commands from the repository root.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create a `.env` file in the repository root. Never commit it.

```dotenv
SECRET_KEY=replace-with-a-long-random-secret
DATABASE_URL=sqlite:///trustvault.db
COOKIE_SECURE=false
MAIL_SUPPRESS_SEND=true
```

For local HTTP, `COOKIE_SECURE=false` is needed so the browser sends the session cookie. Set it to `true` behind HTTPS in deployment. Keep `.env` ignored by Git.

### Database migration

The repository already has a migration history. Keep your existing `migrations/` folder and copy the new migration file from `migrations/versions/20261024_audit_company.py` into your repository's `migrations/versions/` directory.

Then run:

```powershell
python -m flask --app backend.app db upgrade
```

This migration adds a workspace snapshot to audit rows and rebuilds the audit hash chain to include that field. Back up your database before applying it. Do not run `db.create_all()` as a replacement for migrations on an existing database.

### Run backend

```powershell
python -m flask --app backend.app run --debug
```

Check `http://127.0.0.1:5000/health`. For API requests, fetch `/csrf-token` and send the returned token in the `X-CSRFToken` header on state-changing requests.

### Run automated tests

```powershell
python -m pytest -q
```

The tests use a temporary in-memory SQLite database and do not need your local `.env` database.

## Frontend (React + TypeScript + Vite)

The included frontend is a starter interface for authentication, workspace switching, document search/create/edit, file upload/download, permission grants/revocation, workspace member management, and audit review.

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal (usually `http://localhost:5173`). Keep Flask running on `http://127.0.0.1:5000`; Vite proxies API calls to it. For a production build, run `npm run build` from `frontend/`.

## Workspace & authentication flow

1. Register with `full_name`, `email`, `password` (minimum 12 characters), `confirm_password`, and optional initial `company_name`.
2. Sign in using direct database authentication with session cookies and CSRF protection.
3. Use `GET /companies` to list workspaces the account belongs to.
4. If the account belongs to multiple workspaces, choose one using `POST /companies/active` with `{"company_id": 123}`.
5. Workspace-scoped document and admin routes operate strictly within the selected workspace.
6. Workspace administrators can manage members, update roles (`admin`, `member`, `viewer`), and search registered users.

## Demo personas and showcase data protection

TrustVault includes pre-configured demonstration personas (Alex Morgan, Dr. Marcus Vance, Elena Rostova) and a showcase workspace (`Acme Global Security Vault`) with sample compliance and security documents for evaluator presentations:

- **Backend Protection:** The backend enforces protection rules on the `User`, `Company`, and `Document` data models. Any attempt to remove protected demo members, demote the demo owner, leave the showcase workspace, delete the showcase workspace, or delete showcase documents is rejected server-side with `403 Forbidden`.
- **Standard Operations Intact:** Non-demo members, custom workspaces, and user-uploaded documents can be managed, updated, and deleted normally according to standard role permissions.
- **No Public Reset Controls:** Destructive database reset is never exposed via HTTP routes or client UI. For developer maintenance in isolated test environments, developers use the standalone CLI script `python reset_and_seed_evaluators.py`.

Single-workspace accounts are selected automatically for backward compatibility. Multi-workspace accounts without an active selection receive a `403` for workspace-scoped document operations until they select one.

## Security notes

- Authorization is enforced by the backend; frontend hiding alone is not security.
- Workspace administrators can inspect workspace audit metadata but do not automatically gain access to document contents.
- Revocation blocks future requests; it cannot recall content a user already downloaded.
- The audit hash chain is tamper-evident, not immutable. An attacker with write access to the database may be able to rewrite the entire chain. For stronger guarantees, export signed checkpoints to independently controlled append-only storage.
- Use HTTPS, strong secrets, database backups, upload scanning, rate limiting, and operational monitoring before production deployment.

See [`docs/API.md`](docs/API.md), [`docs/SETUP_AND_DEPLOYMENT.md`](docs/SETUP_AND_DEPLOYMENT.md), and [`THREATS.md`](THREATS.md).


## New onboarding and identity features

- Optional Google OAuth sign-in (requires Google Cloud OAuth credentials).
- Workspace roles: Administrator, Member, and Viewer. Viewer is read-only.
- Email invitations for new members with one-time password setup links.
- Workspace administrators can remove memberships without deleting user accounts or memberships in other workspaces.
- Requests to become an administrator of an existing company require approval by a current workspace administrator.

See `docs/SETUP_AND_DEPLOYMENT.md` for Google OAuth and SMTP setup. Apply migrations before running the updated app.
