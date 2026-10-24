# Setup and deployment

## Local Windows development

1. Activate the project's `.venv` in PowerShell.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Set `SECRET_KEY`, `DATABASE_URL`, and cookie/mail configuration in an ignored `.env`.
4. Back up an existing SQLite database before schema changes.
5. Copy the new audit workspace migration into the repository's existing `migrations/versions/` directory.
6. Run `python -m flask --app backend.app db upgrade`.
7. Run `python -m pytest -q`.
8. Start with `python -m flask --app backend.app run --debug`.

## Frontend

With Flask running in one terminal, open another PowerShell terminal:

```powershell
cd frontend
npm install
npm run dev
```

Use the Vite URL printed by the command. The development proxy forwards API calls to `http://localhost:5000`. Build static frontend assets with `npm run build`.

## Configuration

- `SECRET_KEY`: required, long random secret; never commit it.
- `DATABASE_URL`: local default `sqlite:///trustvault.db`; use a PostgreSQL SQLAlchemy URL for deployment and install the PostgreSQL driver.
- `COOKIE_SECURE`: `false` only for local HTTP. Set `true` behind HTTPS.
- `MAIL_SUPPRESS_SEND`: set `true` during local development/tests unless SMTP is intentionally configured.
- SMTP settings: `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USE_SSL`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`.

## Deployment checklist

- Use HTTPS and set secure cookies.
- Store secrets in the deployment secret manager, not source control.
- Use PostgreSQL or another supported production database and apply migrations before serving traffic.
- Run under a production WSGI server; do not use Flask's development server in production.
- Restrict database and private upload directory access to the application service account.
- Back up the database and upload files; test restoration.
- Add rate limiting, monitoring/alerts, upload malware/content scanning, storage quotas, and orphan-file cleanup.
- Use a dedicated external audit sink or signed checkpoints if the threat model requires stronger tamper evidence than an in-database hash chain.
- Review CORS, reverse-proxy headers, request size limits, error handling and log redaction before exposing the service publicly.


## Google sign-in and invitation email configuration

Set these values in the private `.env` file (never commit `.env`):

```dotenv
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
FRONTEND_URL=http://localhost:5173
BACKEND_URL=http://localhost:5000
MAIL_SUPPRESS_SEND=false
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USE_SSL=false
MAIL_USERNAME=your-smtp-username
MAIL_PASSWORD=your-smtp-password
MAIL_DEFAULT_SENDER=TrustVault <no-reply@example.com>
INVITATION_TTL_HOURS=48
JOIN_REQUEST_TTL_HOURS=72
COOKIE_SECURE=false
```

Create a Google OAuth Web application in Google Cloud Console. For local development, add the authorized redirect URI `http://localhost:5000/auth/google/callback`. For production, set `BACKEND_URL` to the HTTPS backend origin, use `https://YOUR_BACKEND_HOST/auth/google/callback` as the authorized redirect URI, and update `FRONTEND_URL` to the deployed frontend origin. Google OAuth will not work until the client ID/secret and redirect URI match.

Email delivery requires a working SMTP account. Invitation and administrator-approval emails are best-effort; check the backend log and `notification_sent` response when delivery fails. Tokens are stored as SHA-256 digests, are single-use, and expire. Never put provider credentials in source control.

The company-name duplicate check normalizes capitalization and whitespace before matching. Existing duplicate workspace records are not automatically merged, because merging companies can alter ownership and audit history; inspect and reconcile old duplicates separately before production deployment.
