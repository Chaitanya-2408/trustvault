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

Use the Vite URL printed by the command. The development proxy forwards API calls to `http://127.0.0.1:5000`. Build static frontend assets with `npm run build`.

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
