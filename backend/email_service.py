
import smtplib
from email.message import EmailMessage

from flask import current_app


def send_email(to_address, subject, body):
    """Send a plain-text email using the application's SMTP settings."""

    config = current_app.config

    # Prevent real email delivery during development and tests.
    if config.get("MAIL_SUPPRESS_SEND", False):
        return

    server = config.get("MAIL_SERVER")
    sender = config.get("MAIL_DEFAULT_SENDER")
    port = config.get("MAIL_PORT", 587)
    use_tls = config.get("MAIL_USE_TLS", True)
    use_ssl = config.get("MAIL_USE_SSL", False)
    username = config.get("MAIL_USERNAME")
    password = config.get("MAIL_PASSWORD")

    if not server or not sender:
        raise RuntimeError(
            "MAIL_SERVER and MAIL_DEFAULT_SENDER must be configured."
        )

    if use_tls and use_ssl:
        raise RuntimeError(
            "Enable either MAIL_USE_TLS or MAIL_USE_SSL, not both."
        )

    if username and not (use_tls or use_ssl):
        raise RuntimeError(
            "SMTP authentication requires TLS or SSL."
        )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_address
    message.set_content(body)

    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP

    with smtp_class(server, port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()

        if username:
            smtp.login(username, password or "")

        smtp.send_message(message)
