"""
Modular Email Service for Network Traffic Investigation & Analysis Platform.
Supports:
- Development Console Mode (formats and logs verification / reset links safely)
- Production SMTP Mode (sends HTML and text emails over TLS)
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import settings

logger = logging.getLogger("email_service")


class EmailService:
    def __init__(self):
        self.enabled = settings.SMTP_ENABLED
        self.host = settings.SMTP_HOST
        self.port = settings.SMTP_PORT
        self.username = settings.SMTP_USERNAME
        self.password = settings.SMTP_PASSWORD
        self.from_email = settings.SMTP_FROM_EMAIL
        self.from_name = settings.SMTP_FROM_NAME
        self.use_tls = settings.SMTP_USE_TLS
        self.frontend_url = settings.FRONTEND_URL.rstrip("/")

    def send_verification_email(self, email: str, name: str, token: str) -> bool:
        """Send account email verification link."""
        verification_url = f"{self.frontend_url}/verify-email?token={token}"
        subject = f"Verify your email — {settings.APP_NAME}"
        
        text_content = f"""Hello {name},

Thank you for registering for the {settings.APP_NAME}.
Please verify your email address by visiting the link below:

{verification_url}

This verification link will expire in {settings.VERIFICATION_TOKEN_EXPIRE_HOURS} hours.

If you did not create this account, please ignore this email.

Regards,
{self.from_name}
"""
        html_content = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; background: #0a0e1a; color: #f1f5f9; padding: 20px;">
  <div style="max-width: 560px; margin: 0 auto; background: #111827; border: 1px solid #1f293d; border-radius: 8px; padding: 24px;">
    <h2 style="color: #3b82f6; margin-top: 0;">Verify Your Email Address</h2>
    <p>Hello {name},</p>
    <p>Thank you for registering for the <strong>{settings.APP_NAME}</strong>. Please confirm your email address to complete your registration.</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="{verification_url}" style="background: #3b82f6; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
        Verify Email Address
      </a>
    </div>
    <p style="font-size: 12px; color: #94a3b8;">Link: <a href="{verification_url}" style="color: #38bdf8;">{verification_url}</a></p>
    <p style="font-size: 12px; color: #64748b;">This link will expire in {settings.VERIFICATION_TOKEN_EXPIRE_HOURS} hours.</p>
  </div>
</body>
</html>
"""
        return self._send(email, subject, text_content, html_content, dev_label="EMAIL VERIFICATION LINK", link=verification_url)

    def send_password_reset_email(self, email: str, name: str, token: str) -> bool:
        """Send password reset instructions."""
        reset_url = f"{self.frontend_url}/reset-password?token={token}"
        subject = f"Password Reset Request — {settings.APP_NAME}"
        
        text_content = f"""Hello {name},

We received a request to reset your password for the {settings.APP_NAME}.
To choose a new password, please visit the link below:

{reset_url}

This link will expire in {settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS} hour.

If you did not request a password reset, please secure your account immediately or ignore this email.

Regards,
{self.from_name}
"""
        html_content = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; background: #0a0e1a; color: #f1f5f9; padding: 20px;">
  <div style="max-width: 560px; margin: 0 auto; background: #111827; border: 1px solid #1f293d; border-radius: 8px; padding: 24px;">
    <h2 style="color: #f59e0b; margin-top: 0;">Password Reset Request</h2>
    <p>Hello {name},</p>
    <p>A password reset request was initiated for your account. Click the button below to choose a new password:</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="{reset_url}" style="background: #f59e0b; color: #000000; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
        Reset Password
      </a>
    </div>
    <p style="font-size: 12px; color: #94a3b8;">Link: <a href="{reset_url}" style="color: #38bdf8;">{reset_url}</a></p>
    <p style="font-size: 12px; color: #64748b;">This link will expire in {settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS} hour.</p>
  </div>
</body>
</html>
"""
        return self._send(email, subject, text_content, html_content, dev_label="PASSWORD RESET LINK", link=reset_url)

    def send_security_alert(self, email: str, name: str, event_title: str, details: str) -> bool:
        """Send security notification (new login, password change, account lockout)."""
        subject = f"Security Notification: {event_title} — {settings.APP_NAME}"
        text_content = f"Hello {name},\n\nSecurity Event: {event_title}\n{details}\n\nIf this was not you, please contact your administrator immediately.\n\nRegards,\n{self.from_name}"
        html_content = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; background: #0a0e1a; color: #f1f5f9; padding: 20px;">
  <div style="max-width: 560px; margin: 0 auto; background: #111827; border: 1px solid #ef4444; border-radius: 8px; padding: 24px;">
    <h2 style="color: #ef4444; margin-top: 0;">Security Alert: {event_title}</h2>
    <p>Hello {name},</p>
    <p>{details}</p>
    <p style="font-size: 12px; color: #94a3b8;">If you did not perform this action, please reset your password and contact an administrator immediately.</p>
  </div>
</body>
</html>
"""
        return self._send(email, subject, text_content, html_content, dev_label=f"SECURITY ALERT [{event_title}]", link=None)

    def _send(self, to_email: str, subject: str, text: str, html: str, dev_label: str, link: str | None = None) -> bool:
        """Internal dispatcher between console logging and SMTP."""
        if not self.enabled:
            # Safe development console logging
            divider = "=" * 60
            logger.info(f"\n{divider}\n [DEVELOPMENT EMAIL DISPATCHER] -> {to_email}\n Subject: {subject}\n {dev_label}:\n {link if link else text}\n{divider}")
            return True

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email

            msg.attach(MIMEText(text, "plain"))
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.host, self.port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_email, [to_email], msg.as_string())
            logger.info(f"Email successfully sent to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {to_email} via SMTP: {e}")
            return False


email_service = EmailService()
