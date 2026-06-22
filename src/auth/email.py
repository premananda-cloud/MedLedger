"""
auth/email.py — EmailAuthModule

Responsibility: validate an email address, generate a verification code,
send it via Gmail, and return the plain code to the orchestrator.

What it does:
  ✓ Checks disposable email domains
  ✓ Generates a secure code
  ✓ Sends the code via Gmail using wholemail
  ✓ Returns the plain code to the caller

What it does NOT do:
  ✗ Store the code
  ✗ Know about users or user IDs
  ✗ Verify submitted codes (that's the orchestrator's job)
  ✗ Touch the database
"""
from __future__ import annotations

import re
import secrets

import disposable_email_domains as ded
from wholemail import (
    CodeVerificationEmailTemplate,
    EmailCodeVerifier,
    GmailEmailWorker,
)

from .models import EmailSendResult, EmailValidationResult


class EmailAuthModule:
    """
    Self-contained email auth worker.

    The caller (auth_service) passes in Gmail credentials so this module
    doesn't need to know where config lives.

    Usage:
        module = EmailAuthModule(company_name="MyApp")

        result = module.validate_and_send_code(
            email="user@example.com",
            gmail_user="noreply@myapp.com",
            gmail_app_password="xxxx xxxx xxxx xxxx",
        )

        if result.success:
            db.store(email=result.email, code=result.code, ttl=600)
        else:
            raise BadRequest(result.error)
    """

    # Simple RFC-5322 format check
    _EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    def __init__(
        self,
        company_name:          str = "AuthSystem",
        company_logo_link:     str = "",
        company_website_link:  str = "",
        customer_support_link: str = "",
        code_length:           int = 6,
    ):
        self.company_name          = company_name
        self.company_logo_link     = company_logo_link
        self.company_website_link  = company_website_link
        self.customer_support_link = customer_support_link
        self.code_length           = code_length

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def validate_email(self, email: str) -> EmailValidationResult:
        """
        Validate format and check against disposable-domain blocklist.
        Call this standalone if you want to surface errors before sending.
        """
        if not email or not self._EMAIL_RE.match(email):
            return EmailValidationResult(
                valid=False, email=email, reason="Invalid email format."
            )

        domain = email.lower().split("@")[1]
        if domain in ded.blocklist:
            return EmailValidationResult(
                valid=False, email=email,
                reason="Disposable or temporary email addresses are not accepted."
            )

        return EmailValidationResult(valid=True, email=email.lower())

    def validate_and_send_code(
        self,
        email:              str,
        gmail_user:         str,
        gmail_app_password: str,
        storage_folder:     str = "./",
    ) -> EmailSendResult:
        """
        Validate the email, generate a code, send it, and return the plain
        code to the caller.

        Args:
            email:              Recipient email address.
            gmail_user:         Sender Gmail address.
            gmail_app_password: Gmail App Password (not account password).
            storage_folder:     Folder wholemail uses for internal tracking.

        Returns:
            EmailSendResult:
              • success=True  → code contains the plain text code
              • success=False → error contains the reason
        """
        # 1. Validate format + disposable check
        validation = self.validate_email(email)
        if not validation.valid:
            return EmailSendResult(success=False, email=email, error=validation.reason)

        normalized = validation.email  # already lowercased

        # 2. Generate code
        code = self._generate_code()

        # 3. Build Gmail worker + template
        try:
            worker = GmailEmailWorker(
                email=gmail_user,
                password=gmail_app_password,
                storage_folder=storage_folder,
            )
            template = CodeVerificationEmailTemplate(
                code=code,
                company_name=self.company_name,
                company_logo_link=self.company_logo_link,
                company_website_link=self.company_website_link,
                customer_support_link=self.customer_support_link,
            )
            sent = worker.SendTemplate(
                template=template,
                subject=f"Your {self.company_name} verification code",
                recipient=normalized,
            )
        except Exception as exc:
            return EmailSendResult(
                success=False, email=normalized,
                error=f"Failed to send verification email: {exc}",
            )

        if not sent:
            return EmailSendResult(
                success=False, email=normalized,
                error="Email delivery failed. Check Gmail credentials.",
            )

        # 4. Return plain code — orchestrator stores it
        return EmailSendResult(success=True, email=normalized, code=code)

    # ──────────────────────────────────────────
    # Private
    # ──────────────────────────────────────────

    def _generate_code(self) -> str:
        """
        Generate a cryptographically secure numeric verification code.
        6 digits by default (matching wholemail's EmailCodeVerifier style).
        """
        return "".join(str(secrets.randbelow(10)) for _ in range(self.code_length))
