# accounts/emails.py
import os
from dotenv import load_dotenv
load_dotenv()
from django.conf import settings
from django.urls import reverse

def build_verify_url(temp_user):
    path = reverse("accounts:verify")
    return f"{settings.SITE_URL}{path}?token={temp_user.verification_token}"

def send_verification_email(temp_user):
    # Send via SendGrid API
    # pip install sendgrid
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail

    verify_url = build_verify_url(temp_user)
    subject = "Verify your Afrobeutic account"
    body = (
        f"Hi {temp_user.first_name or temp_user.email},\n\n"
        f"Thanks for signing up for Afrobeutic. Please verify your email within the next hour:\n\n"
        f"{verify_url}\n\n"
        f"If you didn't request this, you can ignore this email."
    )

    message = Mail(
        from_email=settings.DEFAULT_FROM_EMAIL,
        to_emails=temp_user.email,
        subject=subject,
        plain_text_content=body
    )
    sg = SendGridAPIClient(os.environ["SENDGRID_API_KEY"])
    sg.send(message)
    return verify_url
