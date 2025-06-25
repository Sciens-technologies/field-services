import os
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content, HtmlContent
from sqlalchemy.orm import Session
from db.models import User, UserNotificationPreferences

# Set up logging
logger = logging.getLogger(__name__)

# Get email settings from environment variables
MAIL_PROVIDER = os.getenv("MAIL_PROVIDER", "smtp").lower()
MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM_ADDRESS = os.getenv("MAIL_FROM_ADDRESS")
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")


async def send_email(
    to_email: str,
    subject: str,
    plain_text: str,
    html_content: Optional[str] = None,
    ignore_preferences: bool = False,
    db: Optional[Session] = None,
) -> bool:
    """
    Sends a multipart email (text + optional HTML) via SMTP or SendGrid.
    Returns True on success, False on failure.

    Parameters:
        ignore_preferences: If True, sends email regardless of notification preferences (for critical emails)
        db: SQLAlchemy session, required if checking notification preferences
    """
    # If we're not ignoring preferences and have a db session, check notification preferences
    if not ignore_preferences and db is not None:
        # Get the user and their preferences
        user = db.query(User).filter(User.email == to_email).first()
        if user:
            prefs = (
                db.query(UserNotificationPreferences).filter_by(user_id=user.id).first()
            )
            if prefs and not bool(prefs.email_enabled):
                logger.info(f"Email not sent to {to_email} - notifications disabled")
                return False

    # Debug log to see what provider is being used
    logger.info(f"Email provider setting: '{MAIL_PROVIDER}'")

    # Check if we're in development mode with a mock provider
    if MAIL_PROVIDER.lower() == "mock":
        # Just log the email instead of sending it
        logger.info("\n=== MOCK EMAIL ===")
        logger.info(f"To: {to_email}")
        logger.info(f"Subject: {subject}")
        logger.info(f"Body: {plain_text[:100]}...")  # Show first 100 chars
        logger.info("=================\n")
        return True

    # Use SendGrid if configured
    if MAIL_PROVIDER.lower() == "sendgrid":
        if not SENDGRID_API_KEY:
            logger.error(
                "SendGrid API key not configured. Check environment variables."
            )
            return False

        try:
            # Create SendGrid message
            from_email = Email(str(MAIL_FROM_ADDRESS), str(MAIL_FROM_NAME))
            to_email_obj = To(to_email)
            content = Content("text/plain", plain_text)
            mail = Mail(from_email, to_email_obj, subject, content)

            # Add HTML content if provided
            if html_content:
                mail.add_content(HtmlContent(html_content))

            # Send email via SendGrid
            sg = SendGridAPIClient(str(SENDGRID_API_KEY))
            response = sg.send(mail)

            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Email sent successfully to {to_email} via SendGrid")
                return True
            else:
                logger.error(
                    f"SendGrid API returned status code {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Error sending email via SendGrid: {e}")
            return False

    # Default to SMTP if not using SendGrid
    # Check if email settings are configured
    if not all([MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM_ADDRESS]):
        logger.error(
            "Email settings not fully configured. Check environment variables."
        )
        return False

    # Build the message container
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = (
        f"{MAIL_FROM_NAME} <{MAIL_FROM_ADDRESS}>"
        if MAIL_FROM_NAME
        else str(MAIL_FROM_ADDRESS)
    )
    msg["To"] = to_email

    # Attach plain-text
    msg.attach(MIMEText(plain_text, "plain"))
    # Attach HTML if provided
    if html_content:
        msg.attach(MIMEText(html_content, "html"))

    try:
        # Connect to SMTP server with timeout
        if not MAIL_SERVER:
            raise ValueError("MAIL_SERVER is not configured")

        with smtplib.SMTP(str(MAIL_SERVER), MAIL_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if not MAIL_USERNAME or not MAIL_PASSWORD or not MAIL_FROM_ADDRESS:
                raise ValueError("Email credentials not fully configured")
            server.login(str(MAIL_USERNAME), str(MAIL_PASSWORD))
            server.sendmail(str(MAIL_FROM_ADDRESS), to_email, msg.as_string())
        logger.info(f"Email sent successfully to {to_email} via SMTP")
        return True

    except socket.gaierror as e:
        logger.error(f"DNS lookup failed for email server {MAIL_SERVER}: {e}")
        return False
    except socket.timeout as e:
        logger.error(f"Connection to email server {MAIL_SERVER} timed out: {e}")
        return False
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {e}")
        return False


async def send_welcome_email(email: str, username: str, first_name: str) -> bool:
    """
    Sends a welcome email to a new user.
    Returns True if successful, False otherwise.
    """
    subject = "Welcome to Field Service App"
    body = f"""Hello {first_name},\n\nWelcome to Field Service App! Your account has been created.\n\nYou can log in with your username: {username}\nLogin URL: https://yourapp.example.com/login\n\nIf you have any questions, please contact support.\n\nBest regards,\nThe Field Service App Team\n"""
    html_content = f"""\n<!DOCTYPE html>\n<html>\n<body style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;\">\n    <div style=\"background-color: #4a90e2; color: white; padding: 15px; text-align: center;\">\n        <h2>Welcome to Field Service App!</h2>\n    </div>\n    \n    <div style=\"padding: 20px; border: 1px solid #ddd;\">\n        <p>Hello {first_name},</p>\n        <p>Your account has been created successfully.</p>\n        \n        <div style=\"background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-left: 4px solid #4a90e2;\">\n            <p><strong>Username:</strong> {username}</p>\n            <p><strong>Login URL:</strong> <a href=\"https://yourapp.example.com/login\">https://yourapp.example.com/login</a></p>\n        </div>\n        \n        <p>If you have any questions, please contact support.</p>\n        \n        <p>Best regards,<br>The Field Service App Team</p>\n    </div>\n</body>\n</html>\n"""
    return await send_email(email, subject, body, html_content)


async def send_password_reset_email(email: str, username: str, reset_key: str) -> bool:
    """
    Sends a password reset email to the user.
    Returns True if successful, False otherwise.
    """
    reset_link = f"https://yourapp.example.com/reset-password?key={reset_key}"
    subject = "Password Reset Request - Field Service App"
    
    # Plain text version
    body = f"""Hello {username},

We received a request to reset your password for the Field Service App.

To reset your password, click on the following link:
{reset_link}

IMPORTANT:
- This link will expire in 24 hours
- If you did not request a password reset, please ignore this email
- For security reasons, this link can only be used once

If you have any questions or need assistance, please contact support.

Best regards,
The Field Service App Team
"""

    # HTML version with better styling
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Request - Field Service App</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
    <div style="background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden;">
        <!-- Header -->
        <div style="background-color: #dc3545; color: white; padding: 20px; text-align: center;">
            <h2 style="margin: 0; font-size: 24px;">Password Reset Request</h2>
        </div>
        
        <!-- Content -->
        <div style="padding: 30px;">
            <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Hello {username},</p>
            
            <p style="font-size: 16px; color: #333; margin-bottom: 20px;">
                We received a request to reset your password for the Field Service App.
            </p>
            
            <!-- Reset Button -->
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}" 
                   style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    Reset Your Password
                </a>
            </div>
            
            <!-- Alternative Link -->
            <div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px; margin: 20px 0;">
                <p style="font-size: 14px; color: #666; margin: 0 0 10px 0;">
                    <strong>If the button doesn't work, copy and paste this link into your browser:</strong>
                </p>
                <p style="font-size: 12px; color: #007bff; word-break: break-all; margin: 0; font-family: monospace;">
                    {reset_link}
                </p>
            </div>
            
            <!-- Security Notice -->
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 20px 0;">
                <h4 style="color: #856404; margin: 0 0 10px 0;">⚠️ IMPORTANT SECURITY INFORMATION</h4>
                <ul style="color: #856404; margin: 0; padding-left: 20px;">
                    <li>This link will expire in 24 hours</li>
                    <li>If you did not request a password reset, please ignore this email</li>
                    <li>For security reasons, this link can only be used once</li>
                    <li>Never share this link with anyone</li>
                </ul>
            </div>
            
            <p style="font-size: 14px; color: #666; margin-top: 30px;">
                If you have any questions or need assistance, please contact support.
            </p>
            
            <p style="font-size: 14px; color: #666; margin-top: 20px;">
                Best regards,<br>
                <strong>The Field Service App Team</strong>
            </p>
        </div>
        
        <!-- Footer -->
        <div style="background-color: #f8f9fa; padding: 15px; text-align: center; border-top: 1px solid #e9ecef;">
            <p style="font-size: 12px; color: #6c757d; margin: 0;">
                This is an automated message. Please do not reply to this email.
            </p>
        </div>
    </div>
</body>
</html>
"""
    
    return await send_email(email, subject, body, html_content)


async def send_temporary_password_email(
    email_to: str, username: str, temp_password: str
):
    """
    Send an email with temporary password to a newly created user.

    Args:
        email_to (str): Recipient's email address
        username (str): User's username
        temp_password (str): Temporary password generated for the user
    """
    subject = "Your Field Services Account Credentials"
    
    # Plain text version
    body = f"""Hello,

Welcome to Field Services!

Your account has been created by an administrator. Here are your login credentials:

Username: {username}
Temporary Password: {temp_password}

IMPORTANT SECURITY NOTICE:
- Please change your password immediately after your first login
- Do not share these credentials with anyone
- If you did not expect this email, please contact your administrator

Login URL: https://yourapp.example.com/login

If you have any questions or need assistance, please contact support.

Best regards,
Field Services Team
"""

    # HTML version with better styling
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your Field Services Account Credentials</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
    <div style="background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden;">
        <!-- Header -->
        <div style="background-color: #4a90e2; color: white; padding: 20px; text-align: center;">
            <h2 style="margin: 0; font-size: 24px;">Welcome to Field Services!</h2>
        </div>
        
        <!-- Content -->
        <div style="padding: 30px;">
            <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Hello,</p>
            
            <p style="font-size: 16px; color: #333; margin-bottom: 20px;">
                Your account has been created by an administrator. Here are your login credentials:
            </p>
            
            <!-- Credentials Box -->
            <div style="background-color: #f8f9fa; border: 2px solid #e9ecef; border-radius: 6px; padding: 20px; margin: 20px 0;">
                <div style="margin-bottom: 15px;">
                    <strong style="color: #495057;">Username:</strong>
                    <span style="color: #333; font-family: monospace; background-color: #e9ecef; padding: 4px 8px; border-radius: 4px; margin-left: 10px;">{username}</span>
                </div>
                <div>
                    <strong style="color: #495057;">Temporary Password:</strong>
                    <span style="color: #333; font-family: monospace; background-color: #e9ecef; padding: 4px 8px; border-radius: 4px; margin-left: 10px;">{temp_password}</span>
                </div>
            </div>
            
            <!-- Security Notice -->
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 20px 0;">
                <h4 style="color: #856404; margin: 0 0 10px 0;">⚠️ IMPORTANT SECURITY NOTICE</h4>
                <ul style="color: #856404; margin: 0; padding-left: 20px;">
                    <li>Please change your password immediately after your first login</li>
                    <li>Do not share these credentials with anyone</li>
                    <li>If you did not expect this email, please contact your administrator</li>
                </ul>
            </div>
            
            <!-- Login Button -->
            <div style="text-align: center; margin: 30px 0;">
                <a href="https://yourapp.example.com/login" 
                   style="background-color: #4a90e2; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    Login to Your Account
                </a>
            </div>
            
            <p style="font-size: 14px; color: #666; margin-top: 30px;">
                If you have any questions or need assistance, please contact support.
            </p>
            
            <p style="font-size: 14px; color: #666; margin-top: 20px;">
                Best regards,<br>
                <strong>Field Services Team</strong>
            </p>
        </div>
        
        <!-- Footer -->
        <div style="background-color: #f8f9fa; padding: 15px; text-align: center; border-top: 1px solid #e9ecef;">
            <p style="font-size: 12px; color: #6c757d; margin: 0;">
                This is an automated message. Please do not reply to this email.
            </p>
        </div>
    </div>
</body>
</html>
"""

    return await send_email(to_email=email_to, subject=subject, plain_text=body, html_content=html_content)
