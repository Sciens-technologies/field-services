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
MAIL_PROVIDER     = os.getenv("MAIL_PROVIDER", "smtp").lower()
MAIL_SERVER       = os.getenv("MAIL_SERVER")
MAIL_PORT         = int(os.getenv("MAIL_PORT", 587))
MAIL_USERNAME     = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD     = os.getenv("MAIL_PASSWORD")
MAIL_FROM_ADDRESS = os.getenv("MAIL_FROM_ADDRESS")
MAIL_FROM_NAME    = os.getenv("MAIL_FROM_NAME", "")
SENDGRID_API_KEY  = os.getenv("SENDGRID_API_KEY")

def send_email(
    to_email: str,
    subject: str,
    plain_text: str,
    html_content: Optional[str] = None,
    ignore_preferences: bool = False,
    db: Optional[Session] = None
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
            prefs = db.query(UserNotificationPreferences).filter_by(user_id=user.id).first()
            if prefs and not prefs.email_enabled:
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
            logger.error("SendGrid API key not configured. Check environment variables.")
            return False
            
        try:
            # Create SendGrid message
            from_email = Email(MAIL_FROM_ADDRESS, MAIL_FROM_NAME)
            to_email = To(to_email)
            content = Content("text/plain", plain_text)
            mail = Mail(from_email, to_email, subject, content)
            
            # Add HTML content if provided
            if html_content:
                mail.add_content(HtmlContent(html_content))
                
            # Send email via SendGrid
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(mail)
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Email sent successfully to {to_email.email} via SendGrid")
                return True
            else:
                logger.error(f"SendGrid API returned status code {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending email via SendGrid: {e}")
            return False
    
    # Default to SMTP if not using SendGrid
    # Check if email settings are configured
    if not all([MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM_ADDRESS]):
        logger.error("Email settings not fully configured. Check environment variables.")
        return False
        
    # Build the message container
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{MAIL_FROM_NAME} <{MAIL_FROM_ADDRESS}>" if MAIL_FROM_NAME else MAIL_FROM_ADDRESS
    msg["To"]      = to_email

    # Attach plain-text
    msg.attach(MIMEText(plain_text, "plain"))
    # Attach HTML if provided
    if html_content:
        msg.attach(MIMEText(html_content, "html"))

    try:
        # Connect to SMTP server with timeout
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(
                MAIL_FROM_ADDRESS,
                to_email,
                msg.as_string()
            )
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

def send_welcome_email(email: str, username: str, first_name: str) -> bool:
    """
    Sends a welcome email to a new user.
    Returns True if successful, False otherwise.
    """
    subject = "Welcome to Field Service App"
    
    # Create plain text email body
    body = f"""Hello {first_name},

Welcome to Field Service App! Your account has been created.

You can log in with your username: {username}
Login URL: https://yourapp.example.com/login

If you have any questions, please contact support.

Best regards,
The Field Service App Team
"""

    # Create HTML email body
    html_content = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #4a90e2; color: white; padding: 15px; text-align: center;">
        <h2>Welcome to Field Service App!</h2>
    </div>
    
    <div style="padding: 20px; border: 1px solid #ddd;">
        <p>Hello {first_name},</p>
        <p>Your account has been created successfully.</p>
        
        <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-left: 4px solid #4a90e2;">
            <p><strong>Username:</strong> {username}</p>
            <p><strong>Login URL:</strong> <a href="https://yourapp.example.com/login">https://yourapp.example.com/login</a></p>
        </div>
        
        <p>If you have any questions, please contact support.</p>
        
        <p>Best regards,<br>The Field Service App Team</p>
    </div>
</body>
</html>
"""
    
    return send_email(email, subject, body, html_content)

def send_password_reset_email(email: str, username: str, reset_key: str) -> bool:
    """
    Sends a password reset email to the user.
    Returns True if successful, False otherwise.
    """
    reset_link = f"https://yourapp.example.com/reset-password?key={reset_key}"
    subject = "Password Reset Request - Field Service App"
    
    # Create plain text email body
    body = f"""Hello {username},

We received a request to reset your password for the Field Service App.

To reset your password, click on the following link:
{reset_link}

If you did not request a password reset, please ignore this email.

Best regards,
The Field Service App Team
"""

    # Create HTML email body
    html_content = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #4a90e2; color: white; padding: 15px; text-align: center;">
        <h2>Password Reset Request</h2>
    </div>
    
    <div style="padding: 20px; border: 1px solid #ddd;">
        <p>Hello {username},</p>
        <p>We received a request to reset your password for the Field Service App.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_link}" style="background-color: #4a90e2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                Reset Your Password
            </a>
        </div>
        
        <p>If you did not request a password reset, please ignore this email.</p>
        
        <p>Best regards,<br>The Field Service App Team</p>
    </div>
</body>
</html>
"""
    
    return send_email(email, subject, body, html_content)

def send_temporary_password_email(email: str, username: str, temp_password: str) -> bool:
    """
    Sends an email with a temporary password to the user.
    Returns True if successful, False otherwise.
    """
    subject = "Your Temporary Password - Field Service App"
    
    # Create plain text email body
    body = f"""Hello {username},

A temporary password has been generated for your Field Service App account.

Your temporary password is: {temp_password}

Please log in and change your password immediately.

Best regards,
The Field Service App Team
"""

    # Create HTML email body
    html_content = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #4a90e2; color: white; padding: 15px; text-align: center;">
        <h2>Temporary Password</h2>
    </div>
    
    <div style="padding: 20px; border: 1px solid #ddd;">
        <p>Hello {username},</p>
        <p>A temporary password has been generated for your Field Service App account.</p>
        
        <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-left: 4px solid #4a90e2;">
            <p><strong>Temporary Password:</strong> {temp_password}</p>
        </div>
        
        <p>Please log in and change your password immediately.</p>
        
        <p>Best regards,<br>The Field Service App Team</p>
    </div>
</body>
</html>
"""
    
    return send_email(email, subject, body, html_content)


















