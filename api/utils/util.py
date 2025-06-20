from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from api.schemas import DeviceResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from passlib.hash import bcrypt  # For password hashing
import jwt  # PyJWT for token-based authentication
from pydantic import ValidationError
from enum import Enum as PyEnum
import logging
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, Optional
from dotenv import load_dotenv
from datetime import datetime
from db.database import SessionLocal
from db.models import NotificationHistory,NotificationTemplate,ArtifactNotificationEvent,UserNotification,Device,User,DeviceAssignment
import secrets
import string


# Load environment variables
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def send_email(to_email: str, subject: str, body: str, html_content: Optional[str] = None) -> bool:
    """
    Sends an email with optional HTML content. Handles connection errors.
    Returns True if successful, False otherwise.
    """
    # Get email configuration from environment variables
    mail_server = os.getenv("MAIL_SERVER")
    mail_port = int(os.getenv("MAIL_PORT", "587"))
    mail_username = os.getenv("MAIL_USERNAME")
    mail_password = os.getenv("MAIL_PASSWORD")
    mail_from_address = os.getenv("MAIL_FROM_ADDRESS")
    mail_from_name = os.getenv("MAIL_FROM_NAME", "")

    # Ensure required variables are not None
    if mail_server is None:
        raise RuntimeError("MAIL_SERVER environment variable is not set")
    if mail_username is None:
        raise RuntimeError("MAIL_USERNAME environment variable is not set")
    if mail_password is None:
        raise RuntimeError("MAIL_PASSWORD environment variable is not set")
    if mail_from_address is None:
        raise RuntimeError("MAIL_FROM_ADDRESS environment variable is not set")

    # Build the message container
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{mail_from_name} <{mail_from_address}>" if mail_from_name else mail_from_address
    msg["To"] = to_email

    # Attach plain-text
    msg.attach(MIMEText(body, "plain"))
    # Attach HTML if provided
    if html_content:
        msg.attach(MIMEText(html_content, "html"))

    try:
        server = smtplib.SMTP(mail_server, mail_port)
        server.starttls()  # Secure the connection
        server.login(mail_username, mail_password)
        server.sendmail(mail_from_address, [to_email], msg.as_string())
        server.quit()
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {e}")
        print(f"[send_email] Failed to send to {to_email}: {e}")
        return False


def generate_secure_password(length=12):
    """
    Generates a secure random password with the specified length.
    Includes uppercase, lowercase, digits, and special characters.
    """
    import secrets
    import string
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*"
    
    # Ensure at least one character from each set
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle the password characters
    secrets.SystemRandom().shuffle(password)
    
    # Convert list to string
    return ''.join(password)

def log_notification(db, user_id: int, notif_type: str, event: str, message: str, status: str):
    notif = NotificationHistory(
        user_id=user_id,
        type=notif_type,
        event=event,
        message=message,
        status=status,
    )
    db.add(notif)
    db.commit()


def generate_random_password(length: int = 12) -> str:
    """
    Generate a secure random password.
    
    Args:
        length (int): Length of the password. Defaults to 12.
        
    Returns:
        str: A secure random password containing uppercase, lowercase, digits and special characters.
    """
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one character from each set
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle the password
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)

def trigger_device_block_notification(db, device, reason, admin_user):
    pass

def user_is_agent(user):
    return True
