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


def generate_random_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def send_notification(to_user, subject: str, body: str) -> None:
    """
    Replace this stub with your real implementation:
    • SMTP / SendGrid
    • Firebase push
    • Twilio SMS
    • Kafka/RabbitMQ topic, etc.
    """
    logger.info("📨  Sent notification to %s <%s>", to_user.user_id, to_user.email)


def trigger_device_block_notification(
    db: Session,
    device: Device,
    reason: str,
    admin_user: User
):
    # ✅ Step 1: Get latest active assignment
    assignment = (
        db.query(DeviceAssignment)
        .filter(
            DeviceAssignment.device_id == device.device_id,
            DeviceAssignment.active == True
        )
        .order_by(desc(DeviceAssignment.assigned_at))
        .first()
    )

    assigned_user_id = assignment.user_id if assignment else None
    print(f"[DEBUG] Assigned user ID: {assigned_user_id}")
    if not assigned_user_id:
        print("[DEBUG] No assigned user, skipping notification.")
        return

    # ✅ Step 2: Get notification template
    template = (
        db.query(NotificationTemplate)
        .filter(
            NotificationTemplate.template_key == "DEVICE_BLOCKED",
            NotificationTemplate.active == True
        )
        .first()
    )

    if not template:
        print("[DEBUG] Notification template 'DEVICE_BLOCKED' not found")
        raise HTTPException(status_code=500, detail="Notification template not found")

    print("[DEBUG] Template found. Creating notification event...")

    # ✅ Get admin name fallback
    admin_name = (
        getattr(admin_user, "full_name", None)
        or getattr(admin_user, "name", None)
        or f"{getattr(admin_user, 'first_name', '')} {getattr(admin_user, 'last_name', '')}".strip()
        or getattr(admin_user, "email", "Admin")
    )

    # ✅ Step 3: Metadata for template formatting
    metadata = {
        "device_id": device.device_id,
        "serial": device.serial_number or "N/A",
        "reason": reason,
        "admin": admin_name,
    }

    # ✅ Step 4: Create notification event
    event = ArtifactNotificationEvent(
        template_id=template.template_id,
        initiated_by=admin_user.user_id,
        notification_scope="INDIVIDUAL",
        target_type="USER",
        target_value=str(assigned_user_id),
        custom_metadata=metadata,
    )
    db.add(event)
    db.flush()

    # ✅ Step 5: Prepare title/message from template
    title = template.subject.format(**metadata)
    message = template.content.format(**metadata)

    # ✅ Step 6: Create user notification
    notification = UserNotification(
        user_id=assigned_user_id,
        template_id=template.template_id,
        title=title,
        message=message,
        notification_metadata={"event_id": event.event_id, **metadata},
        status="PENDING",
        created_at=datetime.utcnow()
    )
    db.add(notification)
    db.flush()

    print(f"[DEBUG] Notification created for userid={assigned_user_id}")

def user_is_agent(user: User) -> bool:
    """Check if the user has the AGENT role."""
    return any(
        user_role.role and user_role.role.role_name == "AGENT"
        for user_role in user.roles
    )