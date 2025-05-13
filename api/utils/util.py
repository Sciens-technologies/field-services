from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr

from passlib.hash import bcrypt  # For password hashing
import jwt  # PyJWT for token-based authentication
from pydantic import ValidationError
from enum import Enum as PyEnum
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict

from db.database import SessionLocal



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def send_email(to_email: str, subject: str, body: str) -> None:
    """Sends an email.  Handles connection errors."""
    msg = MIMEText(body, 'plain')
    msg['Subject'] = subject
    msg['From'] = MAIL_FROM_ADDRESS
    msg['To'] = to_email

    try:
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.starttls()  # Secure the connection
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_FROM_ADDRESS, [to_email], msg.as_string())
        server.quit()
        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Error sending email to {to_email}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {e}")  # Raise to notify caller
