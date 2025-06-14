from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from db.models import User, Role, UserStatusAudit
from db.database import get_db
from api.services.users import get_current_user
import datetime

def block_user(user_id: int, db: Session, current_user: User):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store old status for audit
    old_status = user.status
    
    # Update user status
    user.status = "BLOCKED"
    user.updated_at = datetime.datetime.utcnow()
    user.last_modified_by = current_user.username
    
    # Create status audit record
    audit = UserStatusAudit(
        user_id=user.user_id,
        changed_by=current_user.username,
        old_status=old_status,
        new_status="BLOCKED",
        reason="User blocked by admin",
        changed_at=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {"detail": "User blocked successfully"}

