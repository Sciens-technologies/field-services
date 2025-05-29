from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from db.models import User, Role
from db.database import get_db
from api.services.users import get_current_user

def admin_required(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> User:
    role = db.query(Role).filter(Role.id == current_user.role_id).first()
    if not role or role.name not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user

def block_user(user_id: int, db: Session):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.status = "blocked"
    db.commit()
    return {"detail": "User blocked"}

def role_required(allowed_roles: list[str]):
    def wrapper(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        role = db.query(Role).filter(Role.id == current_user.role_id).first()
        if not role or role.name not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to perform this action"
            )
        return current_user
    return wrapper
