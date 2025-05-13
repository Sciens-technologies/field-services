from fastapi import APIRouter, Depends, status
from api.schemas import *
from api.services.users import *
from api.utils.util import get_db
from sqlalchemy.orm import Session


router = APIRouter(prefix='/users', tags=['users'])


@router.post("/", response_model=UserResponse, dependencies=[Depends(has_role([UserRole.SUPER_ADMIN]))])
async def create_user_account(user: UserCreate, db: Session = Depends(get_db)):
    """
    Creates a new user account.  Only accessible by super admins.
    """
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    password = generate_password()
    hashed_password = bcrypt.hash(password)
    new_user = create_user(db, user, hashed_password)

    # Send email notification (handled in helper, exceptions raised)
    email_subject = "Your New Account Information"
    email_body = f"Your account has been created with the following details:\n\n" \
                 f"Email: {user.email}\n" \
                 f"Password: {password}\n\n" \
                 f"Please log in and change your password."
    send_email(user.email, email_subject, email_body)  # send email

    return new_user



@router.get("/", response_model=List[UserResponse], dependencies=[Depends(has_role([UserRole.SUPER_ADMIN]))])
async def get_all_users(db: Session = Depends(get_db)):
    """
    Retrieves all users. Only accessible by super admins.
    """
    return db.query(User).all()



@router.get("/{user_id}", response_model=UserResponse, dependencies=[Depends(has_role([UserRole.SUPER_ADMIN]))])
async def get_user(user_id: int, db: Session = Depends(get_db)):
    """
    Retrieves a specific user by ID. Only accessible by super admins.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



@router.put("/{user_id}", response_model=UserResponse, dependencies=[Depends(has_role([UserRole.SUPER_ADMIN]))])
async def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    """
    Updates a user's details.  Only accessible by super admins.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.email = user_update.email
    user.first_name = user_update.first_name
    user.last_name = user_update.last_name
    user.role = user_update.role
    user.is_active = user_update.is_active
    user.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user



@router.delete("/{user_id}", dependencies=[Depends(has_role([UserRole.SUPER_ADMIN]))])
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    Deletes a user. Only accessible by super admins.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}



def create_token_entry(db: Session, user_id: int, access_token: str, refresh_token: str, expires_at: datetime.datetime) -> Token:
    """Creates a token entry in the database."""
    token = Token(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token



def generate_tokens(user_id: int, email: str, role: UserRole) -> dict:
    """Generates access and refresh tokens."""
    access_token = create_jwt_token(user_id, email, role, JWT_ACCESS_TOKEN_EXPIRES_IN)
    refresh_token = create_jwt_token(user_id, email, role, JWT_REFRESH_TOKEN_EXPIRES_IN)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_token_expires_in": JWT_ACCESS_TOKEN_EXPIRES_IN,
        "refresh_token_expires_in": JWT_REFRESH_TOKEN_EXPIRES_IN,
    }

def create_login_activity(db: Session, user_id: int) -> LoginActivity:
    """Creates a login activity record."""
    login_activity = LoginActivity(user_id=user_id, login_time=datetime.datetime.utcnow())
    db.add(login_activity)
    db.commit()
    db.refresh(login_activity)
    return login_activity

def update_logout_activity(db: Session, user_id: int) -> None:
    """Updates the logout time for the most recent login activity record."""
    login_activity = db.query(LoginActivity).filter(LoginActivity.user_id == user_id, LoginActivity.logout_time == None).order_by(LoginActivity.login_time.desc()).first() # noqa: E711
    if login_activity:
        login_activity.logout_time = datetime.datetime.utcnow()
        db.commit()

@router.post("/login/", response_model=TokenSchema)
async def login(user_credentials: Loginrequest, db: Session = Depends(get_db)):
    """
    Logs in a user and returns access and refresh tokens.
    Accessible to managers and agents.
    """
    user = get_user_by_email(db, user_credentials.email)
    if not user or not bcrypt.verify(user_credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User is deactivated")

    tokens = generate_tokens(user.id, user.email, user.role)
    access_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_ACCESS_TOKEN_EXPIRES_IN)
    create_token_entry(db, user.id, tokens["access_token"], tokens["refresh_token"], access_token_expires_at)
    create_login_activity(db, user.id) #create login activity

    return TokenSchema(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        expires_in=JWT_ACCESS_TOKEN_EXPIRES_IN,
    )



@router.post("/refresh-token/", response_model=TokenSchema)
async def refresh_token(refresh_token, db: Session = Depends(get_db)):
    """
    Refreshes the access token using a valid refresh token.
    """
    try:
        payload = decode_jwt_token(refresh_token)
        user_id = int(payload.get("sub"))
        user = get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if the refresh token exists and is not expired
        token_record = db.query(Token).filter(Token.refresh_token == refresh_token, Token.user_id == user_id).first()
        if not token_record:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if token_record.expires_at < datetime.datetime.utcnow():
            raise HTTPException(status_code=401, detail="Refresh token has expired")

        # Generate new tokens
        tokens = generate_tokens(user.id, user.email, user.role)
        access_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_ACCESS_TOKEN_EXPIRES_IN)

        # Update the existing token record with new access and refresh tokens
        token_record.access_token = tokens["access_token"]
        token_record.refresh_token = tokens["refresh_token"]
        token_record.expires_at = access_token_expires_at
        token_record.updated_at = datetime.datetime.utcnow()
        db.commit()
        db.refresh(token_record)

        return TokenSchema(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            expires_in=JWT_ACCESS_TOKEN_EXPIRES_IN,
        )

    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid refresh token: {e}")



@router.post("/logout/", dependencies=[Depends(get_current_user)])
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Logs out the current user by deleting their tokens.
    """
    tokens = db.query(Token).filter(Token.user_id == current_user.id).all()
    for token in tokens:
        db.delete(token)
    db.commit()
    update_logout_activity(db, current_user.id)
    return {"message": "Logged out successfully"}



@router.post("/change-password/", dependencies=[Depends(get_current_user)])
async def change_password(password_change_request: ChangePasswordRequest, current_user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """
    Allows a user to change their password.
    """
    if not bcrypt.verify(password_change_request.old_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid old password")
    new_hashed_password = bcrypt.hash(password_change_request.new_password)
    current_user.hashed_password = new_hashed_password
    current_user.updated_at = datetime.datetime.utcnow()
    db.commit()
    return {"message": "Password changed successfully"}



@router.put("/profile/", response_model=UserResponse, dependencies=[Depends(get_current_user)])
async def update_profile(profile_update: UpdateProfileRequest, current_user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """
    Allows a user to update their first and last names.
    """
    current_user.first_name = profile_update.first_name
    current_user.last_name = profile_update.last_name
    current_user.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(current_user)
    return current_user