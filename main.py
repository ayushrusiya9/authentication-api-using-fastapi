import uuid
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import random
from datetime import datetime, timedelta, timezone

from database import engine, Base, get_db, SignupSchema, LoginSchema, ForgotPasswordSchema, VerifyOtpSchema, ResetPasswordSchema
from models import User, Otp

import os
from dotenv import load_dotenv
from jose import jwt, JWTError

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be <= 72 characters")
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


app = FastAPI()

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES"))

def create_reset_token(user_id: str, email: str):
    expire = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)

    payload = {
        "user_id": str(user_id),
        "email": email,
        "purpose": "reset_password",
        "exp": expire
    }

    json_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return json_token

Base.metadata.create_all(bind=engine)

@app.get("/")
def home():
    return {"message": "FastAPI and PostgreSQL Working"}

@app.post("/signup/")
def signup(user: SignupSchema, db: Session = Depends(get_db)):

    existing_user = db.query(User).filter(User.email == user.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    print("Password Length:", len(user.password))
    print("Password Bytes:", len(user.password.encode("utf-8")))
    hashed_password = hash_password(user.password)
    new_user = User(
        name=user.name,
        email=user.email,
        password=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created", "user_id": new_user.id}

@app.post("/login/")
def login(user: LoginSchema, db: Session = Depends(get_db)):

    existing_user = db.query(User).filter(User.email == user.email).first()

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    if existing_user.password != user.password:
        raise HTTPException(status_code=401, detail="Invalid password")

    return {
        "message": "Login successful",
        "user_id": existing_user.id,
        "name": existing_user.name,
        "email": existing_user.email
    }

@app.post("/forgot-password/")
def forgot_password(user: ForgotPasswordSchema, db: Session = Depends(get_db)):

    existing_user = db.query(User).filter(User.email == user.email).first()

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    otp_code = str(random.randint(100000, 999999))

    old_otp = db.query(Otp).filter(Otp.email == user.email).first()
    if old_otp:
        db.delete(old_otp)
        db.commit()

    new_otp = Otp(
        email=user.email,
        otp=otp_code
    )

    db.add(new_otp)
    db.commit()

    print("OTP :", otp_code)

    return {"message": "OTP generated. Check console."}

@app.post("/verify-otp/")
def verify_otp(data: VerifyOtpSchema, db: Session = Depends(get_db)):

    otp_record = db.query(Otp).filter(Otp.email == data.email).first()

    if not otp_record:
        raise HTTPException(status_code=404, detail="Otp not found")

    expiry_time = otp_record.created_at + timedelta(minutes=5)
    now = datetime.now(timezone.utc)

    if now > expiry_time:
        db.delete(otp_record)
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired")

    if otp_record.otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = create_reset_token(user.id, user.email)

    db.delete(otp_record)
    db.commit()

    return {"message": "OTP verified successfully", "reset_token": reset_token}


@app.post("/reset-password/")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):

    try:
        payload = jwt.decode(data.reset_token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("purpose") != "reset_password":
            raise HTTPException(status_code=400, detail="Invalid token purpose")

        user_id = payload.get("user_id")

    except JWTError:
        raise HTTPException(status_code=400, detail="Token expired or invalid")

    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password = hash_password(data.new_password)
    db.commit()

    return {"message": "Password reset successfully!"}
