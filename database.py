from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "postgresql://postgres:1234@localhost:5432/eulogik"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


from pydantic import BaseModel, Field

# Schemas for request
class SignupSchema(BaseModel):
    name: str
    email: str
    password: str = Field(..., min_length=8, max_length=72)  


class LoginSchema(BaseModel):
    email: str
    password: str


class ForgotPasswordSchema(BaseModel):
    email: str

class VerifyOtpSchema(BaseModel):
    email: str
    otp: str

class ResetPasswordSchema(BaseModel):
    reset_token:str
    new_password:str
