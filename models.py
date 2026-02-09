import datetime
from xmlrpc.client import DateTime
from sqlalchemy import Column, Integer, String
from database import Base
from sqlalchemy import TIMESTAMP, text
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime, timezone
from database import Base
from sqlalchemy.dialects.postgresql import UUID
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

class Otp(Base):
    __tablename__ = "otps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, nullable=False)
    otp = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'))

class ResetToken(Base):
    __tablename__ = "reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, index=True)
    token = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))