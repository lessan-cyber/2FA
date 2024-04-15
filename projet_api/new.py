import base64
import io
import secrets
from typing import Optional
from pydantic import BaseModel
import qrcode
from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from pyotp import TOTP
from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy import String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

Base = declarative_base()
engine = create_engine('sqlite:///./2fa.db')
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class User(Base):
    __tablename__ = 'users'
    user_id = Column(String, primary_key=True, index=True)
    secret_key = Column(String, index=True)


class UserIn(BaseModel):
    secret_key: str

Base.metadata.create_all(bind=engine)

app = FastAPI()


class TwoFactorAuth:
    def __init__(self, user_id: str, secret_key: str):
        self._user_id = user_id
        self._secret_key = secret_key
        self._totp = TOTP(self._secret_key)
        self._qr_cache: Optional[bytes] = None

    @property
    def totp(self) -> TOTP:
        return self._totp

    @property
    def secret_key(self) -> str:
        return self._secret_key

    @staticmethod
    def _generate_secret_key() -> str:
        secret_bytes = secrets.token_bytes(20)
        secret_key = base64.b32encode(secret_bytes).decode('utf-8')
        return secret_key

    @staticmethod
    def get_or_create_secret_key(db, user_id: str) -> str:
        db_user = db.query(User).filter(User.user_id == user_id).first()
        if db_user:
            return db_user.secret_key
        secret_key = TwoFactorAuth._generate_secret_key()
        db.add(User(user_id=user_id, secret_key=secret_key))
        db.commit()
        return secret_key

    def _create_qr_code(self) -> bytes:
        uri = self.totp.provisioning_uri(
            name=self._user_id,
            issuer_name='2FA',
        )
        img = qrcode.make(uri)
        img_byte_array = io.BytesIO()
        img.save(img_byte_array, format='PNG')
        img_byte_array.seek(0)
        return img_byte_array.getvalue()

    @property
    def qr_code(self) -> bytes:
        if self._qr_cache is None:
            self._qr_cache = self._create_qr_code()
        return self._qr_cache

    def verify_totp_code(self, totp_code: str) -> bool:
        return self.totp.verify(totp_code)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_two_factor_auth(user_id: str, db=Depends(get_db)) -> TwoFactorAuth:
    secret_key = TwoFactorAuth.get_or_create_secret_key(db, user_id)
    return TwoFactorAuth(user_id, secret_key)


@app.post('/add-user')
def add_user(user_data: UserIn, db: Session = Depends(get_db)):
    try:
        new_user = User(secret_key=user_data.secret_key)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {'user_id': new_user.user_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get('/get-user/{user_id}')
def get_user(user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail='User not found')
    return {'user_id': user.user_id, 'secret_key': user.secret_key}

@app.post('/enable-2fa/{user_id}')
def enable_2fa(two_factor_auth: TwoFactorAuth = Depends(get_two_factor_auth)):
    return {'secret_key': two_factor_auth.secret_key}


@app.get('/generate-qr/{user_id}')
def generate_qr(two_factor_auth: TwoFactorAuth = Depends(get_two_factor_auth)):
    qr_code = two_factor_auth.qr_code
    if qr_code is None:
        raise HTTPException(status_code=404, detail='User not found')
    return StreamingResponse(io.BytesIO(qr_code), media_type='image/png')


@app.post('/verify-totp/{user_id}')
def verify_totp(
    totp_code: str,
    two_factor_auth: TwoFactorAuth = Depends(get_two_factor_auth),
):
    is_valid = two_factor_auth.verify_totp_code(totp_code)
    if not is_valid:
        raise HTTPException(status_code=400, detail='Code invalid')
    return {'valid': is_valid}