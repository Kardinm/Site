from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from Site.db.db import get_db
from Site.schemas.user import Token
from Site.web.main import authenticate_user, create_access_token

router = APIRouter(tags=["auth"])


@router.post("/token", response_model=Token)
def token(form: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    user = authenticate_user(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(user.username, user.role)

    return Token(access_token=access_token)
