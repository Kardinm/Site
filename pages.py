from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from Site.db.db import get_db
from Site.models.user import User
from Site.web.main import hash_password, authenticate_user, create_access_token,get_current_user, require_admin, get_user_by_username


templates = Jinja2Templates(directory="app/templates")
router = APIRouter(tags=["pages"])


@router.get("/")
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})
  

@router.get("/register")
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})
  

@router.post("/register")
def register(username: str = Form(...), password: str = Form(...), db = Depends(get_db)):
    username = username.strip()
    if len(username) < 3:
        raise HTTPException(400, "Username too short")
    if get_user_by_username(db, username):
        raise HTTPException(400, "Username already exists")

    user = User(username=username, hashed_password=hash_password(password), role="user")
    db.add(user)
    db.commit()
  
    return RedirectResponse("/login", status_code=303)
  

@router.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
  

@router.post("/login")
def login(username: str = Form(...), password: str = Form(...), db = Depends(get_db)):
    user = authenticate_user(db, username.strip(), password)
    if not user:
        raise HTTPException(status_code=401, detail="Bad credentials")

    token = create_access_token(user.username, user.role)
    resp = RedirectResponse("/me", status_code=303)
    resp.set_cookie("access_token", token, httponly=True, samesite="lax")
  
    return resp


@router.post("/logout")
def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie("access_token")
  
    return resp


@router.get("/me")
def me(request: Request, user = Depends(get_current_user)):
    return templates.TemplateResponse("me.html", {"request": request, "user": user})
  

@router.get("/admin")
def admin(request: Request, user = Depends(require_admin)):
    return templates.TemplateResponse("admin.html", {"request": request, "user": user})
