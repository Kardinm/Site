from fastapi import FastAPI

from Site.db.db import Base, engine, SessionLocal
from Site.models.user import User
from Site.web.main import ADMIN_USERNAME, ADMIN_PASSWORD, hash_password

from Site.routers.auth import router as auth_router
from Site.routers.pages import router as pages_router

app = FastAPI(title="Так")

app.include_router(auth_router)
app.include_router(pages_router)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        admin = db.query(User).filter(User.username == ADMIN_USERNAME).first()
        if not admin:
            db.add(User(
                username=ADMIN_USERNAME,
                hashed_password=hash_password(ADMIN_PASSWORD),
                role="admin"
            ))
            db.commit()
