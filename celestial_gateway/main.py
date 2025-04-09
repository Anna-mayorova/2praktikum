from fastapi import FastAPI
from database import engine, Base
from auth import auth_router

app = FastAPI()

# подключение роутеров
app.include_router(auth_router, prefix="/api")

# создание таблиц при старте
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)