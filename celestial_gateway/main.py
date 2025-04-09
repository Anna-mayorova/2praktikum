from fastapi import FastAPI
from database import engine, Base
from auth import auth_router
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

app = FastAPI()

# обработчк ошибок в ноорм формате
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={"detail": "Validation error", "errors": exc.errors()},
    )


@app.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)

app.include_router(auth_router)

@app.get("/")
def root():
    return {
        "message": "Доступные команды для выаолнения ( в /docs ) ",
        "endpoints": {
            "signup": "/sign-up/",
            "docs": "/docs",
            "healthcheck": "/"},
            "TODO": {
                '1 - сделано ': '/login',
                '2': '/user/me/',
                '3':'"/shortest-path/", response_model=PathResult'
                    }
        }

