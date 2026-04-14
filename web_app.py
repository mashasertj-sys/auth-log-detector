import os
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
from pydantic import BaseModel
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", "my_super_secret_key_for_dev_only")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

app = FastAPI(
    title="SOC Dashboard",
    description="Security Operations Center Monitoring System",
    version="1.0.0"
)

templates = Jinja2Templates(directory="templates")


try:
    from database import get_db, SecurityAlert
    from sqlalchemy.orm import Session
except ImportError:
    logger.error("database.py не найден. Убедитесь, что файлы проекта на месте.")


    def get_db():
        yield None


    class SecurityAlert:
        pass

def verify_password(plain_password: str, hashed_password: str) -> bool:

    return hashed_password == plain_password


def authenticate_user(db: Session, username: str, password: str):

    if username == "admin" and password == "admin123":
        return {"username": username, "role": "admin"}
    return None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Cookie(None)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверные учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}


@app.get("/login")
async def login_page(request: Request):

    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_action(request: Request, username: str = Form(...), password: str = Form(...)):

    user = authenticate_user(None, username, password)  # None вместо db для примера

    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверный логин или пароль"
        })

    # Создаём токен
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )


    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )
    logger.info(f"User {username} logged in successfully.")
    return response


@app.get("/dashboard")
async def dashboard(request: Request, current_user: dict = Depends(get_current_user)):

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user
    })


@app.get("/api/alerts")
async def api_get_alerts(current_user: dict = Depends(get_current_user)):

    try:
        db = next(get_db())
        # Пример запроса (адаптируй под свою модель)
        # alerts = db.query(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).limit(50).all()

        # Заглушка данных, если БД пуста или не подключена
        alerts = []

        return {"status": "success", "alerts": alerts}
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/api/stats")
async def api_get_stats(current_user: dict = Depends(get_current_user)):

    try:

        stats = {
            "total_alerts": 0,
            "new_alerts": 0,
            "total_runs": 10,
            "unique_alerts": 0
        }
        return stats
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return {"total_alerts": 0, "new_alerts": 0, "total_runs": 0, "unique_alerts": 0}


@app.post("/api/alerts/add")
async def api_add_alert(request: Request, current_user: dict = Depends(get_current_user)):

    form = await request.form()
    rule = form.get("rule")
    indicator = form.get("indicator")
    technique = form.get("technique", "N/A")
    severity = form.get("severity", "LOW")

    unique_string = f"{rule}:{indicator}:{technique}"
    alert_id = hashlib.sha256(unique_string.encode()).hexdigest()[:12]

    logger.info(f"New alert added: {rule} from {indicator} (ID: {alert_id})")

    # TODO: Здесь логика сохранения в БД
    # db.add(new_alert)
    # db.commit()

    return {"status": "success", "alert_id": alert_id}

if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("SOC Dashboard Starting...")
    logger.info(f"Server running on http://{HOST}:{PORT}")
    logger.info(f"Docs available at http://{HOST}:{PORT}/docs")
    logger.info("=" * 50)

    # Безопасный запуск через env vars
    uvicorn.run(app, host=HOST, port=PORT)