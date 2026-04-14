from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from datetime import datetime, timedelta
import database
from database import get_db, Alert

app = FastAPI(title="Security SOC Dashboard")

# Шаблоны и статика
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Главная страница дашборда"""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/api/alerts", response_model=List[dict])
def get_alerts(db: Session = Depends(get_db)):
    """Получить все алерты"""
    return db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Статистика для графиков"""
    total = db.query(Alert).count()
    by_severity = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    by_country = db.query(Alert.country, func.count(Alert.id)).group_by(Alert.country).all()

    return {
        "total_alerts": total,
        "by_severity": dict(by_severity),
        "by_country": dict(by_country)
    }


@app.post("/api/alerts")
def create_alert(alert_data: dict, db: Session = Depends(get_db)):
    """Создать новый алерт"""
    alert = Alert(**alert_data)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)