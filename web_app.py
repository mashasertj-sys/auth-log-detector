from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
import json
import os
from pathlib import Path
from database import get_db, SecurityAlert, engine
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SECRET_KEY = "your-super-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="SOC Dashboard", docs_url=None, redoc_url=None)

templates = Jinja2Templates(directory="templates")

DATA_DIR = Path(__file__).parent
HISTORY_FILE = DATA_DIR / "alerts_history.json"

USERS_DB = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "full_name": "SOC Administrator"
    }
}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("access_token")
    if not token:
        return None

    try:
        if token.startswith("Bearer "):
            token = token[7:]

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return USERS_DB.get(username)
    except JWTError:
        return None

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = USERS_DB.get(username)
    if not user or user["password"] != password:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверное имя пользователя или пароль"
        })

    access_token = create_access_token(data={"sub": user["username"]})
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=1800)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    current_user = await get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    total_alerts = db.query(SecurityAlert).count()
    new_alerts = db.query(SecurityAlert).filter(SecurityAlert.is_new == True).count()
    unique_alerts = db.query(SecurityAlert.alert_id).distinct().count()

    stats = {
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "total_runs": 10,
        "unique_alerts": unique_alerts
    }

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "alerts": [],
        "stats": stats,
        "user": current_user
    })

@app.get("/api/alerts")
async def api_get_alerts(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    alerts = db.query(SecurityAlert).order_by(SecurityAlert.last_seen.desc()).all()

    return {
        "alerts": [
            {
                "id": alert.id,
                "alert_id": alert.alert_id,
                "rule": alert.rule_name,
                "severity": alert.severity,
                "indicator": alert.indicator,
                "count": alert.count,
                "technique": alert.technique,
                "is_new": alert.is_new,
                "timestamp": alert.last_seen.isoformat(),
                "first_seen": alert.first_seen.isoformat()
            }
            for alert in alerts
        ]
    }


@app.get("/api/stats")
async def api_get_stats(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    total = db.query(SecurityAlert).count()
    new = db.query(SecurityAlert).filter(SecurityAlert.is_new == True).count()
    unique = db.query(SecurityAlert.alert_id).distinct().count()

    return {
        "total_alerts": total,
        "new_alerts": new,
        "unique_alerts": unique,
        "total_runs": 10
    }

@app.post("/api/alerts/add")
async def api_add_alert(
        rule: str = Form(...),
        severity: str = Form(...),
        indicator: str = Form(...),
        count: int = Form(...),
        technique: str = Form(None),
        db: Session = Depends(get_db)
):
    import hashlib

    alert_id = hashlib.md5(f"{rule}:{indicator}:{technique}".encode()).hexdigest()[:8] # nosec B324

    existing = db.query(SecurityAlert).filter(SecurityAlert.alert_id == alert_id).first()

    if existing:
        existing.count = count
        existing.last_seen = datetime.now(timezone.utc)
        existing.is_new = False
        db.commit()
        db.refresh(existing)
        return {"status": "updated", "id": existing.id}
    else:
        alert = SecurityAlert(
            alert_id=alert_id,
            rule_name=rule,
            severity=severity,
            indicator=indicator,
            count=count,
            technique=technique,
            is_new=True
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return {"status": "created", "id": alert.id}

@app.get("/api/security/scan")
async def api_run_scan(current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    scanner = OWASPScanner(str(DATA_DIR))
    findings = scanner.scan_all()

    return {
        "status": "complete",
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        }
    }


@app.get("/api/security/findings")
async def api_get_findings(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    report_file = DATA_DIR / "security_scan_report.json"
    if report_file.exists():
        with open(report_file, "r") as f:
            return json.load(f)
    return {"findings": [], "summary": {"total": 0}}


@app.post("/api/security/scan/run")
async def api_trigger_scan(current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    scanner = OWASPScanner(str(DATA_DIR))
    findings = scanner.scan_all()

    report = scanner.generate_report("json")
    with open(DATA_DIR / "security_scan_report.json", "w") as f:
        f.write(report)

    return {"status": "completed", "findings_count": len(findings)}

if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print(" SOC Dashboard with Database starting...")
    print(" Open http://localhost:8000 or http://YOUR_IP:8000")
    print(" Login: admin")
    print(" Password: admin123")
    print(" Database: security_alerts.db")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000) # nosec B104