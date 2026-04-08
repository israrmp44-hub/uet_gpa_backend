"""
UET GPA Calculator — FastAPI Backend
Deploy on Railway or Render (free tier)
Set environment variables: DATABASE_URL, SECRET_KEY
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import psycopg2.extras
import os, hashlib, secrets, jwt
from datetime import datetime, timedelta, date
from typing import Optional

app = FastAPI(title="UET GPA Calculator API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "uet-gpa-change-this-secret-2024")
DATABASE_URL = os.getenv("DATABASE_URL")  # Set this on Railway/Render
security = HTTPBearer()

GRADE_MAP = {
    "A+": 4.0, "A": 4.0, "A-": 3.7,
    "B+": 3.3, "B": 3.0, "B-": 2.7,
    "C+": 2.3, "C": 2.0, "C-": 1.7,
    "D+": 1.3, "D": 1.0, "F": 0.0
}

# ──────────────────────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            name            VARCHAR(100) NOT NULL,
            email           VARCHAR(100) UNIQUE NOT NULL,
            password_hash   VARCHAR(200) NOT NULL,
            salt            VARCHAR(50)  NOT NULL,
            role            VARCHAR(20)  DEFAULT 'student',
            is_active       BOOLEAN      DEFAULT FALSE,
            subscription_end DATE,
            created_at      TIMESTAMP    DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS payments (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            transaction_id  VARCHAR(100) UNIQUE NOT NULL,
            amount          DECIMAL(10,2) DEFAULT 5.00,
            status          VARCHAR(20)  DEFAULT 'pending',
            submitted_at    TIMESTAMP    DEFAULT NOW(),
            verified_at     TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS semesters (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name            VARCHAR(50)  NOT NULL,
            created_at      TIMESTAMP    DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS courses (
            id              SERIAL PRIMARY KEY,
            semester_id     INTEGER REFERENCES semesters(id) ON DELETE CASCADE,
            name            VARCHAR(100) NOT NULL,
            grade           VARCHAR(5)   NOT NULL,
            credit_hours    INTEGER      NOT NULL,
            grade_points    DECIMAL(3,1) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_history (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            login_time      TIMESTAMP    DEFAULT NOW()
        );
    """)
    # Default admin
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256(f"admin123{salt}".encode()).hexdigest()
    cur.execute("""
        INSERT INTO users (name, email, password_hash, salt, role, is_active)
        VALUES ('Admin', 'admin@uet.edu.pk', %s, %s, 'admin', TRUE)
        ON CONFLICT (email) DO NOTHING
    """, (pw_hash, salt))
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database initialized")

# ──────────────────────────────────────────────────────────────
# AUTH HELPERS
# ──────────────────────────────────────────────────────────────
def hash_pw(password: str, salt: str) -> str:
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

def create_token(user_id: int, role: str) -> str:
    payload = {"user_id": user_id, "role": role,
                "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")

def require_admin(token=Depends(verify_token)):
    if token["role"] != "admin":
        raise HTTPException(403, "Admin access only")
    return token

# ──────────────────────────────────────────────────────────────
# REQUEST MODELS
# ──────────────────────────────────────────────────────────────
class RegisterReq(BaseModel):
    name: str
    email: str
    password: str

class LoginReq(BaseModel):
    email: str
    password: str

class PaymentReq(BaseModel):
    transaction_id: str

class SemesterReq(BaseModel):
    name: str

class CourseReq(BaseModel):
    semester_id: int
    name: str
    grade: str
    credit_hours: int

class PaymentActionReq(BaseModel):
    payment_id: int
    action: str   # 'approve' or 'reject'

class DeleteCourseReq(BaseModel):
    course_id: int

# ──────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ──────────────────────────────────────────────────────────────
@app.post("/auth/register")
def register(req: RegisterReq, conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (req.email,))
    if cur.fetchone():
        raise HTTPException(400, "Email already registered")
    salt = secrets.token_hex(16)
    pw_hash = hash_pw(req.password, salt)
    cur.execute(
        "INSERT INTO users (name, email, password_hash, salt) VALUES (%s,%s,%s,%s) RETURNING id",
        (req.name, req.email.lower().strip(), pw_hash, salt)
    )
    user_id = cur.fetchone()[0]
    conn.commit()
    return {"message": "Registered! Please pay 5 PKR via EasyPaisa to activate.", "user_id": user_id}

@app.post("/auth/login")
def login(req: LoginReq, conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email=%s", (req.email.lower().strip(),))
    user = cur.fetchone()
    if not user or hash_pw(req.password, user["salt"]) != user["password_hash"]:
        raise HTTPException(401, "Incorrect email or password")
    if user["role"] == "student":
        if not user["is_active"]:
            raise HTTPException(403, "INACTIVE: Pay 5 PKR via EasyPaisa and submit Transaction ID")
        if user["subscription_end"] and user["subscription_end"] < date.today():
            raise HTTPException(403, "EXPIRED: Your subscription has expired. Please renew.")
    cur.execute("INSERT INTO login_history (user_id) VALUES (%s)", (user["id"],))
    conn.commit()
    days_left = None
    if user["subscription_end"]:
        days_left = (user["subscription_end"] - date.today()).days
    return {
        "token": create_token(user["id"], user["role"]),
        "role": user["role"],
        "name": user["name"],
        "days_left": days_left
    }

# ──────────────────────────────────────────────────────────────
# PAYMENT ENDPOINTS
# ──────────────────────────────────────────────────────────────
@app.post("/payment/submit")
def submit_payment(req: PaymentReq, token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("SELECT id FROM payments WHERE transaction_id=%s", (req.transaction_id,))
    if cur.fetchone():
        raise HTTPException(400, "This Transaction ID has already been used")
    cur.execute("INSERT INTO payments (user_id, transaction_id) VALUES (%s,%s)",
                (token["user_id"], req.transaction_id))
    conn.commit()
    return {"message": "Payment submitted. Admin will verify within 24 hours."}

@app.get("/payment/status")
def payment_status(token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM payments WHERE user_id=%s ORDER BY submitted_at DESC LIMIT 1",
                (token["user_id"],))
    row = cur.fetchone()
    return dict(row) if row else {"status": "none"}

# ──────────────────────────────────────────────────────────────
# GPA ENDPOINTS
# ──────────────────────────────────────────────────────────────
@app.get("/gpa/semesters")
def get_semesters(token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM semesters WHERE user_id=%s ORDER BY created_at", (token["user_id"],))
    semesters = cur.fetchall()
    result = []
    for sem in semesters:
        cur.execute("SELECT * FROM courses WHERE semester_id=%s ORDER BY id", (sem["id"],))
        courses = cur.fetchall()
        total_pts = sum(float(c["grade_points"]) * c["credit_hours"] for c in courses)
        total_cr  = sum(c["credit_hours"] for c in courses)
        gpa = round(total_pts / total_cr, 2) if total_cr > 0 else 0.0
        result.append({**dict(sem), "courses": [dict(c) for c in courses], "gpa": gpa, "total_credits": total_cr})
    return result

@app.post("/gpa/semester")
def add_semester(req: SemesterReq, token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("INSERT INTO semesters (user_id, name) VALUES (%s,%s) RETURNING id",
                (token["user_id"], req.name))
    sem_id = cur.fetchone()[0]
    conn.commit()
    return {"id": sem_id, "name": req.name, "courses": [], "gpa": 0.0}

@app.delete("/gpa/semester/{semester_id}")
def delete_semester(semester_id: int, token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM semesters WHERE id=%s", (semester_id,))
    row = cur.fetchone()
    if not row or row[0] != token["user_id"]:
        raise HTTPException(403, "Not your semester")
    cur.execute("DELETE FROM semesters WHERE id=%s", (semester_id,))
    conn.commit()
    return {"message": "Semester deleted"}

@app.post("/gpa/course")
def add_course(req: CourseReq, token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM semesters WHERE id=%s", (req.semester_id,))
    row = cur.fetchone()
    if not row or row[0] != token["user_id"]:
        raise HTTPException(403, "Not your semester")
    gp = GRADE_MAP.get(req.grade.upper(), 0.0)
    cur.execute("INSERT INTO courses (semester_id, name, grade, credit_hours, grade_points) VALUES (%s,%s,%s,%s,%s)",
                (req.semester_id, req.name, req.grade.upper(), req.credit_hours, gp))
    conn.commit()
    return {"message": "Course added"}

@app.delete("/gpa/course/{course_id}")
def delete_course(course_id: int, token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("""
        SELECT s.user_id FROM courses c
        JOIN semesters s ON c.semester_id = s.id
        WHERE c.id = %s
    """, (course_id,))
    row = cur.fetchone()
    if not row or row[0] != token["user_id"]:
        raise HTTPException(403, "Not your course")
    cur.execute("DELETE FROM courses WHERE id=%s", (course_id,))
    conn.commit()
    return {"message": "Course deleted"}

@app.get("/gpa/cgpa")
def get_cgpa(token=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("""
        SELECT COALESCE(SUM(c.grade_points * c.credit_hours), 0),
               COALESCE(SUM(c.credit_hours), 0)
        FROM courses c JOIN semesters s ON c.semester_id = s.id
        WHERE s.user_id = %s
    """, (token["user_id"],))
    total_pts, total_cr = cur.fetchone()
    cgpa = round(float(total_pts) / float(total_cr), 2) if total_cr > 0 else 0.0
    return {"cgpa": cgpa, "total_credits": int(total_cr)}

# ──────────────────────────────────────────────────────────────
# ADMIN ENDPOINTS
# ──────────────────────────────────────────────────────────────
@app.get("/admin/payments/pending")
def pending_payments(token=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT p.id, p.transaction_id, p.amount, p.status, p.submitted_at,
               u.name, u.email, u.id as user_id
        FROM payments p JOIN users u ON p.user_id = u.id
        WHERE p.status = 'pending'
        ORDER BY p.submitted_at DESC
    """)
    return [dict(r) for r in cur.fetchall()]

@app.get("/admin/payments/all")
def all_payments(token=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT p.id, p.transaction_id, p.amount, p.status, p.submitted_at, p.verified_at,
               u.name, u.email
        FROM payments p JOIN users u ON p.user_id = u.id
        ORDER BY p.submitted_at DESC LIMIT 100
    """)
    return [dict(r) for r in cur.fetchall()]

@app.post("/admin/payment/action")
def payment_action(req: PaymentActionReq, token=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM payments WHERE id=%s", (req.payment_id,))
    payment = cur.fetchone()
    if not payment:
        raise HTTPException(404, "Payment not found")
    if req.action == "approve":
        cur.execute("UPDATE payments SET status='approved', verified_at=NOW() WHERE id=%s", (req.payment_id,))
        sub_end = date.today() + timedelta(days=30)
        cur.execute("UPDATE users SET is_active=TRUE, subscription_end=%s WHERE id=%s",
                    (sub_end, payment["user_id"]))
        conn.commit()
        return {"message": f"Approved — student active until {sub_end}"}
    elif req.action == "reject":
        cur.execute("UPDATE payments SET status='rejected', verified_at=NOW() WHERE id=%s", (req.payment_id,))
        conn.commit()
        return {"message": "Payment rejected"}
    else:
        raise HTTPException(400, "action must be 'approve' or 'reject'")

@app.get("/admin/students")
def get_students(token=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT u.id, u.name, u.email, u.is_active, u.subscription_end, u.created_at,
               ROUND(COALESCE(
                   SUM(c.grade_points * c.credit_hours)::numeric /
                   NULLIF(SUM(c.credit_hours), 0), 0
               ), 2) as cgpa
        FROM users u
        LEFT JOIN semesters s ON s.user_id = u.id
        LEFT JOIN courses c ON c.semester_id = s.id
        WHERE u.role = 'student'
        GROUP BY u.id ORDER BY cgpa DESC NULLS LAST
    """)
    return [dict(r) for r in cur.fetchall()]

@app.get("/admin/analytics")
def analytics(token=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT COUNT(*) as v FROM users WHERE role='student'")
    total = cur.fetchone()["v"]
    cur.execute("SELECT COUNT(*) as v FROM users WHERE role='student' AND is_active=TRUE AND subscription_end >= CURRENT_DATE")
    active = cur.fetchone()["v"]
    cur.execute("SELECT COALESCE(SUM(amount),0) as v FROM payments WHERE status='approved'")
    revenue = cur.fetchone()["v"]
    cur.execute("SELECT COUNT(*) as v FROM payments WHERE status='pending'")
    pending = cur.fetchone()["v"]
    cur.execute("""
        SELECT DATE(login_time) as day, COUNT(*) as count
        FROM login_history WHERE login_time >= NOW() - INTERVAL '7 days'
        GROUP BY day ORDER BY day
    """)
    daily = [{"day": str(r["day"]), "count": r["count"]} for r in cur.fetchall()]
    return {
        "total_students": int(total),
        "active_students": int(active),
        "revenue_pkr": float(revenue),
        "pending_payments": int(pending),
        "daily_logins": daily
    }

@app.delete("/admin/student/{student_id}")
def delete_student(student_id: int, token=Depends(require_admin), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s AND role='student'", (student_id,))
    conn.commit()
    return {"message": "Student deleted"}

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0"}

# ──────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
