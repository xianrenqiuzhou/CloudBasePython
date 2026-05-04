"""
物料管理系统 — 用户认证后端 API
技术栈：FastAPI + MySQL (pymysql)
运行方式：uvicorn main:app --host 0.0.0.0 --port 8000 --reload

环境变量（MySQL 连接）：
  MYSQL_HOST     默认 127.0.0.1
  MYSQL_PORT     默认 3306
  MYSQL_USER     默认 root
  MYSQL_PASSWORD 默认空
  MYSQL_DATABASE 默认 material_system
"""

import json
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Optional

import pymysql
from pymysql.cursors import DictCursor
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────
DB_HOST     = os.getenv("MYSQL_HOST", "127.0.0.1")
DB_PORT     = int(os.getenv("MYSQL_PORT", "3306"))
DB_USER     = os.getenv("MYSQL_USER", "root")
DB_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
DB_NAME     = os.getenv("MYSQL_DATABASE", "material_system")

PASS_SALT = ""          # 密码不加密，直接明文存储
TOKEN_TTL = 7           # 会话 token 有效天数

app = FastAPI(title="物料管理系统 API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],             # 生产环境改为具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# 数据库（MySQL）
# ─────────────────────────────────────────────
@contextmanager
def get_db():
    """获取 MySQL DictCursor，yield 后自动 commit/close"""
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    finally:
        cur.close()
        conn.close()


def _ensure_database():
    """确保数据库存在（首次启动时创建）"""
    conn = pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER,
        password=DB_PASSWORD, charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    finally:
        conn.close()


def init_db():
    _ensure_database()
    with get_db() as db:
        # users 表
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone      VARCHAR(255) PRIMARY KEY,
                name       VARCHAR(255) NOT NULL,
                password   VARCHAR(255) NOT NULL,
                role       VARCHAR(50)  NOT NULL DEFAULT 'user',
                expire_at  DATETIME,
                created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # sessions 表
        db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      VARCHAR(255) PRIMARY KEY,
                phone      VARCHAR(255) NOT NULL,
                expire_at  DATETIME     NOT NULL,
                created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_phone (phone)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # userdata 表（物料等业务数据）
        db.execute("""
            CREATE TABLE IF NOT EXISTS userdata (
                phone      VARCHAR(255) PRIMARY KEY,
                data       LONGTEXT     NOT NULL DEFAULT '{}',
                updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_updated (updated_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        # 初始化超级管理员
        db.execute("SELECT 1 FROM users WHERE phone = %s", ("13800000000",))
        if not db.fetchone():
            db.execute(
                "INSERT INTO users (phone, name, password, role) VALUES (%s,%s,%s,%s)",
                ("13800000000", "超级管理员", "123456", "superadmin"),
            )
        else:
            db.execute(
                "UPDATE users SET password = %s, role = %s WHERE phone = %s",
                ("123456", "superadmin", "13800000000"),
            )


init_db()


# ─────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────
def hash_pass(password: str) -> str:
    return password  # 明文存储，不加密


def make_token(phone: str) -> str:
    token = secrets.token_hex(32)
    expire = (datetime.now() + timedelta(days=TOKEN_TTL)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO sessions (token, phone, expire_at) VALUES (%s,%s,%s)",
            (token, phone, expire),
        )
    return token


def user_row_to_dict(u) -> dict:
    return {
        "phone":     u["phone"],
        "name":      u["name"],
        "role":      u["role"],
        "expireAt":  u["expire_at"].isoformat() if u["expire_at"] else None,
        "createdAt": u["created_at"].isoformat() if u["created_at"] else None,
    }


def verify_token(authorization: Optional[str] = Header(None)) -> str:
    """从 Authorization: Bearer <token> 中解析并验证 token，返回 phone"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未提供 Token，请先登录")
    token = authorization[7:]
    with get_db() as db:
        db.execute("SELECT phone, expire_at FROM sessions WHERE token = %s", (token,))
        row = db.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Token 无效，请重新登录")
    if datetime.fromisoformat(row["expire_at"]) < datetime.now():
        raise HTTPException(status_code=401, detail="Token 已过期，请重新登录")
    return row["phone"]


# ─────────────────────────────────────────────
# 请求模型
# ─────────────────────────────────────────────
class RegisterReq(BaseModel):
    phone:    str
    name:     str
    password: str

class LoginReq(BaseModel):
    phone:    str
    password: str

class SetExpiryReq(BaseModel):
    days: int   # 0=永久, -1=立即停用, >0=延长天数

class SetRoleReq(BaseModel):
    role: str   # 'user' | 'admin'


# ─────────────────────────────────────────────
# 路由
# ─────────────────────────────────────────────

@app.post("/api/auth/register", summary="注册")
def register(req: RegisterReq):
    if not req.phone or len(req.phone) != 11 or not req.phone.isdigit():
        raise HTTPException(400, "手机号格式错误")
    if len(req.password) < 6:
        raise HTTPException(400, "密码不能少于 6 位")
    if not req.name.strip():
        raise HTTPException(400, "姓名不能为空")

    with get_db() as db:
        db.execute("SELECT 1 FROM users WHERE phone=%s", (req.phone,))
        if db.fetchone():
            raise HTTPException(409, "该手机号已注册")
        default_expire = (datetime.now() + timedelta(days=30)).isoformat()
        db.execute(
            "INSERT INTO users (phone, name, password, expire_at) VALUES (%s,%s,%s,%s)",
            (req.phone, req.name.strip(), hash_pass(req.password), default_expire),
        )
        db.execute("SELECT * FROM users WHERE phone=%s", (req.phone,))
        user = db.fetchone()

    token = make_token(req.phone)
    return {"token": token, "user": user_row_to_dict(user)}


@app.post("/api/auth/login", summary="登录")
def login(req: LoginReq):
    with get_db() as db:
        db.execute("SELECT * FROM users WHERE phone=%s", (req.phone,))
        user = db.fetchone()

    if not user:
        raise HTTPException(404, "手机号未注册，请先注册")
    if user["password"] != hash_pass(req.password):
        raise HTTPException(401, "密码错误，请重新输入")

    # 校验账号有效期
    if user["expire_at"]:
        if datetime.fromisoformat(user["expire_at"].isoformat() if hasattr(user["expire_at"], 'isoformat') else str(user["expire_at"])) < datetime.now():
            exp_date = user["expire_at"].strftime("%Y-%m-%d") if hasattr(user["expire_at"], 'strftime') else str(user["expire_at"])[:10]
            raise HTTPException(403, f"账号授权已于 {exp_date} 到期，请联系管理员续期")

    token = make_token(req.phone)
    return {"token": token, "user": user_row_to_dict(user)}


@app.get("/api/auth/verify", summary="验证当前 Token")
def verify(phone: str = Depends(verify_token)):
    with get_db() as db:
        db.execute("SELECT * FROM users WHERE phone=%s", (phone,))
        user = db.fetchone()
    if not user:
        raise HTTPException(404, "用户不存在")
    return user_row_to_dict(user)


@app.post("/api/auth/logout", summary="登出（删除 Token）")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token=%s", (token,))
    return {"success": True}


@app.get("/api/users", summary="用户列表（管理员）")
def list_users(phone: str = Depends(verify_token)):
    with get_db() as db:
        db.execute("SELECT * FROM users WHERE phone=%s", (phone,))
        me = db.fetchone()
        if not me or me["role"] not in ("admin", "superadmin"):
            raise HTTPException(403, "无权限")
        if me["role"] == "superadmin":
            db.execute("SELECT * FROM users ORDER BY created_at DESC")
            rows = db.fetchall()
        else:
            db.execute("SELECT * FROM users WHERE role='user' OR role IS NULL ORDER BY created_at DESC")
            rows = db.fetchall()
    return [user_row_to_dict(u) for u in rows]


@app.put("/api/users/{target_phone}/expiry", summary="设置授权有效期")
def set_expiry(target_phone: str, req: SetExpiryReq, phone: str = Depends(verify_token)):
    with get_db() as db:
        db.execute("SELECT * FROM users WHERE phone=%s", (phone,))
        me     = db.fetchone()
        db.execute("SELECT * FROM users WHERE phone=%s", (target_phone,))
        target = db.fetchone()

        if not me or me["role"] not in ("admin", "superadmin"):
            raise HTTPException(403, "无权限")
        if not target:
            raise HTTPException(404, "用户不存在")
        if target["role"] == "superadmin":
            raise HTTPException(403, "超级管理员授权不可修改")
        if me["role"] == "admin" and target["role"] in ("admin", "superadmin"):
            raise HTTPException(403, "普通管理员无权修改管理员授权")

        if req.days == 0:
            new_expire = None
        elif req.days == -1:
            new_expire = (datetime.now() - timedelta(days=1)).isoformat()
        else:
            base = datetime.now()
            if target["expire_at"]:
                t = datetime.fromisoformat(target["expire_at"].isoformat() if hasattr(target["expire_at"], 'isoformat') else str(target["expire_at"]))
                if t > datetime.now():
                    base = t
            new_expire = (base + timedelta(days=req.days)).isoformat()

        db.execute("UPDATE users SET expire_at=%s WHERE phone=%s", (new_expire, target_phone))

    return {"success": True, "expireAt": new_expire}


@app.put("/api/users/{target_phone}/role", summary="设置用户角色（超管）")
def set_role(target_phone: str, req: SetRoleReq, phone: str = Depends(verify_token)):
    if req.role not in ("user", "admin"):
        raise HTTPException(400, "角色只能为 user 或 admin")

    with get_db() as db:
        db.execute("SELECT * FROM users WHERE phone=%s", (phone,))
        me = db.fetchone()
        db.execute("SELECT * FROM users WHERE phone=%s", (target_phone,))
        target = db.fetchone()

        if not me or me["role"] != "superadmin":
            raise HTTPException(403, "仅超级管理员可修改角色")
        if not target:
            raise HTTPException(404, "用户不存在")
        if target["role"] == "superadmin":
            raise HTTPException(403, "超级管理员角色不可修改")
        if phone == target_phone:
            raise HTTPException(400, "不能修改自己的角色")

        db.execute("UPDATE users SET role=%s WHERE phone=%s", (req.role, target_phone))

    return {"success": True}


# ─────────────────────────────────────────────
# 用户物料数据读写（存储在 userdata 表）
# ─────────────────────────────────────────────

@app.get("/api/data", summary="读取当前用户物料数据")
def get_data(
    request: Request,
    phone: str = Depends(verify_token),
    x_data_owner: Optional[str] = Header(None, alias="X-Data-Owner")
):
    target_phone = x_data_owner if x_data_owner else phone
    sync_check = request.query_params.get("sync_check") == "1"
    with get_db() as db:
        db.execute("SELECT data, updated_at FROM userdata WHERE phone=%s", (target_phone,))
        row = db.fetchone()
    if not row:
        if sync_check:
            return {"dataVersion": "0"}
        return {"materials": [], "transactions": [], "logs": [], "codeCounter": 0, "customTypeRules": [], "customMaterialTypes": [], "customUnits": ["个","片","条","套","卷","批","根","块"], "materialPresets": []}
    data = json.loads(row["data"]) if not sync_check else {}
    if sync_check:
        return {"dataVersion": row["updated_at"].isoformat() if hasattr(row["updated_at"], 'isoformat') else str(row["updated_at"]) or "0"}
    data["dataVersion"] = row["updated_at"].isoformat() if hasattr(row["updated_at"], 'isoformat') else str(row["updated_at"]) or "0"
    return data


@app.put("/api/data", summary="保存当前用户物料数据")
async def save_data(
    request: Request,
    phone: str = Depends(verify_token),
    x_data_owner: Optional[str] = Header(None, alias="X-Data-Owner")
):
    body = await request.json()
    now  = datetime.now().isoformat()
    target_phone = x_data_owner if x_data_owner else phone
    with get_db() as db:
        db.execute("SELECT data FROM userdata WHERE phone=%s", (target_phone,))
        row = db.fetchone()
        existing = json.loads(row["data"]) if row else {}
        merged = {**existing, **body}
        merged["dataVersion"] = now
        db.execute(
            """INSERT INTO userdata (phone, data, updated_at) VALUES (%s,%s,%s)
               ON DUPLICATE KEY UPDATE data=VALUES(data), updated_at=VALUES(updated_at)""",
            (target_phone, json.dumps(merged, ensure_ascii=False), now),
        )
    return {"success": True, "savedAt": now, "dataVersion": now}


# ─────────────────────────────────────────────
# 子账号管理
# ─────────────────────────────────────────────

class SaveSubAccountsReq(BaseModel):
    subAccounts: list


@app.get("/api/subaccounts/{sub_phone}", summary="根据手机号查找子账号")
def find_subaccount(sub_phone: str):
    """遍历所有用户的 userdata，查找 subAccounts 中包含该手机号的记录。
    匿名访问（登录前查询），找到后自动为子账号创建有效 session token。"""
    with get_db() as db:
        db.execute("SELECT phone, data FROM userdata")
        rows = db.fetchall()
        for row in rows:
            data = json.loads(row["data"])
            subs = data.get("subAccounts", [])
            for sub in subs:
                if str(sub.get("phone", "")) == sub_phone:
                    parent_phone = row["phone"]
                    token = secrets.token_hex(32)
                    expire = (datetime.now() + timedelta(days=TOKEN_TTL)).isoformat()
                    db.execute(
                        "INSERT INTO sessions (token, phone, expire_at) VALUES (%s,%s,%s)",
                        (token, parent_phone, expire),
                    )
                    db.execute("SELECT phone, name, expire_at FROM users WHERE phone=%s", (parent_phone,))
                    parent = db.fetchone()
                    return {
                        "parentPhone": parent_phone,
                        "parentName": parent["name"] if parent else parent_phone,
                        "expireAt": parent["expire_at"].isoformat() if parent and parent["expire_at"] else None,
                        "subAccount": sub,
                        "token": token
                    }
    raise HTTPException(404, "子账号不存在")


@app.put("/api/subaccounts", summary="保存当前用户的子账号列表")
async def save_subaccounts(
    request: Request,
    phone: str = Depends(verify_token)
):
    body = await request.json()
    subs = body.get("subAccounts", [])
    now  = datetime.now().isoformat()
    with get_db() as db:
        db.execute("SELECT data FROM userdata WHERE phone=%s", (phone,))
        row = db.fetchone()
        data = json.loads(row["data"]) if row else {}
        data["subAccounts"] = subs
        db.execute(
            """INSERT INTO userdata (phone, data, updated_at) VALUES (%s,%s,%s)
               ON DUPLICATE KEY UPDATE data=VALUES(data), updated_at=VALUES(updated_at)""",
            (phone, json.dumps(data, ensure_ascii=False), now),
        )
    return {"success": True, "savedAt": now}


# ─────────────────────────────────────────────
# 健康检查
# ─────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "db": "mysql", "time": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
