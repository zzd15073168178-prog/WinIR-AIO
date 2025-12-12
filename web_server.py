#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon Web Server (FastAPI)
带有基本安全防护的 API 服务器
"""

import sys
import os
import secrets
import hashlib
import uvicorn
import psutil
from functools import wraps
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import List, Dict, Any, Optional

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from process_manager import ProcessManager
from utils.validation import sanitize_pid

# Initialize API
app = FastAPI(title="Sysmon Web API", description="Backend API for Sysmon Web GUI")

# ==================== 安全配置 ====================

# API Token（启动时生成，或从环境变量读取）
# 生产环境应使用强密码并通过环境变量传入
API_TOKEN = os.environ.get("SYSMON_API_TOKEN", None)
if not API_TOKEN:
    # 开发模式：生成随机 token 并打印
    API_TOKEN = secrets.token_urlsafe(32)
    print(f"[安全] 生成临时 API Token: {API_TOKEN}")
    print("[安全] 生产环境请设置 SYSMON_API_TOKEN 环境变量")

# 是否启用认证（可通过环境变量禁用，仅用于开发）
AUTH_ENABLED = os.environ.get("SYSMON_AUTH_ENABLED", "true").lower() != "false"

# 受保护的 PID 列表（系统关键进程，禁止终止）
PROTECTED_PIDS = {0, 4}  # System Idle Process, System

# CORS 配置 - 严格限制允许的来源
ALLOWED_ORIGINS = [
    "http://localhost:5173",     # Vite 开发服务器
    "http://127.0.0.1:5173",
    "http://localhost:3000",     # 常见开发端口
    "http://127.0.0.1:3000",
]

# 生产环境：不允许凭证跨域传输
ALLOW_CREDENTIALS = os.environ.get("SYSMON_ALLOW_CREDENTIALS", "false").lower() == "true"

# 从环境变量读取额外的允许源（仅在明确设置时）
extra_origins = os.environ.get("CORS_ORIGINS", "")
if extra_origins:
    for origin in extra_origins.split(","):
        origin = origin.strip()
        if origin.startswith("http://") or origin.startswith("https://"):
            ALLOWED_ORIGINS.append(origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST"],  # 移除 DELETE，使用 POST 代替
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)


# ==================== 认证依赖 ====================

async def verify_token(authorization: Optional[str] = Header(None)):
    """验证 API Token"""
    if not AUTH_ENABLED:
        return True

    if not authorization:
        raise HTTPException(status_code=401, detail="缺少认证头")

    # 支持 Bearer token 格式
    if authorization.startswith("Bearer "):
        token = authorization[7:]
    else:
        token = authorization

    # 使用常量时间比较防止时序攻击
    if not secrets.compare_digest(token, API_TOKEN):
        raise HTTPException(status_code=401, detail="无效的 API Token")

    return True


async def verify_localhost(request: Request):
    """验证请求来自本地（额外的安全层）"""
    client_host = request.client.host if request.client else None
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}

    if client_host not in allowed_hosts:
        raise HTTPException(status_code=403, detail="只允许本地访问")

    return True

# Initialize Managers
# Note: Some managers might need to be singleton or initialized properly
process_manager = ProcessManager()

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}

@app.get("/api/processes", response_model=Dict[str, Any])
async def get_processes():
    """Get the process tree and list with detailed info"""
    try:
        # 获取基本进程树
        data = process_manager.get_process_tree()
        all_procs = data.get('all_procs', {})

        # 为每个进程添加详细信息
        enhanced_procs = {}
        for pid_str, proc_info in all_procs.items():
            pid = int(pid_str)
            enhanced_proc = proc_info.copy()

            try:
                p = psutil.Process(pid)
                # 添加 CPU、内存和用户信息
                enhanced_proc['cpu_percent'] = p.cpu_percent(interval=0)
                enhanced_proc['memory_mb'] = p.memory_info().rss / 1024 / 1024
                try:
                    enhanced_proc['username'] = p.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    enhanced_proc['username'] = '-'
                enhanced_proc['status'] = p.status()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # 进程可能已结束或无权限
                enhanced_proc['cpu_percent'] = 0
                enhanced_proc['memory_mb'] = 0
                enhanced_proc['username'] = '-'
                enhanced_proc['status'] = 'unknown'

            enhanced_procs[pid_str] = enhanced_proc

        return {
            'all_procs': enhanced_procs,
            'root_procs': data.get('root_procs', [])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/processes/{pid}")
async def get_process_details(pid: int):
    """Get details for a specific process"""
    try:
        import psutil
        try:
            p = psutil.Process(pid)
            return {
                "pid": pid,
                "name": p.name(),
                "status": p.status(),
                "cpu_percent": p.cpu_percent(interval=0.1),
                "memory_mb": p.memory_info().rss / 1024 / 1024,
                "create_time": p.create_time(),
                "username": p.username(),
                "cmdline": p.cmdline(),
                "exe": p.exe(),
                "cwd": p.cwd(),
                "num_threads": p.num_threads(),
                "ppid": p.ppid()
            }
        except psutil.NoSuchProcess:
            raise HTTPException(status_code=404, detail=f"Process {pid} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/processes/{pid}/kill")
async def kill_process(
    pid: int,
    request: Request,
    _auth: bool = Depends(verify_token),
    _local: bool = Depends(verify_localhost)
):
    """Kill a process（需要认证和本地访问）"""
    # 安全验证：验证 PID
    valid, safe_pid, error = sanitize_pid(pid)
    if not valid:
        raise HTTPException(status_code=400, detail=f"无效的 PID: {error}")

    # 安全检查：禁止终止受保护的系统进程
    if safe_pid in PROTECTED_PIDS:
        raise HTTPException(status_code=403, detail="禁止终止系统关键进程")

    # 安全检查：禁止终止自身
    if safe_pid == os.getpid():
        raise HTTPException(status_code=403, detail="禁止终止服务器进程")

    try:
        p = psutil.Process(safe_pid)

        # 额外检查：禁止终止 csrss.exe, winlogon.exe 等关键进程
        critical_processes = {'csrss.exe', 'winlogon.exe', 'smss.exe', 'services.exe', 'lsass.exe'}
        if p.name().lower() in critical_processes:
            raise HTTPException(status_code=403, detail=f"禁止终止系统关键进程: {p.name()}")

        p.terminate()
        return {"status": "success", "message": f"进程 {safe_pid} 已终止"}
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="进程不存在")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail="权限不足，无法终止该进程")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/system/stats")
async def get_system_stats():
    """Get global system stats (CPU, Memory)"""
    import psutil
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage('/')._asdict()
    }

# Serve Frontend (after build)
# We will point this to sysmon_web/dist later
# app.mount("/", StaticFiles(directory="sysmon_web/dist", html=True), name="static")

def run_server():
    """Run the uvicorn server"""
    print("Starting Sysmon Web Backend on http://localhost:8001")
    uvicorn.run(app, host="127.0.0.1", port=8001)

if __name__ == "__main__":
    run_server()
