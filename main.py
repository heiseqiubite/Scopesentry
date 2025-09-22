import logging
import time
from distutils.version import LooseVersion

from loguru import logger
import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.staticfiles import StaticFiles

from core.config import *
import os

set_config()

from core.redis_handler import subscribe_log_channel
from starlette.requests import Request
import asyncio
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from core import db
import json
from fastapi import WebSocket
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.websockets import WebSocketDisconnect

app = FastAPI(timeout=None)

from api.task.handler import scheduler

"""
日志文件配置：
- logs/api.log    记录 API 访问日志
- logs/mongo.log  记录 MongoDB 查询耗时日志
保持控制台输出，便于开发调试
"""
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir, exist_ok=True)

# API 访问日志 sink（按 channel 过滤）
logger.add(
    os.path.join(logs_dir, "api.log"),
    rotation="20 MB",
    retention="7 days",
    enqueue=True,
    encoding="utf-8",
    backtrace=False,
    diagnose=False,
    filter=lambda record: record["extra"].get("channel") == "api",
)

# Mongo 查询耗时日志 sink（按 channel 过滤）
logger.add(
    os.path.join(logs_dir, "mongo.log"),
    rotation="20 MB",
    retention="7 days",
    enqueue=True,
    encoding="utf-8",
    backtrace=False,
    diagnose=False,
    filter=lambda record: record["extra"].get("channel") == "mongo",
)


@app.on_event("startup")
async def startup_db_client():
    print("\n" + "=" * 50)
    print("✨✨✨ IMPORTANT NOTICE: Please review the Plugin Key below ✨✨✨")
    print("=" * 50)
    print(f"🔑 Plugin Key: {PLUGINKEY}")
    print("=" * 50)
    print("✅ Ensure the Plugin Key is correctly copied!\n")
    file_path = os.path.join(os.getcwd(), 'file')
    if not os.path.exists(file_path):
        os.makedirs(file_path)
    await db.create_database()
    scheduler.start()
    asyncio.create_task(subscribe_log_channel())


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    if type(exc.detail) == str:
        exc.detail = {'code': 500, 'message': exc.detail}
    return JSONResponse(exc.detail, status_code=exc.status_code)


os.chdir(os.path.dirname(os.path.abspath(__file__)))

from api import users, poc, configuration, fingerprint, node, task, notification, system, export
from api.dictionary import router as dictionary_router
from api.asset import router as asset_route
from api.plugins import router as plugin_route
from api.project import router as project_route
from api.vuln import router as vuln_router

app.include_router(plugin_route, prefix='/api')
app.include_router(users.router, prefix='/api')
app.include_router(dictionary_router, prefix='/api/dictionary')
app.include_router(poc.router, prefix='/api')
app.include_router(configuration.router, prefix='/api/configuration')
app.include_router(fingerprint.router, prefix='/api')
app.include_router(node.router, prefix='/api')
app.include_router(project_route, prefix='/api')
app.include_router(task.router, prefix='/api')
app.include_router(asset_route, prefix='/api')
app.include_router(vuln_router, prefix='/api')
app.include_router(notification.router, prefix='/api')
app.include_router(system.router, prefix='/api')
app.include_router(export.router, prefix='/api')
app.mount("/assets", StaticFiles(directory="static/assets"), name="assets")


@app.get("/logo.png", response_class=FileResponse)
async def get_logo(request: Request):
    return FileResponse("static/logo.png")


@app.get("/favicon.ico", response_class=FileResponse)
async def get_favicon(request: Request):
    return FileResponse("static/favicon.ico")


app.add_middleware(GZipMiddleware, minimum_size=5 * 1024 * 1024)

class ApiAccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        end_time = time.time()
        duration = end_time - start_time
        if request.url.path.startswith("/api"):
            logger.bind(channel="api").info(
                f"{request.client.host} {request.method} {request.url.path} -> {response.status_code} {duration:.3f}s"
            )
        return response


@app.get("/")
async def read_root():
    return FileResponse("static/index.html")


class MongoDBQueryTimeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        end_time = time.time()
        # 计算查询时间
        query_time = end_time - start_time
        # 获取当前请求的路由信息
        route = request.url.path
        if route.startswith("/api"):
            logger.bind(channel="mongo").info(f"MongoDB 查询时间：{query_time:.3f} 秒, 路由: {route}")
        return response


SQLTIME = True

if SQLTIME:
    app.add_middleware(MongoDBQueryTimeMiddleware)
app.add_middleware(ApiAccessLogMiddleware)


@app.websocket("/")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    node_name = ""
    try:
        while True:
            data = await websocket.receive_text()
            # 解析收到的消息，假设消息格式为 JSON {"node_name": "example_node"}
            try:
                message = json.loads(data)
                node_name = message.get("node_name")
                if node_name:
                    GET_LOG_NAME.append(node_name)
                    if node_name in LOG_INFO:
                        while LOG_INFO[node_name]:
                            log = LOG_INFO[node_name].pop(0)
                            await websocket.send_text(log)
                else:
                    await websocket.send_text("Invalid message format: missing node_name")
            except json.JSONDecodeError:
                await websocket.send_text("Invalid JSON format")
    except WebSocketDisconnect:
        GET_LOG_NAME.remove(node_name)
        pass


def banner():
    banner = '''   _____                         _____            _              
  / ____|                       / ____|          | |             
 | (___   ___ ___  _ __   ___  | (___   ___ _ __ | |_ _ __ _   _ 
  \___ \ / __/ _ \| '_ \ / _ \  \___ \ / _ \ '_ \| __| '__| | | |
  ____) | (_| (_) | |_) |  __/  ____) |  __/ | | | |_| |  | |_| |
 |_____/ \___\___/| .__/ \___| |_____/ \___|_| |_|\__|_|   \__, |
                  | |                                       __/ |
                  |_|                                      |___/ '''
    print(banner)
    print("Server Version:", VERSION)


# 自定义日志过滤器
class IgnoreStaticFilesFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # 如果日志消息包含静态文件路径，则过滤掉
        static_file_keywords = [".js", ".css", ".png", ".svg", ".jpg"]
        return not any(keyword in record.getMessage() for keyword in static_file_keywords)


# 应用自定义过滤器，禁用静态文件日志
logging.getLogger("uvicorn.access").addFilter(IgnoreStaticFilesFilter())

if __name__ == "__main__":
    banner()
    file_path = os.path.join(os.getcwd(), "file")
    uvicorn.run("main:app", host="0.0.0.0", port=8082, reload=False, reload_excludes=[file_path])
