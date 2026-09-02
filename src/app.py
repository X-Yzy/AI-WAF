"""本地完整应用：在线检测 API + 可视化 Dashboard。

本地开发使用 ``uvicorn src.app:app``；服务器最小部署请使用
``uvicorn src.runtime_api:app``，避免依赖数据集、训练和生成器。
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response

from . import runtime_api
from .dashboard import create_dashboard_router
from .settings import DEMO_ROOT


app = FastAPI(
    title="Web 攻击检测本地开发控制台",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(create_dashboard_router(
    lambda: runtime_api.pipeline,
    runtime_api.replace_pipeline,
    "final-model",
))


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def demo():
    demo_path = DEMO_ROOT / "index.html"
    if demo_path.exists():
        return demo_path.read_text(encoding="utf-8")
    return "<h1>demo/index.html not found</h1>"


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Avoid a noisy browser-console 404 in the standalone demonstration UI."""

    return Response(status_code=204)


# 本地页面和训练路由优先；其余在线检测 API 交给独立的服务器运行时应用。
# 这样服务器的根页面不会覆盖本地 demo，同时两种启动方式仍共用检测管线。
app.mount("/", runtime_api.app)
