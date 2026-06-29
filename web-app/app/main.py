"""Web App - FastAPI + Jinja UI."""
import logging

from fastapi import FastAPI

from .routes import ui, actions, admin

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("web-app")

app = FastAPI(title="Identity Demo - Web App")

app.include_router(ui.router)
app.include_router(actions.router)
app.include_router(admin.router)


@app.get("/health")
def health():
    return {"status": "ok"}
