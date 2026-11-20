from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, Field

from backend.config import Settings, load_settings
from backend.pending import (
    NoPendingError,
    PendingConflictError,
    PendingExpiredError,
    PendingStore,
)
from backend.snapshot import create_snapshot, restore_snapshot
from backend.ufw_logs import match_rule_hint, read_ufw_hits
from backend.ufw_parse import parse_ufw_numbered
from backend.ufw_runner import (
    AddRuleRequest,
    UfwRunner,
    delete_might_cut_access,
    rule_would_block_client,
)

log = logging.getLogger("host-firewall")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class AddRuleBody(BaseModel):
    action: str = Field(pattern="^(allow|deny)$")
    port_or_app: str = Field(min_length=1, max_length=64)
    from_address: str = "Anywhere"
    comment: str = ""
    direction: str = Field(default="in", pattern="^(in|out)$")


def _password_ok(provided: str, expected: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(provided.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )


def create_app(
    settings: Settings | None = None,
    runner: UfwRunner | None = None,
    *,
    start_watchdog: bool = True,
) -> FastAPI:
    settings = settings or load_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    pending = PendingStore(settings.data_dir, ttl_seconds=settings.confirm_seconds)
    ufw = runner or UfwRunner(settings.ufw_bin)
    signer = URLSafeSerializer(settings.secret_key, salt="host-firewall-session")
    cookie_name = "hf_session"
    stop_watchdog = threading.Event()

    def restore_pending_change(change) -> None:
        """Restore snapshot + reload, then clear pending only on success."""
        restore_snapshot(Path(change.snapshot_path), settings.ufw_dir)
        ufw.reload()
        pending.clear_if_snapshot(change.snapshot_path)

    def maybe_auto_rollback() -> None:
        change = pending.peek_expired()
        if change is None:
            return
        try:
            restore_pending_change(change)
        except Exception:
            log.exception("auto-rollback failed; pending kept for retry")

    def watchdog_loop() -> None:
        while not stop_watchdog.wait(1.0):
            maybe_auto_rollback()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        thread = None
        if start_watchdog:
            thread = threading.Thread(target=watchdog_loop, name="hf-watchdog", daemon=True)
            thread.start()
        yield
        stop_watchdog.set()
        if thread is not None:
            thread.join(timeout=2)

    app = FastAPI(title="Host Firewall", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.pending = pending
    app.state.ufw = ufw

    static_dir = BASE_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _set_session(response: Response) -> None:
        token = signer.dumps({"ok": True, "n": secrets.token_hex(8)})
        response.set_cookie(
            cookie_name,
            token,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=60 * 60 * 12,
        )

    def _authed(request: Request) -> bool:
        raw = request.cookies.get(cookie_name)
        if not raw:
            return False
        try:
            data = signer.loads(raw)
            return bool(data.get("ok"))
        except BadSignature:
            return False

    def require_auth(request: Request) -> bool:
        if not _authed(request):
            raise HTTPException(status_code=401, detail="Unauthorized")
        return True

    def client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "label": settings.hostname_label}

    @app.post("/api/login")
    def api_login(response: Response, password: str = Form()) -> dict:
        if not _password_ok(password, settings.password):
            raise HTTPException(status_code=401, detail="Invalid password")
        _set_session(response)
        return {"ok": True}

    @app.post("/api/logout")
    def api_logout(response: Response) -> dict:
        response.delete_cookie(cookie_name)
        return {"ok": True}

    @app.get("/api/rules")
    def api_rules(auth: bool = Depends(require_auth)) -> dict:
        maybe_auto_rollback()
        text = ufw.status_numbered()
        rules = [
            {
                "number": r.number,
                "to": r.to,
                "action": r.action,
                "direction": r.direction,
                "from": r.from_,
                "comment": r.comment,
            }
            for r in parse_ufw_numbered(text)
        ]
        return {"rules": rules, "raw": text}

    @app.get("/api/pending")
    def api_pending(auth: bool = Depends(require_auth)) -> dict:
        maybe_auto_rollback()
        change = pending.get()
        if change is None:
            return {"pending": None}
        return {"pending": change.to_dict()}

    @app.post("/api/rules")
    def api_add_rule(
        body: AddRuleBody,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        warn = rule_would_block_client(
            action=body.action, from_address=body.from_address, client_ip=ip
        )
        snap = create_snapshot(settings.ufw_dir, settings.data_dir)
        desc = f"{body.action} {body.port_or_app} from {body.from_address}"
        if body.comment:
            desc += f" # {body.comment}"
        try:
            change = pending.start(
                snapshot_path=snap,
                description=desc,
                client_ip=ip,
                warn_blocks_client=warn,
            )
        except PendingConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            ufw.add_rule(
                AddRuleRequest(
                    action=body.action,
                    port_or_app=body.port_or_app,
                    from_address=body.from_address,
                    comment=body.comment,
                    direction=body.direction,
                )
            )
        except Exception as exc:
            try:
                restore_pending_change(change)
            except Exception:
                log.exception("failed to restore after add error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"pending": change.to_dict(), "warn_blocks_client": warn}

    @app.delete("/api/rules/{number}")
    def api_delete_rule(
        number: int,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        current = parse_ufw_numbered(ufw.status_numbered())
        target = next((r for r in current if r.number == number), None)
        warn = False
        if target is not None:
            warn = delete_might_cut_access(
                to=target.to,
                action=target.action,
                from_=target.from_,
                client_ip=ip,
            )
        snap = create_snapshot(settings.ufw_dir, settings.data_dir)
        desc = f"delete rule {number}"
        if target and target.comment:
            desc += f" # {target.comment}"
        try:
            change = pending.start(
                snapshot_path=snap,
                description=desc,
                client_ip=ip,
                warn_blocks_client=warn,
            )
        except PendingConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            ufw.delete_rule(number)
        except Exception as exc:
            try:
                restore_pending_change(change)
            except Exception:
                log.exception("failed to restore after delete error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"pending": change.to_dict(), "warn_blocks_client": warn}

    @app.put("/api/rules/{number}")
    def api_edit_rule(
        number: int,
        body: AddRuleBody,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        current = parse_ufw_numbered(ufw.status_numbered())
        target = next((r for r in current if r.number == number), None)
        if target is None:
            raise HTTPException(status_code=404, detail=f"Rule {number} not found")
        warn = rule_would_block_client(
            action=body.action, from_address=body.from_address, client_ip=ip
        ) or delete_might_cut_access(
            to=target.to,
            action=target.action,
            from_=target.from_,
            client_ip=ip,
        )
        snap = create_snapshot(settings.ufw_dir, settings.data_dir)
        desc = (
            f"edit #{number} → {body.action} {body.port_or_app} from {body.from_address}"
        )
        if body.comment:
            desc += f" # {body.comment}"
        try:
            change = pending.start(
                snapshot_path=snap,
                description=desc,
                client_ip=ip,
                warn_blocks_client=warn,
            )
        except PendingConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            ufw.delete_rule(number)
            ufw.add_rule(
                AddRuleRequest(
                    action=body.action,
                    port_or_app=body.port_or_app,
                    from_address=body.from_address,
                    comment=body.comment,
                    direction=body.direction,
                    insert_at=number,
                )
            )
        except Exception as exc:
            try:
                restore_pending_change(change)
            except Exception:
                log.exception("failed to restore after edit error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"pending": change.to_dict(), "warn_blocks_client": warn}

    @app.get("/api/logs")
    def api_logs(auth: bool = Depends(require_auth)) -> dict:
        maybe_auto_rollback()
        rules = parse_ufw_numbered(ufw.status_numbered())
        hits = read_ufw_hits(list(settings.log_paths), limit=settings.log_limit)
        return {
            "hits": [
                {
                    "timestamp": h.timestamp,
                    "action": h.action,
                    "src": h.src,
                    "dst": h.dst,
                    "proto": h.proto,
                    "spt": h.spt,
                    "dpt": h.dpt,
                    "iface_in": h.iface_in,
                    "summary": h.summary,
                    "rule_hint": match_rule_hint(h, rules),
                }
                for h in hits
            ],
            "sources": [str(p) for p in settings.log_paths if p.is_file()],
        }

    @app.post("/api/pending/confirm")
    def api_confirm(auth: bool = Depends(require_auth)) -> dict:
        try:
            change = pending.confirm()
        except NoPendingError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PendingExpiredError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"ok": True, "confirmed": change.to_dict()}

    @app.post("/api/pending/rollback")
    def api_rollback(auth: bool = Depends(require_auth)) -> dict:
        try:
            change = pending.rollback()
        except NoPendingError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        try:
            restore_pending_change(change)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Rollback failed: {exc}") from exc
        return {"ok": True, "rolled_back": change.to_dict()}

    # ---- HTML ----

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> HTMLResponse:
        if _authed(request):
            return RedirectResponse("/", status_code=303)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"label": settings.hostname_label, "error": None},
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request) -> Response:
        form = await request.form()
        password = str(form.get("password") or "")
        if not _password_ok(password, settings.password):
            return templates.TemplateResponse(
                request,
                "login.html",
                {"label": settings.hostname_label, "error": "Invalid password"},
                status_code=401,
            )
        resp = RedirectResponse("/", status_code=303)
        _set_session(resp)
        return resp

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        maybe_auto_rollback()
        text = ufw.status_numbered()
        rules = parse_ufw_numbered(text)
        change = pending.get()
        hits = read_ufw_hits(list(settings.log_paths), limit=settings.log_limit)
        log_rows = [
            {
                "timestamp": h.timestamp,
                "action": h.action,
                "summary": h.summary,
                "src": h.src,
                "dpt": h.dpt,
                "proto": h.proto,
                "rule_hint": match_rule_hint(h, rules),
            }
            for h in hits
        ]
        log_sources = [str(p) for p in settings.log_paths if p.is_file()]
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "label": settings.hostname_label,
                "rules": rules,
                "pending": change,
                "confirm_seconds": settings.confirm_seconds,
                "log_rows": log_rows,
                "log_sources": log_sources,
                "edit_rule": None,
            },
        )

    @app.get("/edit/{number}", response_class=HTMLResponse)
    def edit_page(number: int, request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        maybe_auto_rollback()
        if pending.get() is not None:
            return RedirectResponse("/", status_code=303)
        rules = parse_ufw_numbered(ufw.status_numbered())
        target = next((r for r in rules if r.number == number), None)
        if target is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "label": settings.hostname_label,
                "rules": rules,
                "pending": None,
                "confirm_seconds": settings.confirm_seconds,
                "log_rows": [],
                "log_sources": [],
                "edit_rule": target,
            },
        )

    @app.post("/actions/add", response_class=HTMLResponse)
    async def html_add(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        body = AddRuleBody(
            action=str(form.get("action") or "allow"),
            port_or_app=str(form.get("port_or_app") or ""),
            from_address=str(form.get("from_address") or "Anywhere"),
            comment=str(form.get("comment") or ""),
            direction=str(form.get("direction") or "in"),
        )
        api_add_rule(body, request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/delete/{number}", response_class=HTMLResponse)
    def html_delete(number: int, request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        api_delete_rule(number, request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/edit/{number}", response_class=HTMLResponse)
    async def html_edit(number: int, request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        body = AddRuleBody(
            action=str(form.get("action") or "allow"),
            port_or_app=str(form.get("port_or_app") or ""),
            from_address=str(form.get("from_address") or "Anywhere"),
            comment=str(form.get("comment") or ""),
            direction=str(form.get("direction") or "in"),
        )
        api_edit_rule(number, body, request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/confirm", response_class=HTMLResponse)
    def html_confirm(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        api_confirm(True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/rollback", response_class=HTMLResponse)
    def html_rollback(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        api_rollback(True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/logout", response_class=HTMLResponse)
    def html_logout() -> Response:
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(cookie_name)
        return resp

    return app


app = None


def get_app() -> FastAPI:
    global app
    if app is None:
        app = create_app()
    return app
