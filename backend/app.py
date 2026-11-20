from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, Response as RawResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, Field

from backend.config import Settings, load_settings
from backend.export_backup import build_ufw_export_tar, list_snapshots
from backend.history import ChangeHistory
from backend.insights import docker_published, hourly_blocks, relative_time, uncovered_ports
from backend.ratelimit import LoginLimiter
from backend.listening import list_listening_ports
from backend.pending import (
    NoPendingError,
    PendingConflictError,
    PendingExpiredError,
    PendingStore,
)
from backend.snapshot import create_snapshot, restore_snapshot
from backend.ufw_logs import match_rule_hint, read_ufw_hits
from backend.ufw_parse import parse_app_list, parse_ufw_numbered, parse_ufw_status
from backend.ufw_runner import (
    DEFAULT_POLICIES,
    LOGGING_LEVELS,
    AddRuleRequest,
    UfwRunner,
    delete_might_cut_access,
    rule_would_block_client,
)

log = logging.getLogger("host-firewall")

APP_VERSION = "0.4.0"

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class AddRuleBody(BaseModel):
    action: str = Field(pattern="^(allow|deny|reject|limit)$")
    port_or_app: str = Field(min_length=1, max_length=64)
    from_address: str = "Anywhere"
    comment: str = ""
    direction: str = Field(default="in", pattern="^(in|out)$")
    insert_at: int | None = None


class MoveRuleBody(BaseModel):
    to_number: int = Field(ge=1)


class DefaultPolicyBody(BaseModel):
    direction: str = Field(pattern="^(incoming|outgoing|routed)$")
    policy: str = Field(pattern="^(allow|deny|reject)$")


class LoggingBody(BaseModel):
    level: str


class RestoreBody(BaseModel):
    snapshot_name: str = Field(min_length=1, max_length=128)


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
    listening_runner=None,
) -> FastAPI:
    settings = settings or load_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if settings.demo and runner is None:
        from backend.demo import prepare_demo

        runner, demo_ss = prepare_demo(settings.data_dir, settings.ufw_dir, settings.log_paths[0])
        listening_runner = listening_runner or demo_ss
    limiter = LoginLimiter()
    pending = PendingStore(settings.data_dir, ttl_seconds=settings.confirm_seconds)
    history = ChangeHistory(settings.data_dir)
    ufw = runner or UfwRunner(settings.ufw_bin)
    signer = URLSafeSerializer(settings.secret_key, salt="host-firewall-session")
    cookie_name = "hf_session"
    stop_watchdog = threading.Event()

    def restore_pending_change(change) -> None:
        """Restore snapshot + reload, then clear pending only on success."""
        restore_snapshot(Path(change.snapshot_path), settings.ufw_dir)
        try:
            ufw.reload()
        except Exception:
            # reload may fail if UFW was disabled in snapshot
            log.exception("ufw reload after restore failed")
        pending.clear_if_snapshot(change.snapshot_path)

    def maybe_auto_rollback() -> None:
        change = pending.peek_expired()
        if change is None:
            return
        try:
            restore_pending_change(change)
            history.append(
                description=change.description,
                client_ip=change.client_ip,
                outcome="rolled_back",
                snapshot_path=change.snapshot_path,
            )
        except Exception:
            log.exception("auto-rollback failed; pending kept for retry")

    def watchdog_loop() -> None:
        while not stop_watchdog.wait(1.0):
            maybe_auto_rollback()

    def begin_mutation(
        *,
        description: str,
        client_ip: str,
        warn: bool = False,
    ):
        snap = create_snapshot(settings.ufw_dir, settings.data_dir)
        try:
            change = pending.start(
                snapshot_path=snap,
                description=description,
                client_ip=client_ip,
                warn_blocks_client=warn,
            )
        except PendingConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return change

    def run_mut(change, fn):
        try:
            fn()
        except Exception as exc:
            try:
                restore_pending_change(change)
            except Exception:
                log.exception("failed to restore after mutation error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"pending": change.to_dict(), "warn_blocks_client": change.warn_blocks_client}

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

    app = FastAPI(title="Host Firewall", version=APP_VERSION, lifespan=lifespan)
    app.state.settings = settings
    app.state.pending = pending
    app.state.ufw = ufw
    app.state.history = history

    static_dir = BASE_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _set_session(response: Response, request: Request) -> None:
        token = signer.dumps({"ok": True, "n": secrets.token_hex(8)})
        secure = settings.cookie_secure
        if secure is None:
            # uvicorn runs with proxy_headers, so this honours X-Forwarded-Proto
            secure = request.url.scheme == "https"
        response.set_cookie(
            cookie_name,
            token,
            httponly=True,
            samesite="lax",
            secure=secure,
            max_age=60 * 60 * 12,
        )

    def _lockout_message(seconds: int) -> str:
        minutes = max(1, round(seconds / 60))
        return f"Too many failed attempts. Try again in {minutes} min."

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

    def dashboard_context(
        request: Request,
        *,
        edit_rule=None,
        prefill: dict | None = None,
    ) -> dict:
        maybe_auto_rollback()
        numbered = ufw.status_numbered()
        rules = parse_ufw_numbered(numbered)
        try:
            verbose = ufw.status_verbose()
            status = parse_ufw_status(verbose)
        except Exception:
            status = parse_ufw_status(numbered)
            verbose = numbered
        try:
            apps = parse_app_list(ufw.app_list())
        except Exception:
            apps = []
        change = pending.get()
        all_hits = read_ufw_hits(
            list(settings.log_paths), limit=max(2000, settings.log_limit)
        )
        chart = hourly_blocks(all_hits)
        hits = []
        seen_raw: set[str] = set()
        for h in all_hits:
            if h.raw in seen_raw:
                continue
            seen_raw.add(h.raw)
            hits.append(h)
            if len(hits) >= settings.log_limit:
                break
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
        ports = list_listening_ports(runner=listening_runner)
        uncovered = uncovered_ports(ports, rules)
        docker_ports = docker_published(ports)
        recent_history = [e.to_dict() for e in history.recent(40)]
        last_change = None
        if recent_history:
            last = recent_history[0]
            last_change = {
                "ago": relative_time(last["ts"]),
                "outcome": last["outcome"],
                "description": last["description"],
            }
        return {
            "version": APP_VERSION,
            "chart": chart,
            "uncovered": uncovered,
            "uncovered_keys": {f"{p.proto}/{p.port}" for p in uncovered},
            "docker_ports": docker_ports,
            "docker_keys": {f"{p.proto}/{p.port}" for p in docker_ports},
            "demo": settings.demo,
            "last_change": last_change,
            "label": settings.hostname_label,
            "rules": rules,
            "status": status,
            "pending": change,
            "confirm_seconds": settings.confirm_seconds,
            "log_rows": log_rows,
            "log_sources": [str(p) for p in settings.log_paths if p.is_file()],
            "edit_rule": edit_rule,
            "apps": apps,
            "ports": ports,
            "history": recent_history,
            "snapshots": list_snapshots(settings.data_dir)[:20],
            "logging_levels": LOGGING_LEVELS,
            "default_policies": DEFAULT_POLICIES,
            "prefill": prefill or {},
            "request": request,
        }

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "label": settings.hostname_label, "version": APP_VERSION}

    @app.post("/api/login")
    def api_login(request: Request, response: Response, password: str = Form()) -> dict:
        ip = client_ip(request)
        wait = limiter.retry_after(ip)
        if wait:
            raise HTTPException(
                status_code=429,
                detail=_lockout_message(wait),
                headers={"Retry-After": str(wait)},
            )
        if not _password_ok(password, settings.password):
            limiter.failure(ip)
            raise HTTPException(status_code=401, detail="Invalid password")
        limiter.success(ip)
        _set_session(response, request)
        return {"ok": True}

    @app.post("/api/logout")
    def api_logout(response: Response) -> dict:
        response.delete_cookie(cookie_name)
        return {"ok": True}

    @app.get("/api/status")
    def api_status(auth: bool = Depends(require_auth)) -> dict:
        maybe_auto_rollback()
        verbose = ufw.status_verbose()
        status = parse_ufw_status(verbose)
        return {
            "active": status.active,
            "logging": status.logging,
            "default_incoming": status.default_incoming,
            "default_outgoing": status.default_outgoing,
            "default_routed": status.default_routed,
            "raw": status.raw,
        }

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
                "family": r.family,
            }
            for r in parse_ufw_numbered(text)
        ]
        return {"rules": rules, "raw": text}

    @app.get("/api/apps")
    def api_apps(auth: bool = Depends(require_auth)) -> dict:
        return {"apps": parse_app_list(ufw.app_list())}

    @app.get("/api/ports")
    def api_ports(auth: bool = Depends(require_auth)) -> dict:
        ports = list_listening_ports(runner=listening_runner)
        return {
            "ports": [
                {
                    "proto": p.proto,
                    "local": p.local,
                    "port": p.port,
                    "process": p.process,
                    "family": p.family,
                }
                for p in ports
            ]
        }

    @app.get("/api/history")
    def api_history(auth: bool = Depends(require_auth)) -> dict:
        return {"history": [e.to_dict() for e in history.recent(100)]}

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
        desc = f"{body.action} {body.port_or_app} from {body.from_address}"
        if body.comment:
            desc += f" # {body.comment}"
        change = begin_mutation(description=desc, client_ip=ip, warn=warn)
        return run_mut(
            change,
            lambda: ufw.add_rule(
                AddRuleRequest(
                    action=body.action,
                    port_or_app=body.port_or_app,
                    from_address=body.from_address,
                    comment=body.comment,
                    direction=body.direction,
                    insert_at=body.insert_at,
                )
            ),
        )

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
        desc = f"delete rule {number}"
        if target and target.comment:
            desc += f" # {target.comment}"
        change = begin_mutation(description=desc, client_ip=ip, warn=warn)
        return run_mut(change, lambda: ufw.delete_rule(number))

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
        desc = (
            f"edit #{number} → {body.action} {body.port_or_app} from {body.from_address}"
        )
        if body.comment:
            desc += f" # {body.comment}"
        change = begin_mutation(description=desc, client_ip=ip, warn=warn)

        def do_edit():
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

        return run_mut(change, do_edit)

    @app.post("/api/rules/{number}/move")
    def api_move_rule(
        number: int,
        body: MoveRuleBody,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        if number == body.to_number:
            raise HTTPException(status_code=400, detail="Already at that position")
        change = begin_mutation(
            description=f"move rule {number} → {body.to_number}",
            client_ip=ip,
            warn=False,
        )
        return run_mut(change, lambda: ufw.move_rule(number, body.to_number))

    @app.post("/api/ufw/enable")
    def api_enable(request: Request, auth: bool = Depends(require_auth)) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        change = begin_mutation(description="enable UFW", client_ip=ip, warn=False)
        return run_mut(change, ufw.enable)

    @app.post("/api/ufw/disable")
    def api_disable(request: Request, auth: bool = Depends(require_auth)) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        change = begin_mutation(
            description="disable UFW",
            client_ip=ip,
            warn=True,
        )
        return run_mut(change, ufw.disable)

    @app.post("/api/ufw/default")
    def api_default(
        body: DefaultPolicyBody,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        ip = client_ip(request)
        warn = body.direction == "incoming" and body.policy in {"deny", "reject"}
        change = begin_mutation(
            description=f"default {body.policy} {body.direction}",
            client_ip=ip,
            warn=warn,
        )
        return run_mut(
            change, lambda: ufw.set_default(body.direction, body.policy)
        )

    @app.post("/api/ufw/logging")
    def api_logging(
        body: LoggingBody,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        level = body.level.lower()
        if level not in LOGGING_LEVELS:
            raise HTTPException(status_code=400, detail="Invalid logging level")
        ip = client_ip(request)
        change = begin_mutation(
            description=f"logging {level}",
            client_ip=ip,
            warn=False,
        )
        return run_mut(change, lambda: ufw.set_logging(level))

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

    @app.get("/api/export")
    def api_export(auth: bool = Depends(require_auth)) -> RawResponse:
        maybe_auto_rollback()
        payload = build_ufw_export_tar(
            settings.ufw_dir,
            status_numbered=ufw.status_numbered(),
            status_verbose=ufw.status_verbose(),
        )
        filename = f"host-firewall-ufw-{int(time.time())}.tar.gz"
        return RawResponse(
            content=payload,
            media_type="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/snapshots")
    def api_snapshots(auth: bool = Depends(require_auth)) -> dict:
        return {"snapshots": list_snapshots(settings.data_dir)}

    @app.post("/api/snapshots/restore")
    def api_restore(
        body: RestoreBody,
        request: Request,
        auth: bool = Depends(require_auth),
    ) -> dict:
        maybe_auto_rollback()
        name = Path(body.snapshot_name).name
        if not name.startswith("ufw-"):
            raise HTTPException(status_code=400, detail="Invalid snapshot name")
        snap_path = settings.data_dir / "snapshots" / name
        if not snap_path.is_dir():
            raise HTTPException(status_code=404, detail="Snapshot not found")
        ip = client_ip(request)
        # Snapshot current state first so confirm-window can undo the restore
        change = begin_mutation(
            description=f"restore snapshot {name}",
            client_ip=ip,
            warn=True,
        )

        def do_restore():
            restore_snapshot(snap_path, settings.ufw_dir)
            ufw.reload()

        return run_mut(change, do_restore)

    @app.post("/api/pending/confirm")
    def api_confirm(request: Request, auth: bool = Depends(require_auth)) -> dict:
        try:
            change = pending.confirm()
        except NoPendingError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PendingExpiredError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        history.append(
            description=change.description,
            client_ip=change.client_ip,
            outcome="confirmed",
            snapshot_path=change.snapshot_path,
        )
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
        history.append(
            description=change.description,
            client_ip=change.client_ip,
            outcome="rolled_back",
            snapshot_path=change.snapshot_path,
        )
        return {"ok": True, "rolled_back": change.to_dict()}

    # ---- HTML ----

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> HTMLResponse:
        if _authed(request):
            return RedirectResponse("/", status_code=303)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"label": settings.hostname_label, "error": None, "demo": settings.demo,
             "version": APP_VERSION},
        )

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request) -> Response:
        ip = client_ip(request)

        def fail(message: str, status: int, headers: dict | None = None) -> Response:
            return templates.TemplateResponse(
                request,
                "login.html",
                {"label": settings.hostname_label, "error": message, "demo": settings.demo,
                 "version": APP_VERSION},
                status_code=status,
                headers=headers,
            )

        wait = limiter.retry_after(ip)
        if wait:
            return fail(_lockout_message(wait), 429, {"Retry-After": str(wait)})
        form = await request.form()
        password = str(form.get("password") or "")
        if not _password_ok(password, settings.password):
            limiter.failure(ip)
            return fail("Invalid password", 401)
        limiter.success(ip)
        resp = RedirectResponse("/", status_code=303)
        _set_session(resp, request)
        return resp

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        prefill = {
            "action": request.query_params.get("action") or "allow",
            "port_or_app": request.query_params.get("port_or_app") or "",
            "from_address": request.query_params.get("from_address") or "Anywhere",
            "comment": request.query_params.get("comment") or "",
            "direction": request.query_params.get("direction") or "in",
        }
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            dashboard_context(request, prefill=prefill),
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
            dashboard_context(request, edit_rule=target),
        )

    @app.post("/actions/add", response_class=HTMLResponse)
    async def html_add(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        insert_raw = str(form.get("insert_at") or "").strip()
        insert_at = int(insert_raw) if insert_raw.isdigit() else None
        body = AddRuleBody(
            action=str(form.get("action") or "allow"),
            port_or_app=str(form.get("port_or_app") or ""),
            from_address=str(form.get("from_address") or "Anywhere"),
            comment=str(form.get("comment") or ""),
            direction=str(form.get("direction") or "in"),
            insert_at=insert_at,
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

    @app.post("/actions/move/{number}", response_class=HTMLResponse)
    async def html_move(number: int, request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        to_number = int(str(form.get("to_number") or "0"))
        api_move_rule(number, MoveRuleBody(to_number=to_number), request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/enable", response_class=HTMLResponse)
    def html_enable(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        api_enable(request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/disable", response_class=HTMLResponse)
    def html_disable(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        api_disable(request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/default", response_class=HTMLResponse)
    async def html_default(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        api_default(
            DefaultPolicyBody(
                direction=str(form.get("direction") or "incoming"),
                policy=str(form.get("policy") or "deny"),
            ),
            request,
            True,
        )
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/logging", response_class=HTMLResponse)
    async def html_logging(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        api_logging(LoggingBody(level=str(form.get("level") or "low")), request, True)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/restore", response_class=HTMLResponse)
    async def html_restore(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        api_restore(
            RestoreBody(snapshot_name=str(form.get("snapshot_name") or "")),
            request,
            True,
        )
        return RedirectResponse("/", status_code=303)

    @app.get("/export")
    def html_export(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        return api_export(True)

    @app.post("/actions/confirm", response_class=HTMLResponse)
    def html_confirm(request: Request) -> Response:
        if not _authed(request):
            return RedirectResponse("/login", status_code=303)
        api_confirm(request, True)
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
