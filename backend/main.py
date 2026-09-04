import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

import audit_log
import ise_client
import switch_client

app = FastAPI(title="ISE Troubleshooter")

# In un eseguibile PyInstaller i file vengono estratti in sys._MEIPASS.
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).parent.parent))
FRONTEND_DIR = BASE_DIR / "frontend"


class IseCreds(BaseModel):
    host: str
    username: str
    password: str
    verify_ssl: bool = False
    port: int | None = None


class MacQuery(IseCreds):
    mac: str


class UserQuery(IseCreds):
    identity: str


class AuthStatusQuery(IseCreds):
    mac: str
    seconds: int = 86400
    records: int = 20


class EndpointContextQuery(IseCreds):
    mac: str


class CoaReauthRequest(IseCreds):
    psn_name: str
    mac: str
    reauth_type: int = 0


class CoaDisconnectRequest(IseCreds):
    mnt_node: str
    mac: str
    switch_ip: str
    psn_ip: str
    disconnect_type: int = 0


class SwitchExecRequest(BaseModel):
    host: str
    username: str
    password: str
    secret: str = ""
    port: int = 22
    device_type: str = "cisco_ios"
    command: str
    advanced: bool = False


@app.post("/api/ise/test")
async def ise_test(creds: IseCreds):
    try:
        await ise_client.test_connection(creds.host, creds.username, creds.password, creds.verify_ssl, creds.port)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/ise/session/mac")
async def session_by_mac(q: MacQuery):
    try:
        return await ise_client.get_session_by_mac(q.host, q.username, q.password, q.mac, q.verify_ssl, q.port)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/ise/session/user")
async def session_by_user(q: UserQuery):
    try:
        return await ise_client.get_session_by_username(q.host, q.username, q.password, q.identity, q.verify_ssl, q.port)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/ise/session/active")
async def active_sessions(creds: IseCreds):
    try:
        return await ise_client.get_active_sessions(creds.host, creds.username, creds.password, creds.verify_ssl, creds.port)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/ise/authstatus")
async def auth_status(q: AuthStatusQuery):
    try:
        return await ise_client.get_auth_status(
            q.host, q.username, q.password, q.mac, q.seconds, q.records, "All", q.verify_ssl, q.port
        )
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/ise/endpoint-context")
async def endpoint_context(q: EndpointContextQuery):
    try:
        return await ise_client.get_endpoint_context(q.host, q.username, q.password, q.mac, q.verify_ssl, q.port)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/ise/coa/reauth")
async def coa_reauth(req: CoaReauthRequest):
    try:
        result = await ise_client.coa_reauth(
            req.host, req.username, req.password, req.psn_name, req.mac, req.reauth_type, req.verify_ssl, req.port
        )
        audit_log.log("coa_reauth", ise_host=req.host, ise_user=req.username, mac=req.mac, result=str(result))
        return {"result": result}
    except Exception as e:
        audit_log.log("coa_reauth", ise_host=req.host, ise_user=req.username, mac=req.mac, error=str(e))
        raise HTTPException(400, str(e))


@app.post("/api/ise/coa/disconnect")
async def coa_disconnect(req: CoaDisconnectRequest):
    try:
        result = await ise_client.coa_disconnect(
            req.host, req.username, req.password, req.mnt_node, req.mac, req.switch_ip, req.psn_ip,
            req.disconnect_type, req.verify_ssl, req.port
        )
        audit_log.log("coa_disconnect", ise_host=req.host, ise_user=req.username, mac=req.mac, result=str(result))
        return {"result": result}
    except Exception as e:
        audit_log.log("coa_disconnect", ise_host=req.host, ise_user=req.username, mac=req.mac, error=str(e))
        raise HTTPException(400, str(e))


@app.post("/api/switch/exec")
async def switch_exec(sw: SwitchExecRequest):
    if not sw.advanced and not sw.command.strip().lower().startswith("show"):
        audit_log.log("switch_command", switch_host=sw.host, switch_user=sw.username, command=sw.command, error="blocked: not a show command")
        raise HTTPException(400, "Solo comandi 'show' sono permessi. Attiva la modalità avanzata per eseguire altri comandi.")
    try:
        output = await run_in_threadpool(
            switch_client.run_command, sw.host, sw.username, sw.password, sw.command, sw.secret, sw.port, sw.device_type
        )
        audit_log.log("switch_command", switch_host=sw.host, switch_user=sw.username, command=sw.command, advanced=sw.advanced, result="ok")
        return {"output": output}
    except Exception as e:
        audit_log.log("switch_command", switch_host=sw.host, switch_user=sw.username, command=sw.command, advanced=sw.advanced, error=str(e))
        raise HTTPException(400, str(e))


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
