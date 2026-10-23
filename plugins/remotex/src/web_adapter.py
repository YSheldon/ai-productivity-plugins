from __future__ import annotations

import hashlib
import copy
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import credential_store
import config_store
import execution
import profile_tools
import queue_leases
import remotex_core as core
import secure_paths
import vm_queue
import web_policy
import web_channel
import web_authorization
import web_authorization_store
import web_task_service
import web_site_service
import web_recovery
import audit_log
from web_component_protocol import V3_WORKER_PROTOCOL, V3_NATIVE_PROTOCOL


PLAYWRIGHT_VERSION = "1.62.1"
JSONC_VERSION = "3.3.1"
WEB_RUNTIME_REVISION = "1.62.1-init-read-1"
MAX_SESSION_SECONDS = web_authorization.MAX_GRANT_SECONDS + 3600
PLUGIN = Path(__file__).resolve().parents[1]
STATE_FIELDS = {"state","loginSubmitted","authenticationVerified","failureCode","updatedAt"}
STATES = {"starting","opening","ready","submitted","verified","needs-user-check","failed","closed"}
FAILURES = {None,"invalid-job","origin-blocked","redirect-blocked","tls-or-navigation-failed","certificate-pin-mismatch","certificate-validity-failed","request-too-large","response-too-large","form-unavailable","login-flow-failed","network-guard-failed","unsupported-transport","lease-no-longer-covers-session","authorization-contract-required"}
_CHANNELS: dict[str, web_channel.Channel] = {}
_CHANNELS_LOCK = threading.Lock()
_RECOVERY_SERVICE = None
_RECOVERY_LOCK = threading.Lock()


def state_root() -> Path:
    root = core.expand_path(os.environ["REMOTEX_WEB_STATE_DIR"], "REMOTEX_WEB_STATE_DIR") if os.environ.get("REMOTEX_WEB_STATE_DIR") else vm_queue.queue_path().parent / "web"
    if secure_paths._network_path(root) or any(secure_paths._reparse_point(p) for p in [root,*root.parents]):
        raise core.ToolError("Web state must be local without reparse points")
    return root


def _module_path() -> Path | None:
    candidates = [state_root() / "runtime" / WEB_RUNTIME_REVISION / "node_modules" / "playwright-core",
                  state_root() / "runtime" / PLAYWRIGHT_VERSION / "node_modules" / "playwright-core",
                  Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "node_modules" / "playwright-core"]
    if os.environ.get("REMOTEX_PLAYWRIGHT_MODULE"):
        candidates.insert(0, core.expand_path(os.environ["REMOTEX_PLAYWRIGHT_MODULE"], "REMOTEX_PLAYWRIGHT_MODULE"))
    for path in candidates:
        try:
            if json.loads((path / "package.json").read_text(encoding="utf-8")).get("version") == PLAYWRIGHT_VERSION:
                return path
        except (OSError, ValueError):
            pass
    return None


def _parser_module_path() -> Path | None:
    module=_module_path()
    candidates=[state_root() / 'runtime' / WEB_RUNTIME_REVISION / 'node_modules' / 'jsonc-parser',
                PLUGIN / 'scripts' / 'web-runtime' / 'node_modules' / 'jsonc-parser']
    if module:
        candidates.append(module.parent / 'jsonc-parser')
    for path in candidates:
        try:
            if json.loads((path/'package.json').read_text(encoding='utf-8')).get('version')==JSONC_VERSION:
                return path
        except (OSError,ValueError):
            pass
    return None


def _node() -> str:
    node = core.find_executable("node")
    try:
        result = subprocess.run([node,"--version"],capture_output=True,text=True,timeout=10,check=False)
        if int(result.stdout.strip().lstrip("v").split(".")[0]) < 24:
            raise ValueError()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise core.ToolError("Web login requires Node.js 24 or newer for system CA trust") from exc
    return node


def _admit_v3_components(node: str, *, site=False) -> None:
    commands=[([node,str(PLUGIN/'scripts/web_login_worker.mjs'),'--describe-protocol'],V3_WORKER_PROTOCOL),
        ([credential_store._powershell_path(),'-NoLogo','-NoProfile','-NonInteractive','-STA','-File',
          str(PLUGIN/'scripts/web_approval.ps1'),'-DescribeProtocol'],V3_NATIVE_PROTOCOL)]
    if site:
        commands.extend([([node,str(PLUGIN/'scripts/web_site_worker.mjs'),'--describe-protocol'],{'site_authorization':1}),
            ([credential_store._powershell_path(),'-NoLogo','-NoProfile','-NonInteractive','-STA','-File',
              str(PLUGIN/'scripts/web_site_approval.ps1'),'-DescribeProtocol'],{'site_authorization':1,'review_seconds':180})])
    try:
        for command,expected in commands:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding='utf-8',
                timeout=10,env=credential_store._setup_environment(),creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            if result.returncode!=0 or len(result.stdout)>2048 or json.loads(result.stdout)!=expected:
                raise ValueError()
    except (OSError,ValueError,subprocess.SubprocessError):
        raise core.ToolError('RemoteX web components are incomplete or incompatible; install one complete plugin version') from None


def runtime_setup(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) - {"confirm"}:
        raise core.ToolError("Unsupported web runtime argument")
    node = _node()
    module = _module_path()
    if module and _parser_module_path():
        return core.tool_result({"ok":True,"ready":True,"playwrightVersion":PLAYWRIGHT_VERSION,"jsoncVersion":JSONC_VERSION,"installedNow":False})
    if args.get("confirm") is not True:
        return core.tool_result({"ok":True,"preview":True,"ready":False,"package":"playwright-core","version":PLAYWRIGHT_VERSION,
            "packages":{"playwright-core":PLAYWRIGHT_VERSION,"jsonc-parser":JSONC_VERSION},"nextStep":"rerun-with-confirm-true"})
    root = state_root() / "runtime" / WEB_RUNTIME_REVISION
    secure_paths.ensure_private_directory(root)
    for name in ("package.json","package-lock.json"):
        shutil.copyfile(PLUGIN / "scripts" / "web-runtime" / name, root / name)
    npm = Path(core.find_executable("npm.cmd" if os.name == "nt" else "npm"))
    candidates = [npm.parent / "node_modules/npm/bin/npm-cli.js", Path(node).parent / "node_modules/npm/bin/npm-cli.js", Path(node).parent.parent / "node_modules/npm/bin/npm-cli.js"]
    cli = next((p for p in candidates if p.is_file()),None)
    if cli is None:
        raise core.ToolError("The Node.js npm CLI installation is unavailable")
    try:
        result = subprocess.run([node,str(cli),"ci","--ignore-scripts","--no-audit","--no-fund","--registry=https://registry.npmjs.org"],
            cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=_environment(),timeout=180,check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise core.ToolError("Unable to install the pinned web runtime") from exc
    if result.returncode != 0 or not _module_path() or not _parser_module_path():
        raise core.ToolError("Pinned web runtime installation failed")
    return core.tool_result({"ok":True,"ready":True,"playwrightVersion":PLAYWRIGHT_VERSION,"jsoncVersion":JSONC_VERSION,"installedNow":True})


SETUP_FIELDS = {"profile","url","account","credential_ref","username_selector","password_selector","submit_selector","success_selector","certificate_sha256","confirm","timeout_seconds"}


def setup(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) - SETUP_FIELDS:
        raise core.ToolError("Unsupported web profile setup field")
    result = profile_tools.setup({**args,"kind":"web","credential_source":"windows-credential-manager"})
    value = json.loads(result["content"][0]["text"])
    value["webScope"] = {"origin":web_policy.endpoint(args["url"])[1],"account":web_policy.account(args["account"]),"browser":"edge"}
    value["certificateTrust"] = {"mode":"certificate-sha256" if "certificate_sha256" in args else "system", "sha256":web_policy.certificate_pin(args["certificate_sha256"]) if "certificate_sha256" in args else None}
    return core.tool_result(value)


def certificate_trust(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) != {"profile", "origin", "certificate_sha256", "confirm"}:
        raise core.ToolError("Pass profile, exact origin, certificate_sha256 (or null), and confirm")
    name, raw, bundle = core.select_profile("web", args["profile"])
    reference = credential_store.resolve_profile_reference(bundle, name, raw, "web")
    web_policy.validate_binding(raw, reference.reference_dict())
    if args["origin"] != raw["origin"]:
        raise core.ToolError("Certificate trust must name the profile's exact HTTPS origin")
    pin = web_policy.certificate_pin(args["certificate_sha256"]) if args["certificate_sha256"] is not None else None
    result = {"ok":True,"profile":name,"origin":raw["origin"],"previousSha256":raw.get("certificate_sha256"),
              "certificateSha256":pin,"trustMode":"certificate-sha256" if pin else "system", "preview":True,"configurationStored":False}
    if not core.as_bool(args["confirm"], False):
        return core.tool_result(result)
    with vm_queue._resource_operation_lock(raw["queue_resource"]):
        assert_resource_idle(raw["queue_resource"])
        candidate = copy.deepcopy(bundle.data)
        selected = candidate["profiles"][name]
        if pin is None:
            selected.pop("certificate_sha256", None)
        else:
            selected["certificate_sha256"] = pin
        core._validate_config(candidate)
        receipt = config_store.write_config(bundle.path, candidate, expected=bundle.data, expected_exists=True)
    return core.tool_result({**result,"preview":False,"configurationStored":True,"configSha256":receipt.config_sha256})


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    bundle = core.load_config()
    reference = credential_store.resolve_profile_reference(bundle,name,raw,"web")
    present = reference.presence().get("present")
    try:
        _node()
        node_ready = True
    except core.ToolError:
        node_ready = False
    edge_ready = os.name == "nt" and any((Path(os.environ.get(variable,"C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe").is_file() for variable in ("PROGRAMFILES(X86)","PROGRAMFILES"))
    runtime_ready = _module_path() is not None and _parser_module_path() is not None and node_ready
    return {"profile":name,"kind":"web","credential_alias":reference.alias,"credential_source":reference.source,
            "referencePresent":present,"runtimeReady":runtime_ready,"client_available":edge_ready,"ready":present is True and runtime_ready and edge_ready,
            "readinessScope":"local-configuration-only","authenticationVerified":None}


def _directory(value: Any) -> Path:
    if not isinstance(value,str) or re.fullmatch(r"[0-9a-f]{32}",value) is None:
        raise core.ToolError("Invalid web session ID")
    directory = state_root() / "sessions" / value
    if not directory.is_dir() or secure_paths._reparse_point(directory):
        raise core.ToolError("Web session not found")
    return directory


def _read(directory: Path, name: str) -> dict[str, Any]:
    path = directory / name
    if secure_paths._reparse_point(path):
        raise core.ToolError("Web session state cannot be a reparse point")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise core.ToolError("Web session state is unavailable") from exc
    if not isinstance(value,dict):
        raise core.ToolError("Web session state is invalid")
    return value


def _state(directory: Path) -> dict[str, Any]:
    value = _read(directory,"state.json")
    if set(value) != STATE_FIELDS or value.get("state") not in STATES or value.get("failureCode") not in FAILURES or type(value.get("loginSubmitted")) is not bool or type(value.get("authenticationVerified")) is not bool:
        raise core.ToolError("Web session receipt has unexpected fields")
    if not isinstance(value["updatedAt"],str) or not re.fullmatch(r"[0-9T:.Z+-]{20,40}",value["updatedAt"]):
        raise core.ToolError("Web session receipt timestamp is invalid")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value),encoding="utf-8")
    os.replace(temporary,path)


def _active_path(resource: str) -> Path:
    if re.fullmatch(r"web:[0-9a-f]{64}",resource) is None:
        raise core.ToolError("Invalid web queue resource")
    directory = state_root() / "active"
    if secure_paths._reparse_point(directory):
        raise core.ToolError("Web active state cannot be a reparse point")
    return directory / (resource[4:]+".json")


def _running_or_unknown(pid: int) -> bool:
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32",use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.OpenProcess(0x1000,False,pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return ctypes.get_last_error() not in {87,1168}


def assert_resource_idle(resource: str) -> None:
    if re.fullmatch(r"web:[0-9a-f]{64}",resource) is None:
        return
    path = _active_path(resource)
    if not path.exists():
        return
    marker = _read(path.parent,path.name)
    if set(marker) != {"webSessionId","processId","supervisorId"} or not all(type(marker.get(k)) is int and marker[k]>0 for k in ("processId","supervisorId")):
        raise core.ToolError("Invalid active web session marker")
    identifier = marker.get("webSessionId")
    if not isinstance(identifier,str) or re.fullmatch(r"[0-9a-f]{32}",identifier) is None:
        raise core.ToolError("Invalid active web session identifier")
    proof = state_root() / "sessions" / identifier / "closed.json"
    if proof.exists() and _read(proof.parent,proof.name) == marker:
        path.unlink()
        return
    if _running_or_unknown(marker["processId"]) or _running_or_unknown(marker["supervisorId"]):
        raise core.ToolError("Close the active web session before releasing or recovering its queue")
    # If the MCP supervisor exited, Windows closed its kill-on-close job too.
    path.unlink()


def _upgrade_web_idle() -> bool:
    root=state_root()
    active=root/'active'
    if secure_paths._reparse_point(active):return False
    if not active.exists():return True
    paths=list(active.iterdir())
    if len(paths)>256:return False
    for path in paths:
        if (not re.fullmatch(r'[0-9a-f]{64}\.json',path.name) or not path.is_file() or
                secure_paths._reparse_point(path) or path.stat().st_size>4096):return False
        marker=_read(active,path.name)
        if (set(marker)!={'webSessionId','processId','supervisorId'} or
                not isinstance(marker['webSessionId'],str) or not re.fullmatch(r'[0-9a-f]{32}',marker['webSessionId']) or
                any(type(marker[k]) is not int or not 0<marker[k]<2**32 for k in ('processId','supervisorId'))):return False
        directory=root/'sessions'/marker['webSessionId']
        if any(secure_paths._reparse_point(p) for p in (root/'sessions',directory)):return False
        proof=directory/'closed.json'
        if proof.exists():
            if proof.stat().st_size>4096 or _read(directory,'closed.json')!=marker:return False
            continue
        if _running_or_unknown(marker['processId']) or _running_or_unknown(marker['supervisorId']):return False
    return True


def authorization_upgrade(args):
    if set(args)-{'confirm'} or type(args.get('confirm',False)) is not bool:
        raise core.ToolError('Pass only an optional boolean confirm')
    try:
        root = state_root()/'authorization'
        if (root/'integrity.key').exists() and not (root/'uncertain-writes.json').exists():
            web_recovery._key_only(root)
            raise core.ToolError('recovery-state-missing: run remotex_web_authorization_recovery with confirm=false; do not reset recovery state')
        return core.tool_result(web_authorization_store.upgrade_protocol(root,
            check_idle=_upgrade_web_idle,confirm=args.get('confirm',False)))
    except web_authorization.ScopeError as exc:
        raise core.ToolError(exc.code) from None


def _recovery_scope():
    return [{'profile': name, 'origin': raw.get('origin'), 'account': raw.get('account')}
        for name, raw in core.load_config().data['profiles'].items() if raw.get('kind') == 'web']


def authorization_recovery(args):
    global _RECOVERY_SERVICE
    if (set(args) - {'confirm', 'recovery_id'} or type(args.get('confirm', False)) is not bool or
            args.get('confirm') is True and 'recovery_id' not in args):
        raise core.ToolError('Pass only confirm and an optional preview recovery_id; approval is local only')
    try:
        with _RECOVERY_LOCK:
            root = state_root() / 'authorization'
            if _RECOVERY_SERVICE is None:
                _RECOVERY_SERVICE = web_recovery.RecoveryService(root, audit_path=audit_log.audit_path(),
                    scope=_recovery_scope, check_idle=_upgrade_web_idle)
            elif _RECOVERY_SERVICE.root != root:
                raise web_authorization.ScopeError('recovery-stale')
            service = _RECOVERY_SERVICE
        identity = args.get('recovery_id')
        value = service.open(identity) if args.get('confirm') is True else service.status(identity) if identity is not None else service.preview()
        return core.tool_result(value)
    except web_authorization.ScopeError as exc:
        raise core.ToolError(exc.code) from None


def _lease_covers(resource: str, requester: str, deadline: int) -> bool:
    try:
        with queue_leases._locked() as (_,leases), vm_queue._locked_state() as (_,queue):
            lease = leases['leases'].get(resource)
            owner = queue['resources'].get(resource,{}).get('owner')
            return bool(lease and owner and owner.get('requester') == requester and lease.get('requester') == requester
                and queue_leases._parse_timestamp(lease['expiresAt'],'expiresAt').timestamp()*1000 >= deadline+45000)
    except (core.ToolError,OSError):
        return False


def _supervise(process: subprocess.Popen, job: Any, directory: Path, resource: str, identifier: str, deadline: int, requester: str) -> None:
    failure = None
    try:
        while process.poll() is None:
            remaining = (deadline/1000)-time.time()
            if remaining <= 0 or not _lease_covers(resource,requester,deadline):
                failure = "lease-no-longer-covers-session" if remaining > 0 else None
                job.terminate()
                process.wait(timeout=10)
                break
            try:
                process.wait(timeout=min(1,remaining))
            except subprocess.TimeoutExpired:
                pass
    except Exception:
        failure = "login-flow-failed"
        job.terminate()
        process.wait(timeout=10)
    finally:
        with _CHANNELS_LOCK:
            channel = _CHANNELS.pop(identifier, None)
        if channel is not None:
            channel.close()
        job.close()
        proof = {"webSessionId":identifier,"processId":process.pid,"supervisorId":os.getpid()}
        _write(directory / "closed.json",proof)
        try:
            state = _state(directory)
            if state["state"] not in {"failed","closed"}:
                _write(directory / "state.json",{**state,"state":"failed" if failure else "closed","failureCode":failure,"updatedAt":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")})
        except core.ToolError:
            pass
        try:
            with vm_queue._resource_operation_lock(resource):
                marker = _active_path(resource)
                if marker.exists() and _read(marker.parent,marker.name) == proof:
                    marker.unlink()
        except core.ToolError:
            pass  # The next queue operation can use closed.json to clear this marker.


def _environment() -> dict[str, str]:
    # Debug/Node injection and proxy variables must not cause credential logging.
    allowed = {"PATH","SYSTEMROOT","WINDIR","COMSPEC","TEMP","TMP","USERPROFILE","LOCALAPPDATA","APPDATA","PROGRAMFILES","PROGRAMFILES(X86)","PROGRAMW6432","HOMEDRIVE","HOMEPATH"}
    return {k:v for k,v in os.environ.items() if k.upper() in allowed}


def probe_config(raw: dict[str, Any]) -> dict[str, Any]:
    if os.name != "nt":
        raise core.ToolError("Web browser probing requires Windows")
    node, module, parser = _node(), _module_path(), _parser_module_path()
    if not module or not parser:
        raise core.ToolError("Run remotex_web_runtime_setup before browser probing")
    directory = state_root() / "probes" / uuid.uuid4().hex
    secure_paths.ensure_private_directory(directory)
    packet = json.dumps({"config":raw,"mode":"probe","deadline":int((time.time()+60)*1000)}).encode()
    process = job = None
    try:
        process = subprocess.Popen([node,"--use-system-ca",str(PLUGIN / "scripts" / "web_login_worker.mjs"),str(directory),str(module),str(parser)],
            stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=_environment(),creationflags=subprocess.CREATE_NO_WINDOW)
        job = execution._WindowsJob(process,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
        if not job.assigned:
            raise OSError("Unable to bind browser process lifetime")
        process.communicate(input=packet,timeout=75)
    except (OSError,subprocess.SubprocessError) as exc:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        raise core.ToolError("Web browser probe did not complete") from exc
    finally:
        if job is not None:
            job.close()
    state = _state(directory)
    return {"ok":process.returncode == 0 and state["state"] == "ready",**state,"credentialUsed":False}


def probe(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) != {"profile"}:
        raise core.ToolError("Pass only profile")
    name, raw, bundle = core.select_profile("web",args["profile"])
    reference = credential_store.resolve_profile_reference(bundle,name,raw,"web")
    web_policy.validate_binding(raw,reference.reference_dict())
    return core.tool_result({"profile":name,**probe_config(raw)})


def login(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) - {"profile","requester","confirm","session_seconds","authorization_mode"} or args.get("confirm") is not True:
        raise core.ToolError("Web login requires profile, requester and confirm=true; credential values are not accepted")
    mode=args.get('authorization_mode','site')
    if mode not in {'site','granular'}:
        raise core.ToolError('authorization_mode must be site or granular')
    if os.name != "nt":
        raise core.ToolError("Web credential login requires Windows")
    seconds = args.get("session_seconds",MAX_SESSION_SECONDS)
    if type(seconds) is not int or not 60 <= seconds <= MAX_SESSION_SECONDS:
        raise core.ToolError(f"session_seconds must be between 60 and {MAX_SESSION_SECONDS}")
    name, raw, bundle = core.select_profile("web",args.get("profile"))
    reference = credential_store.resolve_profile_reference(bundle,name,raw,"web")
    web_policy.validate_binding(raw,reference.reference_dict())
    node, module, parser = _node(), _module_path(), _parser_module_path()
    if not module or not parser:
        raise core.ToolError("Run remotex_web_runtime_setup before web login")
    requester = vm_queue.validate_requester(args.get("requester"))
    resource = raw["queue_resource"]
    with queue_leases.leased_owner_operation(resource,requester) as owner:
        assert_resource_idle(resource)
        _, current, current_bundle = core.select_profile("web", name)
        current_reference = credential_store.resolve_profile_reference(current_bundle, name, current, "web")
        if current != raw or current_reference.reference_dict() != reference.reference_dict():
            raise core.ToolError("Web profile or certificate trust changed; probe the current configuration before login")
        lease = owner.get("lease") or {}
        if lease.get("remainingSeconds",0) < seconds + 45:
            raise core.ToolError(f"Renew this task's web queue lease to cover session_seconds plus 45 seconds (at least {seconds+45} seconds)")
        if mode=='site':
            try:
                recovery_root = state_root()/'authorization'
                if (recovery_root/'integrity.key').is_file() and not (recovery_root/'uncertain-writes.json').exists():
                    web_recovery._key_only(recovery_root)
                    raise core.ToolError('recovery-state-missing: run remotex_web_authorization_recovery with confirm=false; do not reset recovery state')
                web_authorization_store.require_site_protocol(recovery_root)
            except web_authorization.ScopeError as exc:
                raise core.ToolError('Run remotex_web_authorization_upgrade before site login: '+exc.code) from None
        _admit_v3_components(node,site=mode=='site')
        secret = core.read_windows_generic_credential(reference.reference_dict()["target"])
        if secret.username != raw["account"] or not secret.password or len(secret.password) > 4096:
            raise core.ToolError("Stored web credential does not match the configured account")
        root = state_root() / "sessions"
        secure_paths.ensure_private_directory(root)
        identifier = uuid.uuid4().hex
        directory = root / identifier
        secure_paths.ensure_private_directory(directory)
        deadline = int((time.time()+seconds)*1000)
        _write(directory / "session.json",{"profile":name,"requester":requester,"queueResource":resource,"originSha256":hashlib.sha256(raw["origin"].encode()).hexdigest(),"deadline":deadline})
        _write(directory / "state.json",{"state":"starting","loginSubmitted":False,"authenticationVerified":False,"failureCode":None,"updatedAt":datetime.now(timezone.utc).isoformat().replace("+00:00","Z")})
        process = job = None
        try:
            worker='web_site_worker.mjs' if mode=='site' else 'web_login_worker.mjs'
            process = subprocess.Popen([node,"--use-system-ca",str(PLUGIN / "scripts" / worker),str(directory),str(module),str(parser)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=_environment(),close_fds=True,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
            job = execution._WindowsJob(process,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
            if not job.assigned:
                raise OSError("Unable to bind browser process lifetime")
            marker = _active_path(resource)
            secure_paths.ensure_private_directory(marker.parent)
            _write(marker,{"webSessionId":identifier,"processId":process.pid,"supervisorId":os.getpid()})
            packet = json.dumps({"config":raw,"username":secret.username,"password":secret.password,"deadline":deadline,
                **({'authorization_mode':'site'} if mode=='site' else {})}).encode("utf-8") + b'\n'
            process.stdin.write(packet)
            process.stdin.flush()
            del packet, secret
            channel = web_channel.Channel(process,job,profile=name,requester=requester,resource=resource,deadline=deadline,config=raw)
            channel.worker_identity=uuid.uuid4().hex
            monotonic_deadline=time.monotonic()+max(0,deadline/1000-time.time())
            with queue_leases._locked() as (_,leases):
                acquisition=(leases['leases'].get(resource) or {}).get('acquisitionId')
            if not acquisition:
                raise core.ToolError('Renew the web queue lease before using task authorization')
            binding={'origin':raw['origin'],'account':raw['account'],'profile':name,'session':identifier,
                'worker':channel.worker_identity,'acquisition':acquisition,
                'profile_digest':web_authorization.digest([raw,reference.reference_dict()]),'deadline':monotonic_deadline}
            service_type=web_site_service.SiteService if mode=='site' else web_task_service.Service
            channel.authorization=service_type(channel,binding=binding,
                check=lambda:_authorization_binding(channel,identifier,monotonic_deadline),
                journal=web_authorization_store.Journal(state_root()/'authorization'))
            with _CHANNELS_LOCK:
                _CHANNELS[identifier] = channel
            channel.start()
            threading.Thread(target=_supervise,args=(process,job,directory,resource,identifier,deadline,requester),daemon=True).start()
        except Exception as exc:
            with _CHANNELS_LOCK:
                channel = _CHANNELS.pop(identifier,None)
            if channel is not None:
                channel.close()
            if process is not None:
                if job is not None:
                    job.terminate()
                    job.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
            _active_path(resource).unlink(missing_ok=True)
            raise core.ToolError("Unable to start web login securely") from exc
    # Native admission rechecks the covering lease; never reacquire its operation
    # lock while the launch transaction still holds it.
    if mode=='site':
        try:
            channel.authorization.begin()
        except Exception as exc:
            channel.close()
            raise core.ToolError('Unable to open local site authorization securely') from exc
    return core.tool_result({"ok":True,"webSessionId":identifier,"profile":name,"state":"starting","authenticationVerified":False,
                             "nextStep":"approve-local-site-window" if mode=='site' else "run-remotex-web-session-status",
                             "authorizationMode":mode,"sessionSeconds":seconds})


def session_status(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) != {"session_id"}:
        raise core.ToolError("Pass only session_id")
    directory = _directory(args["session_id"])
    state = _state(directory)
    metadata = _read(directory,"session.json")
    if set(metadata) != {"profile","requester","queueResource","originSha256","deadline"} or not isinstance(metadata.get("deadline"),int):
        raise core.ToolError("Web session metadata is invalid")
    expired = time.time()*1000 > metadata["deadline"] + 10000
    result = {"ok":state["state"] != "failed","webSessionId":args["session_id"],**state,
              "deadlineExceeded":expired,"nextStep":"release-own-web-queue" if state["state"] in {"failed","closed"} else "inspect-login-result-or-close-session"}
    with _CHANNELS_LOCK:
        channel = _CHANNELS.get(args['session_id'])
    result['sameSessionControlAvailable'] = bool(channel and channel.available and state['state']=='verified' and not expired)
    result['browserPolicyAttested'] = False
    return core.tool_result(result)


def _owned_channel(identifier, requester):
    if not isinstance(identifier,str) or re.fullmatch(r'[a-f0-9]{32}',identifier) is None:
        raise core.ToolError('Invalid web session ID')
    requester = vm_queue.validate_requester(requester)
    with _CHANNELS_LOCK:
        channel = _CHANNELS.get(identifier)
    if channel is None:
        raise core.ToolError('Same-session control is available only in the MCP process that started this session; do not attach another browser or copy cookies')
    if channel.requester != requester:
        raise core.ToolError('Another requester owns this web session')
    with queue_leases.leased_owner_operation(channel.resource,requester) as owner:
        remaining = (owner.get('lease') or {}).get('remainingSeconds')
        if time.time()*1000 >= channel.deadline or not isinstance(remaining,(int,float)) or remaining < (channel.deadline/1000-time.time())+45:
            channel.close()
            raise core.ToolError('Current queue lease no longer covers this web session')
        try:
            _, current, _ = core.select_profile('web',channel.profile)
        except core.ToolError:
            channel.close()
            raise
        if current != channel.config:
            channel.close()
            raise core.ToolError('Web configuration changed; close this session and probe the current configuration')
    # Do not hold the queue's operation lock while waiting for worker permit IPC.
    return channel


def _authorization_binding(channel, identifier, deadline):
    _owned_channel(identifier,channel.requester)
    _, current, bundle=core.select_profile('web',channel.profile)
    reference=credential_store.resolve_profile_reference(bundle,channel.profile,current,'web')
    with queue_leases._locked() as (_,leases):
        acquisition=(leases['leases'].get(channel.resource) or {}).get('acquisitionId')
    if not channel.available or not acquisition:
        raise web_authorization.ScopeError('session-unavailable')
    return {'origin':current['origin'],'account':current['account'],'profile':channel.profile,'session':identifier,
        'worker':channel.worker_identity,'acquisition':acquisition,
        'profile_digest':web_authorization.digest([current,reference.reference_dict()]),'deadline':deadline}


def _control(args: dict[str, Any], operation: str, extra: set[str]) -> dict[str, Any]:
    if set(args) != {'session_id','requester'} | extra:
        raise core.ToolError('Pass only the declared same-session control fields')
    _owned_channel(args['session_id'],args['requester'])
    return {**core.tool_result({'ok':False,'failureCode':'approval-required',
        'nextStep':'use-components-authorization-request-and-execute','webSessionId':args['session_id']}),'isError':True}


def _task_call(args, operation, required=(), optional=()):
    try:
        base={'session_id','requester'}
        if not isinstance(args,dict) or set(args)-(base|set(required)|set(optional)) or not base|set(required)<=set(args):
            raise web_authorization.ScopeError('request-invalid')
        channel=_owned_channel(args['session_id'],args['requester'])
        service=getattr(channel,'authorization',None)
        if not isinstance(service,(web_task_service.Service,web_site_service.SiteService)):
            raise web_authorization.ScopeError('new-owned-session-required')
        payload={key:value for key,value in args.items() if key not in base}
        if isinstance(service,web_site_service.SiteService) and operation not in {
                'components','status','site-execute','execution-status','revoke','resume-login'}:
            raise web_authorization.ScopeError('site-mode-active')
        if operation=='components':
            result=service.components()
        elif operation=='prepare':
            result=service.prepare(payload)
        elif operation=='request':
            result=service.request(payload)
        elif operation=='status':
            result=service.status(payload.get('request_id'))
        elif operation in {'execute','site-execute'}:
            if operation=='site-execute' and not isinstance(service,web_site_service.SiteService):
                raise web_authorization.ScopeError('site-mode-required')
            result=service.execute(payload)
        elif operation=='execution-status':
            result=service.execution_status(payload)
        elif operation=='revoke':
            result=service.revoke(payload)
        elif operation=='resume-login':
            result=service._worker('resume-login',{})
        else:
            raise web_authorization.ScopeError('request-invalid')
        output=core.tool_result({'ok':True,**result,'webSessionId':args['session_id']})
        guard=service.guard_output(operation,payload,result)
        return web_authorization.GuardedResult(output,guard) if guard is not None else output
    except web_authorization.ScopeError as exc:
        return {**core.tool_result({'ok':False,'failureCode':exc.code}),'isError':True}
    except Exception:
        return {**core.tool_result({'ok':False,'failureCode':'session-unavailable'}),'isError':True}


def checked_output(result):
    if not isinstance(result,web_authorization.GuardedResult):
        return result
    try:
        result.check_authority()
        return result
    except web_authorization.ScopeError as exc:
        return {**core.tool_result({'ok':False,'failureCode':exc.code}),'isError':True}
    except Exception:
        return {**core.tool_result({'ok':False,'failureCode':'session-unavailable'}),'isError':True}


def observe(args: dict[str, Any]) -> dict[str, Any]:
    return _control(args,'observe',set())


def read_result(args: dict[str, Any]) -> dict[str, Any]:
    return _control(args,'read-result',set())


def navigate(args: dict[str, Any]) -> dict[str, Any]:
    if type(args.get('confirm')) is not bool or any(not isinstance(args.get(k),str) or re.fullmatch(r'[a-f0-9]{32}',args[k]) is None for k in ('observation_id','element_ref')):
        raise core.ToolError('Navigation requires fresh observation and element IDs plus a boolean confirm')
    return _control(args,'navigate',{'observation_id','element_ref','confirm'})


def close_session(args: dict[str, Any]) -> dict[str, Any]:
    if set(args) != {"session_id","requester","confirm"} or args.get("confirm") is not True:
        raise core.ToolError("Closing a web session requires confirm=true, session_id and its requester")
    directory = _directory(args["session_id"])
    metadata = _read(directory,"session.json")
    if vm_queue.validate_requester(args["requester"]) != metadata.get("requester"):
        raise core.ToolError("Another requester owns this web session")
    request = directory / "close.request"
    if secure_paths._reparse_point(request):
        raise core.ToolError("Web session close request is invalid")
    request.touch(exist_ok=True)
    return core.tool_result({"ok":True,"closeRequested":True,"webSessionId":args["session_id"],"nextStep":"check-session-closed-before-releasing-queue"})


def _schema(properties: dict, required: list[str]) -> dict:
    return {"type":"object","properties":properties,"required":required,"additionalProperties":False}


TOOLS = {
    'remotex_web_authorization_recovery': {'description': 'Preview eligible legacy key-only recovery, request one native owner-review window, or read status. confirm=true never approves. Requires idle web lifecycle and reconciled evidence; no credentials, network, queue changes or site grant. Missing/corrupt/unknown write evidence remains blocked.',
        'inputSchema': _schema({'confirm': {'type': 'boolean', 'default': False}, 'recovery_id': {'type': 'string', 'pattern': '^[a-f0-9]{32}$'}}, []), 'handler': authorization_recovery},
    'remotex_web_observe':{'description':'Read bounded, redacted visible text and navigation references from the authenticated RemoteX page. Requires current host browser permission and the original requester/lease; never use after host browser access is denied or unknown.',
        'inputSchema':_schema({'session_id':{'type':'string'},'requester':{'type':'string'}},['session_id','requester']),'handler':observe},
    'remotex_web_read_result':{'description':'Read numeric/boolean result-code summaries of responses already received by this authenticated page. Sends no request. Not proof of business success or task permissions. Requires current host browser permission and the original requester/lease.',
        'inputSchema':_schema({'session_id':{'type':'string'},'requester':{'type':'string'}},['session_id','requester']),'handler':read_result},
    'remotex_web_navigate':{'description':'Preview or follow one fresh observed same-document fragment link in the same session. No arbitrary URL, click handler, form, script or raw HTTP. confirm=true requires authorized destination and current host browser permission; navigation is not proof that the site is read-only.',
        'inputSchema':_schema({'session_id':{'type':'string'},'requester':{'type':'string'},'observation_id':{'type':'string'},'element_ref':{'type':'string'},'confirm':{'type':'boolean'}},['session_id','requester','observation_id','element_ref','confirm']),'handler':navigate},
    "remotex_web_certificate_trust":{"description":"Preview or explicitly set/revoke one web profile's exact-origin certificate SHA-256 trust. Confirm the fingerprint through a trusted channel first; null restores system trust.",
        "inputSchema":_schema({"profile":{"type":"string"},"origin":{"type":"string"},"certificate_sha256":{"type":["string","null"]},"confirm":{"type":"boolean"}},["profile","origin","certificate_sha256","confirm"]),"handler":certificate_trust},
    "remotex_web_probe":{"description":"Open an isolated Edge session to verify HTTPS and login controls without reading or submitting credentials.","inputSchema":_schema({"profile":{"type":"string"}},["profile"]),"handler":probe},
    "remotex_web_profile_setup":{"description":"Preview or create an HTTPS/account-bound Edge web profile and open the local secure credential window. Password values are never accepted.",
        "inputSchema":_schema({k:({"type":"boolean"} if k=="confirm" else {"type":"integer","minimum":1,"maximum":600} if k=="timeout_seconds" else {"type":"string"}) for k in sorted(SETUP_FIELDS)},
            ["profile","url","account","credential_ref","username_selector","password_selector","submit_selector","confirm"]),"handler":setup},
    "remotex_web_runtime_setup":{"description":"Check or install the complete pinned Playwright Core and JSON parser runtime for existing Microsoft Edge; never changes browser security policy.","inputSchema":_schema({"confirm":{"type":"boolean"}},[]),"handler":runtime_setup},
    "remotex_web_authorization_upgrade":{"description":"Preview, or explicitly upgrade the local deny-only web recovery protocol to v2 before one-click site authorization. Requires all web sessions naturally closed and no unresolved writes. Preview never creates storage; never stops sessions, clears records or modifies SSH/VM configuration. Old web writers fail closed after upgrade and must reload safely.","inputSchema":_schema({"confirm":{"type":"boolean"}},[]),"handler":authorization_upgrade},
    "remotex_web_login":{"description":"Open one local site authorization window, then automatically initialize and sign in to visible Edge using the saved origin/account-bound credential. Site mode covers ordinary task reads and writes for up to 12 hours; sensitive operations need separate confirmation. Requires current supported host browser access and the caller's covering queue lease. No passwords in arguments.",
        "inputSchema":_schema({"profile":{"type":"string"},"requester":{"type":"string"},"confirm":{"type":"boolean"},
            "authorization_mode":{"type":"string","enum":["site","granular"],"default":"site","description":"Site is the one-click task authorization flow. Granular retains the legacy exact-request protocol for a new session."},
            "session_seconds":{"type":"integer","minimum":60,"maximum":MAX_SESSION_SECONDS,"default":MAX_SESSION_SECONDS,"description":"New session duration, default/maximum 46800 seconds (13 hours); queue lease must cover it plus 45 seconds."}},["profile","requester","confirm"]),"handler":login},
    "remotex_web_session_status":{"description":"Read sanitized Edge login state without exposing DOM, screenshots, cookies or credentials.","inputSchema":_schema({"session_id":{"type":"string"}},["session_id"]),"handler":session_status},
    "remotex_web_session_close":{"description":"Request closure of this requester's RemoteX-owned Edge session. Read back closed state before releasing its queue lease.","inputSchema":_schema({"session_id":{"type":"string"},"requester":{"type":"string"},"confirm":{"type":"boolean"}},["session_id","requester","confirm"]),"handler":close_session},
}


_ID={'type':'string','pattern':'^[a-f0-9]{32}$'}
_TEXT={'type':'string','minLength':1,'maxLength':128}
_REFS={'type':'array','items':_ID,'maxItems':32,'uniqueItems':True}
_EVIDENCE={'type':'array','minItems':1,'maxItems':8,'items':_schema({
    'kind':{'type':'string','enum':['source-review','api-document','verified-record','operator-inspected']},
    'reference':{'type':'string','minLength':1,'maxLength':512}},['kind','reference'])}
_LITERAL={'type':['string','boolean','integer']}
_POINTER={'type':'string','minLength':2,'maxLength':512,'pattern':'^/'}
_CHECK={'oneOf':[
    _schema({'pointer':_POINTER,'test':{'const':'type'},'expected':{'type':'string','enum':['object','array','string','boolean','integer','null']}},['pointer','test','expected']),
    _schema({'pointer':_POINTER,'test':{'const':'nonempty-string'}},['pointer','test']),
    _schema({'pointer':_POINTER,'test':{'const':'equals-boolean'},'expected':{'type':'boolean'}},['pointer','test','expected']),
    _schema({'pointer':_POINTER,'test':{'const':'equals-integer'},'expected':{'type':'integer','minimum':-9007199254740991,'maximum':9007199254740991}},['pointer','test','expected'])]}
_SETUP_USE={'type':'integer','minimum':1,'maximum':10,'default':2}
_SETUP_PHASE={'type':'string','enum':['bootstrap','login-once']}
_LEGACY_SETUP=_schema({'phase':_SETUP_PHASE,'network_refs':_REFS,'evidence':_EVIDENCE,'max_uses':_SETUP_USE},['phase','network_refs','evidence'])
_SETUP_REQUEST={'oneOf':[
    _schema({'network_ref':_ID,'purpose':{'const':'bootstrap-resource'},'max_uses':_SETUP_USE,'evidence':_EVIDENCE},['network_ref','purpose','evidence']),
    _schema({'network_ref':_ID,'purpose':{'const':'initialization-read'},'max_uses':_SETUP_USE,'evidence':_EVIDENCE,
        'response_checks':{'type':'array','minItems':1,'maxItems':8,'items':_CHECK}},['network_ref','purpose','evidence','response_checks'])]}
_MODERN_SETUP=_schema({'revision':{'type':'integer','const':2},'phase':_SETUP_PHASE,
    'requests':{'type':'array','minItems':1,'maxItems':32,'items':_SETUP_REQUEST},
    'replace_grant_ids':{'type':'array','maxItems':2,'uniqueItems':True,'items':_ID}},['revision','phase','requests'])
_V3_SETUP_REQUEST=_schema({'network_ref':_ID,'purpose':{'const':'initialization-read'},
    'representation_ref':_ID,'literal_review_refs':{**_REFS,'minItems':1},'max_uses':_SETUP_USE,
    'response_checks':{'type':'array','minItems':1,'maxItems':8,'items':_CHECK},'evidence':_EVIDENCE},
    ['network_ref','purpose','representation_ref','literal_review_refs','response_checks','evidence'])
_V3_SETUP=_schema({'revision':{'type':'integer','const':3},'phase':_SETUP_PHASE,
    'requests':{'type':'array','minItems':1,'maxItems':32,'items':_V3_SETUP_REQUEST}},['revision','phase','requests'])
_ITEM=_schema({'item_id':_TEXT,'capability':{'type':'string','enum':sorted(web_authorization.CAPABILITIES)},
    'observation_id':_ID,'component_ref':_ID,'max_uses':{'type':'integer','minimum':1,'maximum':50},
    'depends_on':{'type':'array','items':_TEXT,'maxItems':32,'uniqueItems':True},
    'parameters':_schema({'action':{'type':'string','enum':['fill','select','check']},'value':_LITERAL},[]),
    'limits':_schema({'rows':{'type':'integer','minimum':0,'maximum':100},
        'columns':{'type':'integer','minimum':0,'maximum':30},'bytes':{'type':'integer','minimum':0,'maximum':98304}},[]),
    'network_refs':_REFS,'network_evidence':_EVIDENCE,'action_draft_ref':_ID},
    ['item_id','capability','observation_id','component_ref'])
_EFFECT=_schema({'kind':{'type':'string','enum':['create','update','delete','assign','command','cancel','compensate']},
    'name':{'type':'string','maxLength':160},'risks':{'type':'array','items':{'type':'string','enum':[
        'irreversible','weakens-protection','expands-access','availability','inherited-policy','external-concurrency']},'maxItems':6,'uniqueItems':True},
    'fields':{'type':'array','items':_TEXT,'minItems':1,'maxItems':30},'evidence':_EVIDENCE,
    'requires_cas':{'type':'boolean'}},['kind','name','risks','fields','evidence'])
_TASKS={
    'remotex_web_site_execute':('site-execute',{'observation_id':_ID,'component_ref':_ID,
        'action':{'type':'string','enum':['read','read-table','click','fill','select','check']},
        'value':{'type':['string','boolean'],'maxLength':1024},
        'risk':{'type':'string','enum':['ordinary','sensitive'],'description':'Mark irreversible deletion, access/security changes, legal acceptance and other sensitive effects as sensitive. Labels may escalate the review, never override it. Credentials, CAPTCHAs and consequential payments require manual handling.'},
        'idempotency_key':_TEXT},['observation_id','component_ref','action','risk','idempotency_key'],
        'Operate one fresh observed component under the existing site grant, with no resource/category approval. Supports page and table reads, ordinary buttons and non-secret forms. Sensitive effects open a concrete native confirmation. Reuse the same key after uncertain results; never replay with another key. Requires current supported host browser access.'),
    'remotex_web_components':('components',{},[],
        'Discover bounded component metadata in the original authenticated Edge session; not page content or authority. Requires current supported host browser access.'),
    'remotex_web_action_prepare':('prepare',{'observation_id':_ID,'component_ref':_ID,
        'target_refs':{'type':'array','items':_ID,'minItems':1,'maxItems':100,'uniqueItems':True},'read_receipts':_REFS,
        'changes':{'type':'array','maxItems':30,'items':_schema({'component_ref':_ID,'receipt_ref':_ID,
            'value':_LITERAL,'action':{'type':'string','enum':['fill','select','check']}},['component_ref','receipt_ref','value','action'])},
        'effect':_EFFECT,'network_refs':_REFS,
        'target_state':{'type':'object','additionalProperties':_schema({'header':{'type':'string','minLength':1,'maxLength':160},
            'after':_LITERAL},['header','after'])},
        'network_bindings':{'type':'array','maxItems':32,'items':_schema({
            'network_ref':_ID,'target_path':{'type':'array','items':_TEXT,'minItems':2,'maxItems':8},
            'change_paths':{'type':'object','additionalProperties':{'type':'array','items':_TEXT,'minItems':2,'maxItems':8}}},
            ['network_ref','target_path','change_paths'])}},
        ['observation_id','component_ref','target_refs','read_receipts','changes','effect','network_refs'],
        'Prepare an immutable write preview from approved reads and observed controls. Does not change the page or send requests. Show actual targets and before/after values before requesting real business writes.'),
    'remotex_web_authorization_request':('request',{'items':{'type':'array','items':_ITEM,'minItems':1,'maxItems':32},
        'setup':{'oneOf':[_LEGACY_SETUP,_MODERN_SETUP,_V3_SETUP]},
        'idempotency_key':_TEXT,'ttl_seconds':{'type':'integer','minimum':60,'maximum':web_authorization.MAX_GRANT_SECONDS,'default':web_authorization.MAX_GRANT_SECONDS,'description':'Requested task grant lifetime, default/maximum 43200 seconds (12 hours); human may lower it, and the existing session deadline still caps it.'}},['idempotency_key'],
        'Request exact observed operations OR blocked startup contracts through the local human window. Revision3 adds private native review of complete independent public references for exact initialization POSTs; no values or approval verdicts in public arguments. Revision2 static-only replacement is separate. Four active grants; new reviews last at most 180 seconds. Notification requested/shown is not authority or proof of visibility. No credentials, raw requests or self-approval.'),
    'remotex_web_authorization_status':('status',{'request_id':_ID},[],
        'Read decisions, expiry, quotas, blocked descriptors and approval_ui lifecycle/remaining review/exit diagnostics. Shown is not authority or proof of foreground. No approval or request transmission.'),
    'remotex_web_execute':('execute',{'grant_id':_ID,'item_id':_TEXT,'idempotency_key':_TEXT,
        'observation_id':_ID,'component_ref':_ID},['grant_id','item_id','idempotency_key','observation_id','component_ref'],
        'Execute one human-approved typed operation once using fresh observed references. May click approved buttons, fill exact non-secret fields and submit a scoped business workflow. Never retries uncertain writes; inspect the original attempt instead.'),
    'remotex_web_execution_status':('execution-status',{'attempt_id':_ID,'read_receipts':_REFS},['attempt_id'],
        'Read the original attempt without replaying it. Optional fresh approved table-read receipts reconcile actual per-target desired state; no success flag or raw data accepted. A click or HTTP success is not business verification.'),
    'remotex_web_authorization_revoke':('revoke',{'request_id':_ID,'grant_id':_ID,
        'items':{'type':'array','items':_TEXT,'maxItems':32,'uniqueItems':True},'end_task':{'type':'boolean'}},[],
        'Cancel one own pending request, revoke a grant or selected items, or end task authority. Concurrent effects are fenced; already accepted server work cannot be undone.'),
    'remotex_web_login_resume':('resume-login',{},[],
        'Resume the same owned login page after local approval of exact blocked startup contracts; the original result may take up to 55 seconds. Never replays HTTP packets or resubmits a potentially transmitted authentication exchange. Requires current supported host browser access.'),
}

for _name,(_operation,_properties,_required,_description) in _TASKS.items():
    TOOLS[_name]={'description':_description,'inputSchema':_schema({
        'session_id':_ID,'requester':_TEXT,**_properties},['session_id','requester',*_required]),
        'handler':lambda args,op=_operation,required=tuple(_required),optional=tuple(set(_properties)-set(_required)):
            _task_call(args,op,required,optional)}
