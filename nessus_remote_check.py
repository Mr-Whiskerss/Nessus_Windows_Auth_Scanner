#!/usr/bin/env python3
"""
nessus_remote_check.py - Remote (scanner-side) readiness checker for Nessus Windows
                         credentialed/authenticated scans.

Run from a Linux box (e.g. Kali) against one or more Windows targets BEFORE launching a
Nessus credentialed scan. It exercises the same channels Nessus relies on:

    * TCP reachability        : 135 (RPC/WMI), 139 (NetBIOS), 445 (SMB)
    * SMB authentication      : do the supplied creds actually log in? (NTLM or Kerberos)
    * Local admin rights      : can we reach ADMIN$ / C$ (the "Pwn3d!" equivalent)?
    * Administrative shares   : ADMIN$, C$, IPC$ present/accessible
    * Remote Registry         : winreg RPC reachable, or RemoteRegistry start-type
                                (Disabled => Nessus cannot start it; Manual/Stopped => it can, with admin)
    * (opt) RemoteReg probe    : actually start the service + bind winreg + restore state,
                                proving Nessus's "Start the Remote Registry service" will work
    * WMI over DCOM           : root/cimv2 login (catches dynamic-RPC firewall blocks)
    * SMB signing / SMBv1     : informational / finding-worthy
    * OS detection -> CIS     : authoritative via remote registry, fallback WMI, fallback SMB build

Auth supports password, NTLM hash (pass-the-hash), or Kerberos (ccache / AES key).

Examples:
    ./nessus_remote_check.py -t 192.168.1.50 -u svc_scan -p 'P@ss' -d CORP
    ./nessus_remote_check.py -t 192.168.1.0/24 -u admin -p 'Pass' --threads 20 -o run1
    ./nessus_remote_check.py -iL targets.txt -u admin -H :e19ccf... --stop-on-lockout
    ./nessus_remote_check.py -t dc01.corp.local -u admin -k --no-pass --dc-ip 192.168.1.10
    ./nessus_remote_check.py -t 192.168.1.50 -u admin -p 'Pass' --probe-remoteregistry

Requires: impacket  (apt install python3-impacket  /  pip install impacket)

Author : Dan (Mr-Whiskerss)
Version: 1.1.0
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import socket
import sys
import threading
import time
from collections import Counter
from datetime import datetime
from html import escape

TOOL_VERSION = "1.1.0"

# --- impacket imports (fail gracefully) -------------------------------------------
try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.smb import SMB_DIALECT
    from impacket.dcerpc.v5 import transport, rrp, scmr
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
except ImportError:
    sys.stderr.write(
        "[!] impacket is required. Install it with:\n"
        "      sudo apt install python3-impacket    # Kali/Debian\n"
        "      pip install impacket                 # venv\n"
    )
    sys.exit(1)

# Cross-thread safety brake for credential lockout
LOCKOUT_EVENT = threading.Event()


# ----------------------------------------------------------------------------------
# Console colour
# ----------------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"
    GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
    CYAN = "\033[96m"; MAGENTA = "\033[95m"; WHITE = "\033[97m"
    enabled = True

    @classmethod
    def s(cls, text, colour):
        return text if not cls.enabled else f"{colour}{text}{cls.RESET}"


def status_colour(status):
    return {"PASS": C.GREEN, "WARN": C.YELLOW, "FAIL": C.RED, "INFO": C.CYAN}.get(status, C.WHITE)


# ----------------------------------------------------------------------------------
# CIS benchmark mapping
# ----------------------------------------------------------------------------------
def map_cis(build, is_server, display_version):
    rel = f" ({display_version})" if display_version else ""
    try:
        build = int(build)
    except (TypeError, ValueError):
        return {"os": "Unknown", "benchmark": "Unknown - could not determine build"}

    if is_server:
        if build >= 26100:
            return {"os": f"Windows Server 2025{rel}", "benchmark": "CIS Microsoft Windows Server 2025 Benchmark"}
        return {
            20348: {"os": "Windows Server 2022", "benchmark": "CIS Microsoft Windows Server 2022 Benchmark"},
            17763: {"os": "Windows Server 2019", "benchmark": "CIS Microsoft Windows Server 2019 Benchmark"},
            14393: {"os": "Windows Server 2016", "benchmark": "CIS Microsoft Windows Server 2016 Benchmark"},
            9600:  {"os": "Windows Server 2012 R2", "benchmark": "CIS Microsoft Windows Server 2012 R2 Benchmark"},
            9200:  {"os": "Windows Server 2012", "benchmark": "CIS Microsoft Windows Server 2012 (non-R2) Benchmark"},
            7601:  {"os": "Windows Server 2008 R2", "benchmark": "CIS Microsoft Windows Server 2008 R2 Benchmark (legacy)"},
        }.get(build, {"os": f"Windows Server (build {build})", "benchmark": "No exact match - select nearest CIS Windows Server Benchmark"})

    if build >= 22000:
        return {"os": f"Windows 11{rel}", "benchmark": "CIS Microsoft Windows 11 Enterprise Benchmark"}
    if 10240 <= build < 22000:
        rl = {19045: "22H2", 19044: "21H2"}.get(build, display_version)
        suffix = f" ({rl})" if rl else ""
        return {"os": f"Windows 10{suffix}", "benchmark": "CIS Microsoft Windows 10 Enterprise Benchmark"}
    return {
        9600: {"os": "Windows 8.1", "benchmark": "CIS Microsoft Windows 8.1 Benchmark (legacy)"},
        7601: {"os": "Windows 7", "benchmark": "CIS Microsoft Windows 7 Benchmark (legacy)"},
    }.get(build, {"os": f"Windows (build {build})", "benchmark": "No exact match - select nearest CIS Windows Benchmark"})


# ----------------------------------------------------------------------------------
# Auth error interpretation
# ----------------------------------------------------------------------------------
AUTH_STATUS = {
    0xC000006D: ("Bad username or password", False),
    0xC000006A: ("Wrong password", False),
    0xC0000234: ("Account is LOCKED OUT", True),
    0xC0000071: ("Password has expired", False),
    0xC0000224: ("Password must be changed before first logon", False),
    0xC0000072: ("Account is DISABLED", False),
    0xC0000193: ("Account has EXPIRED", False),
    0xC000006F: ("Logon outside permitted hours", False),
    0xC0000070: ("Workstation restriction - logon not allowed from this host", False),
    0xC000015B: ("Account lacks the network logon right (LOGON_TYPE_NOT_GRANTED)", False),
    0xC0000022: ("Access denied", False),
    0xC000018D: ("Trust relationship failure", False),
    0xC0000133: ("Clock skew too great (Kerberos)", False),
}


def interpret_auth_error(e):
    """Return (human_message, is_lockout)."""
    code = None
    try:
        code = e.getErrorCode()
    except Exception:
        pass
    if code is not None:
        if code in AUTH_STATUS:
            msg, locked = AUTH_STATUS[code]
            return f"{msg} (0x{code & 0xFFFFFFFF:08X})", locked
        return f"NTSTATUS 0x{code & 0xFFFFFFFF:08X}", False
    s = str(e)
    return s, ("STATUS_ACCOUNT_LOCKED_OUT" in s)


# ----------------------------------------------------------------------------------
# Per-host result container
# ----------------------------------------------------------------------------------
class HostResult:
    def __init__(self, host):
        self.host = host
        self.checks = []          # (category, check, status, detail, reco)
        self.os = {}
        self.cis = {}
        self.verdict = ""
        self.verdict_status = "INFO"
        # structured flags for table / CSV
        self.reachable445 = None
        self.authenticated = None
        self.is_admin = None
        self.remotereg = None     # ok / startable / disabled / unknown
        self.wmi_ok = None
        self.smbv1 = None
        self.signing = None

    def add(self, category, check, status, detail, reco=""):
        self.checks.append((category, check, status, detail, reco))

    def counts(self):
        out = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
        for _, _, s, _, _ in self.checks:
            out[s] = out.get(s, 0) + 1
        return out


# ----------------------------------------------------------------------------------
# Individual remote checks
# ----------------------------------------------------------------------------------
def check_ports(res, host, ports, timeout):
    open_ports = {}
    for port, name in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            ok = (sock.connect_ex((host, port)) == 0)
        except Exception:
            ok = False
        finally:
            sock.close()
        open_ports[port] = ok
        if ok:
            res.add("Ports", f"TCP {port} ({name})", "PASS", "Open / reachable.")
        else:
            critical = port in (445, 135)
            res.add("Ports", f"TCP {port} ({name})", "FAIL" if critical else "WARN",
                    "Closed / filtered / unreachable.",
                    "Confirm host is up and the scanner can reach this port (routing/host firewall).")
    return open_ports


def smb_connect(host, port, timeout):
    return SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=timeout)


def do_login(smb, args, lmhash, nthash):
    """Perform NTLM or Kerberos login on an SMBConnection."""
    if args.kerberos:
        smb.kerberosLogin(args.user, args.password or "", args.domain or "",
                          lmhash or "", nthash or "", aesKey=args.aes_key or "",
                          kdcHost=args.dc_ip, useCache=bool(args.no_pass))
    else:
        smb.login(args.user, args.password or "", args.domain or "", lmhash or "", nthash or "")


def check_smb_and_auth(res, host, args, lmhash, nthash):
    """Returns (smb_or_None, authed_bool, is_admin_bool)."""
    try:
        smb = smb_connect(host, args.port, args.timeout)
    except Exception as e:
        res.add("SMB", "SMB negotiation", "FAIL", f"Could not negotiate SMB: {e}",
                "Confirm SMB (445) is reachable and the Server service is running on the target.")
        return None, False, False

    try:
        dialect = smb.getDialect()
        dialect_name = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
                        0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", SMB_DIALECT: "SMB 1.0"}.get(dialect, hex(dialect))
        res.signing = bool(smb.isSigningRequired())
        res.add("SMB", "Negotiated dialect", "INFO", dialect_name)
        res.add("SMB", "Signing required", "INFO", str(res.signing))
    except Exception:
        pass

    if args.user is None:
        res.add("Auth", "Credential test", "INFO", "No credentials supplied - auth-dependent checks skipped (recon mode).")
        return smb, False, False

    try:
        do_login(smb, args, lmhash, nthash)
    except SessionError as e:
        msg, locked = interpret_auth_error(e)
        res.add("Auth", "SMB authentication", "FAIL", f"Login failed: {msg}",
                "Verify username/password/domain (or hash/ticket).")
        if locked and args.stop_on_lockout:
            LOCKOUT_EVENT.set()
            res.add("Auth", "Lockout guard", "FAIL", "Lockout detected - halting further attempts (--stop-on-lockout).")
        return smb, False, False
    except Exception as e:
        msg, locked = interpret_auth_error(e)
        res.add("Auth", "SMB authentication", "FAIL", f"Login failed: {msg}",
                "Verify credentials and that the account may authenticate to this host.")
        if locked and args.stop_on_lockout:
            LOCKOUT_EVENT.set()
        return smb, False, False

    try:
        if smb.isGuestSession():
            res.add("Auth", "SMB authentication", "WARN", "Authenticated but mapped to GUEST - not a credentialed context.",
                    "Use a valid account; guest-mapped sessions yield no credentialed results.")
            return smb, True, False
    except Exception:
        pass

    res.add("Auth", "SMB authentication", "PASS",
            f"Authenticated as {args.domain + chr(92) if args.domain else ''}{args.user}"
            f"{' (Kerberos)' if args.kerberos else ''}.")

    is_admin = False
    for share in ("ADMIN$", "C$"):
        try:
            tid = smb.connectTree(share)
            smb.disconnectTree(tid)
            is_admin = True
            break
        except Exception:
            continue
    if is_admin:
        res.add("Auth", "Local administrator rights", "PASS", "Reached an administrative share (ADMIN$/C$) - account is a local admin.")
    else:
        res.add("Auth", "Local administrator rights", "FAIL",
                "Authenticated but could NOT reach ADMIN$/C$ - account is not a local admin.",
                "Nessus credentialed scans require local administrator rights on the target.")
    return smb, True, is_admin


def check_admin_shares(res, smb):
    try:
        shares = [s["shi1_netname"].rstrip("\x00") for s in smb.listShares()]
    except Exception as e:
        res.add("Shares", "Share enumeration", "WARN", f"Could not enumerate shares: {e}",
                "Admin share access could not be confirmed via enumeration.")
        return
    for req in ("ADMIN$", "C$", "IPC$"):
        if req in shares:
            res.add("Shares", f"{req} share", "PASS", "Present.")
        else:
            sev = "WARN" if req == "IPC$" else "FAIL"
            res.add("Shares", f"{req} share", sev, "Not present in share list.",
                    "Ensure default administrative shares are enabled on the target.")


def check_remote_registry(res, smb, host, port):
    """Returns one of: ok / disabled / startable / unknown."""
    try:
        rpc = transport.SMBTransport(host, port, r"\winreg", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(rrp.MSRPC_UUID_RRP)
        res.add("RemoteReg", "Remote Registry (winreg)", "PASS", "winreg RPC reachable - registry-based plugins will work.")
        dce.disconnect()
        return "ok"
    except Exception:
        pass

    start_map = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
    state_map = {1: "Stopped", 2: "StartPending", 3: "StopPending", 4: "Running"}
    try:
        rpc = transport.SMBTransport(host, port, r"\svcctl", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(scmr.MSRPC_UUID_SCMR)
        scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
        svc = scmr.hROpenServiceW(dce, scm, "RemoteRegistry\x00")["lpServiceHandle"]
        cfg = scmr.hRQueryServiceConfigW(dce, svc)["lpServiceConfig"]
        st = scmr.hRQueryServiceStatus(dce, svc)["lpServiceStatus"]
        start = start_map.get(cfg["dwStartType"], cfg["dwStartType"])
        state = state_map.get(st["dwCurrentState"], st["dwCurrentState"])
        dce.disconnect()
        if start == "Disabled":
            res.add("RemoteReg", "Remote Registry service", "WARN",
                    f"Service is DISABLED (state: {state}) - Nessus cannot start it.",
                    "Set RemoteRegistry start-type to Manual; registry-based plugins will otherwise fail.")
            return "disabled"
        res.add("RemoteReg", "Remote Registry service", "WARN",
                f"Service start-type: {start}, state: {state} - winreg not currently reachable.",
                "With admin rights Nessus can start it during the scan if 'Start the Remote Registry service' is enabled.")
        return "startable"
    except Exception as e:
        res.add("RemoteReg", "Remote Registry", "WARN", f"Could not reach winreg or query the service ({e}).",
                "Registry-based collection may be impaired; verify RemoteRegistry availability.")
        return "unknown"


def probe_remote_registry_start(res, smb, host, port, timeout):
    """OPT-IN: start RemoteRegistry, confirm winreg binds, then restore the original state.
    Proves Nessus's 'Start the Remote Registry service during the scan' option will work."""
    try:
        rpc = transport.SMBTransport(host, port, r"\svcctl", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(scmr.MSRPC_UUID_SCMR)
        scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
        svc = scmr.hROpenServiceW(dce, scm, "RemoteRegistry\x00")["lpServiceHandle"]
        cfg = scmr.hRQueryServiceConfigW(dce, svc)["lpServiceConfig"]
        state0 = scmr.hRQueryServiceStatus(dce, svc)["lpServiceStatus"]["dwCurrentState"]

        if cfg["dwStartType"] == 4:
            res.add("Probe", "RemoteRegistry start probe", "WARN",
                    "Service is Disabled - cannot be started (Nessus cannot start it either).",
                    "Set start-type to Manual to allow registry-based collection.")
            dce.disconnect(); return
        if state0 == 4:
            res.add("Probe", "RemoteRegistry start probe", "PASS", "Service already running - no action needed.")
            dce.disconnect(); return

        try:
            scmr.hRStartServiceW(dce, svc)
        except Exception as e:
            res.add("Probe", "RemoteRegistry start probe", "WARN", f"Start request failed: {e}",
                    "Account may lack SERVICE_START on RemoteRegistry.")
            dce.disconnect(); return

        running = False
        for _ in range(max(2, int(timeout * 2))):
            time.sleep(0.5)
            cur = scmr.hRQueryServiceStatus(dce, svc)["lpServiceStatus"]["dwCurrentState"]
            if cur == 4:
                running = True
                break

        winreg_ok = False
        if running:
            try:
                r2 = transport.SMBTransport(host, port, r"\winreg", smb_connection=smb)
                d2 = r2.get_dce_rpc(); d2.connect(); d2.bind(rrp.MSRPC_UUID_RRP); d2.disconnect()
                winreg_ok = True
            except Exception:
                pass

        # Restore: original state was not-running, so stop it again
        restored = "restored to Stopped"
        try:
            scmr.hRControlService(dce, svc, scmr.SERVICE_CONTROL_STOP)
        except Exception as e:
            restored = f"WARNING: could not restore service to Stopped ({e})"
        dce.disconnect()

        if running and winreg_ok:
            res.add("Probe", "RemoteRegistry start probe", "PASS",
                    f"Started service and bound winreg successfully, then {restored}. Nessus auto-start will work.")
        elif running:
            res.add("Probe", "RemoteRegistry start probe", "WARN",
                    f"Service started but winreg bind failed; {restored}.")
        else:
            res.add("Probe", "RemoteRegistry start probe", "WARN",
                    f"Service did not reach Running within timeout; {restored}.")
    except Exception as e:
        res.add("Probe", "RemoteRegistry start probe", "WARN", f"Probe could not run: {e}")


def detect_os_via_registry(smb, host, port):
    try:
        rpc = transport.SMBTransport(host, port, r"\winreg", smb_connection=smb)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(rrp.MSRPC_UUID_RRP)
        hklm = rrp.hOpenLocalMachine(dce)["phKey"]
        key = rrp.hBaseRegOpenKey(dce, hklm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]

        def rd(name):
            try:
                _, val = rrp.hBaseRegQueryValue(dce, key, name + "\x00")
                return val.rstrip("\x00") if isinstance(val, str) else val
            except Exception:
                return None

        info = {
            "ProductName": rd("ProductName"),
            "DisplayVersion": rd("DisplayVersion") or rd("ReleaseId"),
            "CurrentBuild": rd("CurrentBuildNumber") or rd("CurrentBuild"),
            "UBR": rd("UBR"),
            "EditionID": rd("EditionID"),
            "InstallationType": rd("InstallationType"),
        }
        dce.disconnect()
        if info["CurrentBuild"]:
            return info
    except Exception:
        return None
    return None


def detect_os_via_wmi(host, args, lmhash, nthash):
    """WMI-over-DCOM reachability test + OS fallback (authoritative ProductType)."""
    dcom = None
    try:
        dcom = DCOMConnection(host, args.user or "", args.password or "", args.domain or "",
                              lmhash or "", nthash or "", aesKey=args.aes_key or "",
                              oxidResolver=True, doKerberos=bool(args.kerberos), kdcHost=args.dc_ip)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        login = wmi.IWbemLevel1Login(iInterface)
        services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
        login.RemRelease()
        result = {"_wmi_ok": True}
        try:
            it = services.ExecQuery("SELECT Caption, Version, BuildNumber, ProductType FROM Win32_OperatingSystem")
            obj = it.Next(0xffffffff, 1)[0]
            props = obj.getProperties()
            result.update({
                "Caption": props.get("Caption", {}).get("value"),
                "Version": props.get("Version", {}).get("value"),
                "BuildNumber": props.get("BuildNumber", {}).get("value"),
                "ProductType": props.get("ProductType", {}).get("value"),
            })
            it.RemRelease()
        except Exception:
            pass
        return result
    except Exception as e:
        return {"_wmi_ok": False, "_error": str(e)}
    finally:
        if dcom:
            try:
                dcom.disconnect()
            except Exception:
                pass


def check_smbv1(host, port, timeout):
    try:
        c = SMBConnection(remoteName=host, remoteHost=host, sess_port=port,
                          preferredDialect=SMB_DIALECT, timeout=timeout)
        c.close()
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------------------
# Orchestration per host
# ----------------------------------------------------------------------------------
def assess_host(host, args):
    res = HostResult(host)

    if LOCKOUT_EVENT.is_set():
        res.add("Auth", "Lockout guard", "WARN", "Skipped - account lockout detected earlier (--stop-on-lockout).")
        res.verdict = "SKIPPED - halted by lockout guard."
        res.verdict_status = "WARN"
        return res

    lmhash = nthash = ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":") if ":" in args.hashes else ("", args.hashes)

    ports = [(135, "RPC/WMI"), (139, "NetBIOS"), (445, "SMB")]
    open_ports = check_ports(res, host, ports, args.timeout)
    res.reachable445 = bool(open_ports.get(445))

    smb = None
    authed = is_admin = False
    if res.reachable445:
        smb, authed, is_admin = check_smb_and_auth(res, host, args, lmhash, nthash)
        res.smbv1 = check_smbv1(host, args.port, args.timeout)
        res.add("SMB", "SMBv1 enabled", "WARN" if res.smbv1 else "PASS",
                "SMBv1 negotiated successfully." if res.smbv1 else "SMBv1 appears disabled.",
                "SMBv1 is deprecated/insecure - note as a finding (not required for scanning)." if res.smbv1 else "")

    res.authenticated = authed
    res.is_admin = is_admin

    os_info = wmi_result = None
    if authed and smb is not None:
        check_admin_shares(res, smb)
        res.remotereg = check_remote_registry(res, smb, host, args.port)
        if args.probe_remoteregistry and is_admin:
            probe_remote_registry_start(res, smb, host, args.port, args.timeout)
        os_info = detect_os_via_registry(smb, host, args.port)

        wmi_result = detect_os_via_wmi(host, args, lmhash, nthash)
        res.wmi_ok = bool(wmi_result and wmi_result.get("_wmi_ok"))
        if res.wmi_ok:
            res.add("WMI", "WMI over DCOM (root/cimv2)", "PASS", "DCOM/WMI login succeeded - WMI-based plugins will work.")
        else:
            err = (wmi_result or {}).get("_error", "unknown")
            res.add("WMI", "WMI over DCOM (root/cimv2)", "WARN", f"WMI/DCOM login failed: {err}",
                    "Often a firewall blocking dynamic RPC ports (or DCOM disabled). WMI plugins will fail.")

    # ---- OS / CIS resolution ----
    build = display = caption = edition = None
    is_server = False
    source = None
    if os_info and os_info.get("CurrentBuild"):
        build = os_info["CurrentBuild"]; display = os_info.get("DisplayVersion")
        caption = os_info.get("ProductName"); edition = os_info.get("EditionID")
        is_server = (str(os_info.get("InstallationType", "")).lower() == "server")
        source = "remote registry"
    elif wmi_result and wmi_result.get("BuildNumber"):
        build = wmi_result["BuildNumber"]; caption = wmi_result.get("Caption")
        is_server = (str(wmi_result.get("ProductType")) in ("2", "3"))
        source = "WMI"
    elif smb is not None:
        try:
            b = smb.getServerOSBuild()
            if b:
                build = b; osstr = (smb.getServerOS() or "")
                is_server = "server" in osstr.lower(); caption = osstr or None
                source = "SMB negotiate (server/client may be ambiguous)"
        except Exception:
            pass

    if build:
        cis = map_cis(build, is_server, display)
        ubr = os_info.get("UBR") if os_info else None
        full_build = f"{build}.{ubr}" if ubr else f"{build}"
        res.os = {"caption": caption, "build": full_build, "edition": edition,
                  "displayVersion": display, "isServer": is_server, "source": source}
        res.cis = cis
        res.add("OS", "Detected OS", "INFO", f"{caption or cis['os']}  (build {full_build}) [via {source}]")
        res.add("CIS", "Recommended Benchmark", "INFO", cis["benchmark"])
    else:
        res.add("OS", "Detected OS", "WARN", "Could not determine OS build remotely.",
                "Supply valid admin credentials to enable registry/WMI OS detection.")

    # ---- Verdict ----
    if not res.reachable445:
        res.verdict_status, res.verdict = "FAIL", "NOT REACHABLE - SMB/445 is closed or filtered."
    elif args.user is None:
        res.verdict_status, res.verdict = "INFO", "RECON ONLY - no credentials supplied; auth/admin checks not performed."
    elif not authed:
        res.verdict_status, res.verdict = "FAIL", "AUTH FAILED - supplied credentials did not authenticate."
    elif not is_admin:
        res.verdict_status, res.verdict = "FAIL", "NO ADMIN - authenticated but the account is not a local administrator."
    else:
        if res.counts()["WARN"]:
            res.verdict_status, res.verdict = "WARN", "READY WITH CAVEATS - auth + admin OK; review WARN items (registry/WMI/firewall)."
        else:
            res.verdict_status, res.verdict = "PASS", "READY - target should scan cleanly with these credentials."

    if smb is not None:
        try:
            smb.close()
        except Exception:
            pass
    return res


# ----------------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------------
print_lock = threading.Lock()


def print_host(res):
    with print_lock:
        print()
        print(C.s("=" * 74, C.MAGENTA))
        print(C.s(f"  TARGET: {res.host}", C.BOLD + C.WHITE))
        print(C.s("=" * 74, C.MAGENTA))
        for cat, chk, st, detail, reco in res.checks:
            print(f"  {C.s(f'[{st}]', status_colour(st))} {chk:<32} {C.s(detail, C.GREY)}")
            if reco and st in ("WARN", "FAIL"):
                print(C.s(f"        -> {reco}", C.YELLOW))
        print()
        print(f"  VERDICT: {C.s(res.verdict, status_colour(res.verdict_status))}")
        if res.cis:
            print(C.s(f"  CIS: {res.cis['benchmark']}", C.CYAN))


def _flag(value, true_text="yes", false_text="no", none_text="-"):
    if value is None:
        return none_text
    return true_text if value else false_text


def print_summary_table(results):
    print()
    print(C.s("=" * 100, C.MAGENTA))
    print(C.s("  SUMMARY", C.BOLD + C.WHITE))
    print(C.s("=" * 100, C.MAGENTA))
    header = f"  {'HOST':<18} {'VERDICT':<8} {'OS':<26} {'ADMIN':<6} {'REG':<10} {'WMI':<5} CIS"
    print(C.s(header, C.GREY))
    print(C.s("  " + "-" * 96, C.GREY))
    for r in results:
        verdict_word = {"PASS": "READY", "WARN": "CAVEAT", "FAIL": "FAIL", "INFO": "RECON"}.get(r.verdict_status, "?")
        os_txt = (r.os.get("caption") or (r.cis.get("os") if r.cis else "") or "-")[:25]
        cis_txt = (r.cis.get("benchmark") if r.cis else "-") or "-"
        cis_txt = cis_txt.replace("CIS Microsoft Windows ", "").replace(" Benchmark", "")[:34]
        reg_txt = r.remotereg or "-"
        line = (f"  {r.host:<18} "
                f"{C.s(f'{verdict_word:<8}', status_colour(r.verdict_status))} "
                f"{os_txt:<26} {_flag(r.is_admin):<6} {reg_txt:<10} {_flag(r.wmi_ok):<5} {cis_txt}")
        print(line)


def print_cis_rollup(results):
    needed = Counter(r.cis["benchmark"] for r in results if r.cis and r.cis.get("benchmark"))
    if not needed:
        return
    print()
    print(C.s("  CIS BENCHMARKS NEEDED ACROSS ESTATE", C.BOLD + C.CYAN))
    for bench, n in needed.most_common():
        print(C.s(f"    {n:>3}x  {bench}", C.CYAN))
    print(C.s("    (download the latest revision of each from workbench.cisecurity.org)", C.GREY))


def build_json(results, args):
    return {
        "tool": "nessus_remote_check",
        "version": TOOL_VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "scanner_account": args.user,
        "cis_rollup": dict(Counter(r.cis["benchmark"] for r in results if r.cis and r.cis.get("benchmark"))),
        "hosts": [
            {
                "host": r.host, "verdict": r.verdict, "verdictStatus": r.verdict_status,
                "reachable445": r.reachable445, "authenticated": r.authenticated, "isAdmin": r.is_admin,
                "remoteRegistry": r.remotereg, "wmi": r.wmi_ok, "smbv1": r.smbv1, "signingRequired": r.signing,
                "os": r.os, "cis": r.cis, "counts": r.counts(),
                "checks": [{"category": c, "check": k, "status": s, "detail": d, "recommendation": rc}
                           for (c, k, s, d, rc) in r.checks],
            }
            for r in results
        ],
    }


def write_csv(results, path):
    fields = ["host", "verdict_status", "verdict", "os_caption", "build", "is_server",
              "cis_benchmark", "reachable_445", "authenticated", "is_admin",
              "remote_registry", "wmi", "smbv1", "signing_required"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "host": r.host, "verdict_status": r.verdict_status, "verdict": r.verdict,
                "os_caption": (r.os.get("caption") if r.os else "") or (r.cis.get("os") if r.cis else ""),
                "build": r.os.get("build") if r.os else "",
                "is_server": r.os.get("isServer") if r.os else "",
                "cis_benchmark": r.cis.get("benchmark") if r.cis else "",
                "reachable_445": r.reachable445, "authenticated": r.authenticated, "is_admin": r.is_admin,
                "remote_registry": r.remotereg, "wmi": r.wmi_ok, "smbv1": r.smbv1, "signing_required": r.signing,
            })


def build_html(results, args):
    badge = {"PASS": "#15803d", "WARN": "#b45309", "FAIL": "#b91c1c", "INFO": "#1d4ed8"}
    rollup = Counter(r.cis["benchmark"] for r in results if r.cis and r.cis.get("benchmark"))
    rollup_html = "".join(f"<li>{n}x &nbsp;{escape(b)}</li>" for b, n in rollup.most_common())

    sum_rows = []
    for r in results:
        vw = {"PASS": "READY", "WARN": "CAVEAT", "FAIL": "FAIL", "INFO": "RECON"}.get(r.verdict_status, "?")
        os_txt = (r.os.get("caption") if r.os else "") or (r.cis.get("os") if r.cis else "") or "-"
        sum_rows.append(
            f"<tr><td>{escape(r.host)}</td>"
            f"<td><span class='badge' style='background:{badge.get(r.verdict_status)}'>{vw}</span></td>"
            f"<td>{escape(str(os_txt))}</td><td>{_flag(r.is_admin)}</td>"
            f"<td>{escape(str(r.remotereg or '-'))}</td><td>{_flag(r.wmi_ok)}</td>"
            f"<td>{escape(r.cis.get('benchmark') if r.cis else '-')}</td></tr>")

    blocks = []
    for r in results:
        rows = []
        for cat, chk, st, detail, reco in r.checks:
            reco_html = f"<div class='reco'>{escape(reco)}</div>" if reco else ""
            rows.append(f"<tr><td class='cat'>{escape(cat)}</td><td>{escape(chk)}</td>"
                        f"<td><span class='badge' style='background:{badge.get(st)}'>{st}</span></td>"
                        f"<td>{escape(detail)}{reco_html}</td></tr>")
        cis = escape(r.cis['benchmark']) if r.cis else "n/a"
        blocks.append(
            f"<div class='host'><h2>{escape(r.host)}</h2>"
            f"<div class='verdict' style='border-color:{badge.get(r.verdict_status)}'>"
            f"<strong>{escape(r.verdict)}</strong><br><span class='cis'>CIS: {cis}</span></div>"
            f"<table><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")

    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Nessus Remote Readiness</title><style>
body{{background:#0b0f17;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:32px;}}
h1{{font-size:20px;margin:0 0 4px;}} .sub{{color:#94a3b8;font-size:13px;margin-bottom:24px;}}
h2{{font-size:16px;color:#cbd5e1;border-bottom:1px solid #1f2937;padding-bottom:6px;}}
.host{{margin-bottom:36px;}} .panel{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px 20px;margin-bottom:24px;}}
.panel ul{{margin:8px 0 0;padding-left:18px;}} .panel li{{color:#7dd3fc;font-size:13px;margin:2px 0;}}
.verdict{{background:#111827;border-left:4px solid #555;border-radius:8px;padding:12px 16px;margin:12px 0;}}
.cis{{color:#7dd3fc;font-size:13px;}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px;}}
th{{text-align:left;color:#94a3b8;border-bottom:1px solid #1f2937;padding:8px;}}
td{{border-bottom:1px solid #161e2e;padding:8px;vertical-align:top;}} td.cat{{color:#64748b;width:90px;}}
.badge{{padding:2px 9px;border-radius:6px;color:#fff;font-size:11px;font-weight:700;letter-spacing:.5px;}}
.reco{{color:#facc15;font-size:12px;margin-top:4px;}}
</style></head><body>
<h1>Nessus Windows Credentialed Scan - Remote Readiness Report</h1>
<div class='sub'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; scanner account: {escape(str(args.user))} &nbsp;|&nbsp; v{TOOL_VERSION}</div>
<div class='panel'><strong>Summary ({len(results)} host(s))</strong>
<table><thead><tr><th>Host</th><th>Verdict</th><th>OS</th><th>Admin</th><th>Reg</th><th>WMI</th><th>CIS Benchmark</th></tr></thead>
<tbody>{''.join(sum_rows)}</tbody></table></div>
<div class='panel'><strong>CIS benchmarks needed across estate</strong><ul>{rollup_html or '<li>None determined</li>'}</ul></div>
{''.join(blocks)}
</body></html>"""


# ----------------------------------------------------------------------------------
# Target parsing
# ----------------------------------------------------------------------------------
def parse_targets(args):
    targets = []
    if args.target_file:
        with open(args.target_file) as f:
            targets += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if args.target:
        targets += [p.strip() for p in args.target.split(",")]

    expanded = []
    for t in targets:
        if "/" in t:
            try:
                expanded += [str(ip) for ip in ipaddress.ip_network(t, strict=False).hosts()]
                continue
            except ValueError:
                pass
        expanded.append(t)
    seen = set()
    return [x for x in expanded if not (x in seen or seen.add(x))]


# ----------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Remote readiness checker for Nessus Windows credentialed scans.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-t", "--target", help="IP, hostname, comma-list, or CIDR (e.g. 192.168.1.0/24)")
    ap.add_argument("-iL", "--target-file", help="File with one target per line")
    ap.add_argument("-u", "--user", help="Username (omit for recon-only mode)")
    ap.add_argument("-p", "--password", default="", help="Password")
    ap.add_argument("-d", "--domain", default="", help="Domain (omit / '.' for local accounts)")
    ap.add_argument("-H", "--hashes", help="NTLM hash for pass-the-hash, as LM:NT or just NT")
    ap.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    ap.add_argument("--no-pass", action="store_true", help="No password - use Kerberos ccache (KRB5CCNAME)")
    ap.add_argument("--aes-key", help="AES key (hex) for Kerberos auth")
    ap.add_argument("--dc-ip", help="Domain Controller / KDC IP (for Kerberos)")
    ap.add_argument("--local-auth", action="store_true", help="Treat the account as a local (non-domain) account")
    ap.add_argument("--probe-remoteregistry", action="store_true",
                    help="OPT-IN: start RemoteRegistry, confirm winreg, then restore state (modifies target transiently)")
    ap.add_argument("--stop-on-lockout", action="store_true", help="Halt remaining hosts if an account lockout is detected")
    ap.add_argument("--port", type=int, default=445, help="SMB port (default 445)")
    ap.add_argument("--timeout", type=int, default=5, help="Per-connection timeout seconds (default 5)")
    ap.add_argument("--threads", type=int, default=10, help="Concurrent hosts (default 10)")
    ap.add_argument("--json", dest="json_out", help="Write JSON report to this path")
    ap.add_argument("--html", dest="html_out", help="Write HTML report to this path")
    ap.add_argument("--csv", dest="csv_out", help="Write CSV summary to this path")
    ap.add_argument("-o", "--output-prefix", help="Write <prefix>_<timestamp>.{json,html,csv} reports")
    ap.add_argument("--no-color", action="store_true", help="Disable coloured output")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.enabled = False
    if args.local_auth and not args.domain:
        args.domain = ""  # explicit local SAM auth

    if not args.target and not args.target_file:
        ap.error("Provide at least one target with -t/--target or -iL/--target-file")
    targets = parse_targets(args)
    if not targets:
        ap.error("No valid targets parsed.")

    print(C.s(f"\n  nessus_remote_check v{TOOL_VERSION}  |  {len(targets)} target(s)  |  "
              f"{'recon-only' if not args.user else 'account: ' + args.user}"
              f"{'  |  Kerberos' if args.kerberos else ''}"
              f"{'  |  RemoteReg probe ON' if args.probe_remoteregistry else ''}", C.CYAN))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(assess_host, host, args): host for host in targets}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = HostResult(host)
                res.add("Error", "Assessment", "FAIL", f"Unhandled error: {e}")
                res.verdict, res.verdict_status = f"ERROR - {e}", "FAIL"
            results.append(res)
            print_host(res)

    order = {h: i for i, h in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.host, 1e9))

    if len(results) > 1:
        print_summary_table(results)
    print_cis_rollup(results)

    ready = sum(1 for r in results if r.verdict_status == "PASS")
    caveat = sum(1 for r in results if r.verdict_status == "WARN")
    notok = sum(1 for r in results if r.verdict_status == "FAIL")
    print()
    print(C.s("=" * 74, C.MAGENTA))
    print(C.s(f"  OVERALL: {ready} ready   {caveat} ready-with-caveats   {notok} not-ready "
              f"(of {len(results)})", C.BOLD + C.WHITE))
    print(C.s("=" * 74, C.MAGENTA))
    if LOCKOUT_EVENT.is_set():
        print(C.s("  [!] Account lockout was detected - some hosts were skipped.", C.RED))

    # Report outputs
    json_out, html_out, csv_out = args.json_out, args.html_out, args.csv_out
    if args.output_prefix:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{args.output_prefix}_{ts}"
        json_out = json_out or f"{base}.json"
        html_out = html_out or f"{base}.html"
        csv_out = csv_out or f"{base}.csv"

    if json_out:
        with open(json_out, "w") as f:
            json.dump(build_json(results, args), f, indent=2, default=str)
        print(C.s(f"  JSON report: {json_out}", C.GREY))
    if html_out:
        with open(html_out, "w") as f:
            f.write(build_html(results, args))
        print(C.s(f"  HTML report: {html_out}", C.GREY))
    if csv_out:
        write_csv(results, csv_out)
        print(C.s(f"  CSV report : {csv_out}", C.GREY))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Interrupted.\n")
        sys.exit(130)
