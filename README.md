# Nessus Windows Credentialed Scan Readiness Toolkit

A two-part toolkit for confirming that a **Nessus authenticated (credentialed) scan** will succeed against Windows targets *before* you launch the scan — and for identifying the correct **CIS Benchmark** for each host.

Credentialed scans fail quietly for predictable reasons: the Server service is down, admin shares are missing, a non-builtin local admin is hit by UAC remote token filtering, Remote Registry is disabled, or a firewall is silently dropping WMI's dynamic RPC ports. These tools check exactly those things over the same channels Nessus uses (SMB, Remote Registry over RPC, WMI over DCOM), so you stop wasting scan windows on hosts that were never going to authenticate.

| Tool | Runs on | Perspective | Auth |
|------|---------|-------------|------|
| [`Test-NessusScanReadiness.ps1`](#1-test-nessusscanreadinessps1-host-side) | Windows target (elevated) | Host-side self-check | Local context |
| [`nessus_remote_check.py`](#2-nessus_remote_checkpy-scanner-side) | Linux / Kali | Remote, scanner-side | NTLM / hash / Kerberos |

Use the remote tool to sweep an estate from the scanner, and the host-side script when you have a shell on a box and want a definitive local readiness picture.

---

## Contents

- [Requirements](#requirements)
- [Tool 1: Test-NessusScanReadiness.ps1 (host-side)](#1-test-nessusscanreadinessps1-host-side)
- [Tool 2: nessus_remote_check.py (scanner-side)](#2-nessus_remote_checkpy-scanner-side)
- [CIS Benchmark mapping](#cis-benchmark-mapping)
- [Output formats](#output-formats)
- [Authorised use](#authorised-use)
- [License](#license)

---

## Requirements

**Host-side (PowerShell):**
- Windows PowerShell 5.1+ (built in on modern Windows)
- Run elevated (Administrator) for complete results

**Scanner-side (Python):**
- Python 3.8+
- [`impacket`](https://github.com/fortra/impacket)

```bash
# Kali / Debian
sudo apt install python3-impacket

# or in a virtualenv
pip install impacket
```

---

## 1. `Test-NessusScanReadiness.ps1` (host-side)

Run locally on a Windows target, as Administrator, to validate every prerequisite Nessus needs and report the matching CIS Benchmark.

### Usage

```powershell
# Basic readiness check
.\Test-NessusScanReadiness.ps1

# Tell it which account type Nessus will use, and export reports
.\Test-NessusScanReadiness.ps1 -ScanAccountType LocalAdmin -HtmlReport .\readiness.html -JsonReport .\readiness.json
```

If the script is blocked by execution policy, run it for the current process only:

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-NessusScanReadiness.ps1
```

### Parameters

| Parameter | Values | Purpose |
|-----------|--------|---------|
| `-ScanAccountType` | `Domain` (default), `BuiltinAdmin`, `LocalAdmin` | Drives the UAC token verdict — see note below |
| `-JsonReport` | path | Write machine-readable JSON results |
| `-HtmlReport` | path | Write a dark-themed HTML report |

### What it checks

- **Services** — Server (LanmanServer), WMI (Winmgmt), Workstation, Remote Registry, with start-type awareness (Disabled vs Manual vs Running)
- **Administrative shares** — ADMIN$, C$, IPC$ and the `AutoShareWks` / `AutoShareServer` policy
- **UAC remote token policy** — `LocalAccountTokenFilterPolicy` and `FilterAdministratorToken`
- **Windows Firewall** — profile state plus File & Printer Sharing (445/139) and WMI inbound rule groups
- **Listening ports** — 445 / 135 / 139 (with `netstat` fallback)
- **SMB configuration** — SMBv1/2/3 and signing requirements
- **WMI** — a live local CIM query to confirm the repository responds

> **UAC note:** `-ScanAccountType` matters. A non-builtin local admin account receives a *filtered* token over the network unless `LocalAccountTokenFilterPolicy = 1`. Domain accounts and the built-in Administrator are exempt. Set the account type so the verdict reflects reality.

---

## 2. `nessus_remote_check.py` (scanner-side)

Run from Kali against one or many targets. It exercises the real channels Nessus relies on and gives a per-host verdict, an estate summary table, and a CIS benchmark rollup.

### Usage

```bash
chmod +x nessus_remote_check.py

# Single host
./nessus_remote_check.py -t 192.168.1.50 -u svc_scan -p 'P@ssw0rd' -d CORP

# A whole subnet, threaded, write all three reports with a timestamped prefix
./nessus_remote_check.py -t 192.168.1.0/24 -u scanadmin -p 'Pass' --threads 20 -o run1

# Target list, pass-the-hash, with the lockout safety brake
./nessus_remote_check.py -iL targets.txt -u admin -H :e19ccf75ee54e06b06a5907af13cef42 --stop-on-lockout

# Kerberos via ccache
export KRB5CCNAME=admin.ccache
./nessus_remote_check.py -t dc01.corp.local -u admin -k --no-pass --dc-ip 192.168.1.10

# Prove Nessus's Remote Registry auto-start will work (opt-in, restores state)
./nessus_remote_check.py -t 192.168.1.50 -u admin -p 'Pass' --probe-remoteregistry

# Recon only (no creds): ports + OS-from-SMB + signing/SMBv1
./nessus_remote_check.py -t 192.168.1.50
```

### Key options

| Option | Purpose |
|--------|---------|
| `-t`, `--target` | IP, hostname, comma-list, or CIDR |
| `-iL`, `--target-file` | File with one target per line |
| `-u` / `-p` / `-d` | Username / password / domain |
| `-H`, `--hashes` | NTLM hash for pass-the-hash (`LM:NT` or `NT`) |
| `-k`, `--kerberos` | Kerberos auth (`--no-pass`, `--aes-key`, `--dc-ip`) |
| `--local-auth` | Treat the account as a local (non-domain) account |
| `--probe-remoteregistry` | **Opt-in:** start RemoteRegistry, confirm winreg, then restore state |
| `--stop-on-lockout` | Halt remaining hosts if an account lockout is detected |
| `--threads` | Concurrent hosts (default 10) |
| `--json` / `--html` / `--csv` | Write reports to explicit paths |
| `-o`, `--output-prefix` | Write `<prefix>_<timestamp>.{json,html,csv}` together |

### What it checks

- **Reachability** — TCP 135 / 139 / 445
- **SMB authentication** — real login (NTLM, hash, or Kerberos), with human-readable failure reasons (bad password, locked out, disabled, expired, no network-logon right, …)
- **Local admin rights** — ADMIN$ / C$ access (the `Pwn3d!` equivalent)
- **Administrative shares** — ADMIN$, C$, IPC$
- **Remote Registry** — `winreg` RPC bind, or service start-type via `svcctl` (Disabled = Nessus cannot start it; Manual/Stopped = it can, with admin)
- **Remote Registry live probe** (opt-in) — actually starts the service, confirms winreg, then restores the original state
- **WMI over DCOM** — root/cimv2 login (catches dynamic-RPC firewall blocks)
- **SMB signing / SMBv1** — informational and finding-worthy
- **OS detection → CIS** — authoritative via remote registry, fallback WMI, fallback SMB build

### Per-host verdicts

`READY` · `READY WITH CAVEATS` · `AUTH FAILED` · `NO ADMIN` · `NOT REACHABLE` · `RECON ONLY`

> **Note:** `--probe-remoteregistry` is the only feature that modifies the target (it starts, then stops, the RemoteRegistry service). It is self-restoring and opt-in; on unstable links there is a small chance the service is left running. Keep it off for production estates unless you specifically want that proof.

---

## CIS Benchmark mapping

Both tools resolve the host build number, feature update, and server/client role, then map to the correct CIS Benchmark family — for example:

| Build | Role | Benchmark |
|-------|------|-----------|
| 20348 | Server | CIS Microsoft Windows Server 2022 Benchmark |
| 17763 | Server | CIS Microsoft Windows Server 2019 Benchmark |
| 14393 | Server | CIS Microsoft Windows Server 2016 Benchmark |
| 26100 | Server | CIS Microsoft Windows Server 2025 Benchmark |
| 19045 | Client | CIS Microsoft Windows 10 Enterprise Benchmark (22H2) |
| ≥22000 | Client | CIS Microsoft Windows 11 Enterprise Benchmark |

Builds like `17763` and `26100` are shared between server and client editions, so remote detection prefers the registry (`InstallationType`) or WMI (`ProductType`) for an authoritative role before falling back to the (ambiguous) SMB negotiate build. The remote tool also prints a **CIS rollup** across all scanned hosts so you know exactly which benchmarks to pull for an engagement.

Benchmark revisions change over time — always download the latest from [CIS WorkBench](https://workbench.cisecurity.org).

---

## Output formats

| Format | Host-side | Scanner-side | Notes |
|--------|-----------|--------------|-------|
| Console | yes | yes | Colour-coded PASS / WARN / FAIL / INFO |
| JSON | yes | yes | Structured results for import pipelines |
| HTML | yes | yes | Dark-themed report |
| CSV | — | yes | One row per host for quick triage |
| Summary table + CIS rollup | — | yes | Estate-wide overview |

---

## Authorised use

These tools are intended for authorised security testing, vulnerability-assessment preparation, and system administration only. Run them solely against systems you own or have explicit, written permission to test. You are responsible for ensuring your use complies with applicable laws and the scope of your engagement. The author accepts no liability for misuse or for any damage arising from use of this software.

---

## License

Released under the MIT License — see the `LICENSE` file. Adjust to suit your own preference before publishing.

---

## Author

**Dan** — [`Mr-Whiskerss`](https://github.com/Mr-Whiskerss)
Built for credentialed-scan preparation during security assessment work.

Issues and pull requests welcome.
