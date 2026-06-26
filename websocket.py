#!/usr/bin/env python3
"""
Cowrie/OpenCanary JSON WebSocket bridge with optional IP reputation enrichment.

- Tails Cowrie JSON logs.
- Tails OpenCanary JSON logs.
- Normalizes OpenCanary events into Cowrie-like events for browser compatibility.
- Detects the VPS public IPv4 address, avoiding Tailscale/private addresses.
- Optionally enriches source IPs with Spamhaus DROP, AbuseIPDB, and VirusTotal.
- Broadcasts events over a local WebSocket on 127.0.0.1:8765.
"""

import asyncio
import json
import os
import ipaddress
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import websockets


# ---------------------------------------------------------------------------
# Basic configuration
# ---------------------------------------------------------------------------

WS_HOST = os.getenv("WS_HOST", "127.0.0.1")
WS_PORT = int(os.getenv("WS_PORT", "8765"))

COWRIE_LOG = os.getenv(
    "COWRIE_LOG",
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
)

OPENCANARY_LOGS = [
    p.strip()
    for p in os.getenv(
        "OPENCANARY_LOGS",
        "/var/tmp/opencanary.log,/var/log/opencanary/opencanary.log",
    ).split(",")
    if p.strip()
]

clients = set()


# ---------------------------------------------------------------------------
# IP helpers / public sensor IP detection
# ---------------------------------------------------------------------------

def run_cmd(cmd: List[str]) -> str:
    return subprocess.check_output(
        cmd,
        text=True,
        timeout=3,
        stderr=subprocess.DEVNULL,
    ).strip()


def is_bad_sensor_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except Exception:
        return True

    tailscale_range = ipaddress.ip_network("100.64.0.0/10")

    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_private
        or ip in tailscale_range
    )


def is_public_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except Exception:
        return False

    tailscale_range = ipaddress.ip_network("100.64.0.0/10")

    return not (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_private
        or ip in tailscale_range
    )


def detect_primary_public_ipv4() -> str:
    """
    Try to detect the primary public IPv4 address.

    Priority:
    1. IPv4 on the non-Tailscale default route interface.
    2. Source IP used to reach 1.1.1.1.
    3. External check using api.ipify.org.
    """
    try:
        public_if = run_cmd([
            "bash",
            "-lc",
            "ip -4 route show default | awk '$0 !~ /tailscale0/ {print $5; exit}'",
        ])

        if public_if:
            candidate = run_cmd([
                "bash",
                "-lc",
                (
                    f"ip -4 addr show dev {public_if} scope global "
                    "| awk '/inet / {print $2}' "
                    "| cut -d/ -f1 "
                    "| head -n1"
                ),
            ])

            if candidate and not is_bad_sensor_ip(candidate):
                return candidate
    except Exception:
        pass

    try:
        candidate = run_cmd([
            "bash",
            "-lc",
            (
                "ip -4 route get 1.1.1.1 "
                "| awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1); exit}'"
            ),
        ])

        if candidate and not is_bad_sensor_ip(candidate):
            return candidate
    except Exception:
        pass

    try:
        candidate = run_cmd([
            "curl",
            "-4fsS",
            "--max-time",
            "3",
            "https://api.ipify.org",
        ])

        if candidate:
            return candidate
    except Exception:
        pass

    return ""


SERVER_PUBLIC_IP = detect_primary_public_ipv4()
print(f"Detected server public IPv4: {SERVER_PUBLIC_IP}", flush=True)


# ---------------------------------------------------------------------------
# Reputation enrichment
# ---------------------------------------------------------------------------

def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in ("1", "true", "yes", "on")


ENABLE_SPAMHAUS = env_bool("ENABLE_SPAMHAUS", False)
ENABLE_ABUSEIPDB = env_bool("ENABLE_ABUSEIPDB", False)
ENABLE_VIRUSTOTAL = env_bool("ENABLE_VIRUSTOTAL", False)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

SPAMHAUS_DROP_URL = os.getenv(
    "SPAMHAUS_DROP_URL",
    "https://www.spamhaus.org/drop/drop.json",
).strip()

REPUTATION_CACHE_TTL = int(os.getenv("REPUTATION_CACHE_TTL_HOURS", "24")) * 3600

_rep_cache: Dict[str, Dict[str, Any]] = {}
_spamhaus_networks: Optional[List[ipaddress._BaseNetwork]] = None
_spamhaus_loaded_at = 0.0


print(
    "Reputation providers: "
    f"spamhaus={ENABLE_SPAMHAUS} "
    f"abuseipdb={ENABLE_ABUSEIPDB and bool(ABUSEIPDB_API_KEY)} "
    f"virustotal={ENABLE_VIRUSTOTAL and bool(VIRUSTOTAL_API_KEY)}",
    flush=True,
)


def http_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 8) -> Any:
    request = urllib.request.Request(
        url,
        headers=headers or {},
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return json.loads(body)


def parse_http_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""

        if body:
            return f"HTTP {exc.code}: {body[:200]}"

        return f"HTTP {exc.code}"

    return str(exc)


def load_spamhaus_drop() -> List[ipaddress._BaseNetwork]:
    global _spamhaus_networks
    global _spamhaus_loaded_at

    now = time.time()

    if _spamhaus_networks is not None and now - _spamhaus_loaded_at < 86400:
        return _spamhaus_networks

    networks: List[ipaddress._BaseNetwork] = []

    try:
        request = urllib.request.Request(
            SPAMHAUS_DROP_URL,
            headers={"User-Agent": "honeypot-bridge/1.0"},
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8", errors="replace")

        try:
            data = json.loads(raw)

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = (
                    data.get("data")
                    or data.get("drop")
                    or data.get("networks")
                    or data.get("items")
                    or []
                )
            else:
                items = []

            for item in items:
                cidr = None

                if isinstance(item, str):
                    cidr = item
                elif isinstance(item, dict):
                    cidr = (
                        item.get("cidr")
                        or item.get("iprange")
                        or item.get("netblock")
                        or item.get("range")
                        or item.get("prefix")
                    )

                if cidr:
                    try:
                        networks.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
                    except Exception:
                        pass

        except Exception:
            for line in raw.splitlines():
                line = line.strip()

                if not line or line.startswith(";") or line.startswith("#"):
                    continue

                cidr = line.split(";")[0].strip()

                try:
                    networks.append(ipaddress.ip_network(cidr, strict=False))
                except Exception:
                    pass

        _spamhaus_networks = networks
        _spamhaus_loaded_at = now

        print(f"Loaded Spamhaus DROP networks: {len(networks)}", flush=True)

    except Exception as exc:
        print(f"Spamhaus load failed: {parse_http_error(exc)}", flush=True)
        _spamhaus_networks = []

    return _spamhaus_networks


def check_spamhaus(ip_str: str) -> Dict[str, Any]:
    if not ENABLE_SPAMHAUS:
        return {
            "enabled": False,
            "listed": False,
        }

    try:
        ip = ipaddress.ip_address(ip_str)
        networks = load_spamhaus_drop()
        listed = any(ip in net for net in networks)

        return {
            "enabled": True,
            "listed": listed,
        }

    except Exception as exc:
        return {
            "enabled": True,
            "listed": False,
            "error": parse_http_error(exc),
        }


def check_abuseipdb(ip_str: str) -> Dict[str, Any]:
    if not ENABLE_ABUSEIPDB or not ABUSEIPDB_API_KEY:
        return {
            "enabled": False,
            "score": None,
        }

    try:
        params = urllib.parse.urlencode({
            "ipAddress": ip_str,
            "maxAgeInDays": "90",
        })

        data = http_json(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
                "User-Agent": "honeypot-bridge/1.0",
            },
        )

        d = data.get("data", {}) if isinstance(data, dict) else {}

        return {
            "enabled": True,
            "score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "is_tor": d.get("isTor"),
            "country": d.get("countryCode"),
        }

    except Exception as exc:
        return {
            "enabled": True,
            "score": None,
            "error": parse_http_error(exc),
        }


def check_virustotal(ip_str: str) -> Dict[str, Any]:
    if not ENABLE_VIRUSTOTAL or not VIRUSTOTAL_API_KEY:
        return {
            "enabled": False,
            "malicious": None,
            "suspicious": None,
        }

    try:
        safe_ip = urllib.parse.quote(ip_str, safe="")

        data = http_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{safe_ip}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Accept": "application/json",
                "User-Agent": "honeypot-bridge/1.0",
            },
        )

        attrs = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) or {}

        return {
            "enabled": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
        }

    except Exception as exc:
        return {
            "enabled": True,
            "malicious": None,
            "suspicious": None,
            "error": parse_http_error(exc),
        }


def build_reputation(ip_str: str) -> Dict[str, Any]:
    now = time.time()
    cached = _rep_cache.get(ip_str)

    if cached and now - cached["time"] < REPUTATION_CACHE_TTL:
        return cached["reputation"]

    spamhaus = check_spamhaus(ip_str)
    abuseipdb = check_abuseipdb(ip_str)
    virustotal = check_virustotal(ip_str)

    score = 0

    if spamhaus.get("listed"):
        score = max(score, 100)

    abuse_score = abuseipdb.get("score")
    if isinstance(abuse_score, int):
        score = max(score, abuse_score)

    vt_malicious = virustotal.get("malicious")
    if isinstance(vt_malicious, int):
        if vt_malicious >= 5:
            score = max(score, 80)
        elif vt_malicious >= 1:
            score = max(score, 50)

    malicious = score >= 70

    rep = {
        "score": score,
        "malicious": malicious,
        "spamhaus": spamhaus,
        "abuseipdb": abuseipdb,
        "virustotal": virustotal,
    }

    _rep_cache[ip_str] = {
        "time": now,
        "reputation": rep,
    }

    print(
        f"REP {ip_str} score={score} "
        f"spamhaus={spamhaus.get('listed')} "
        f"abuseipdb={abuseipdb.get('score')} "
        f"vt_malicious={virustotal.get('malicious')}",
        flush=True,
    )

    return rep


async def enrich_event(event: Dict[str, Any]) -> Dict[str, Any]:
    src_ip = (
        event.get("src_ip")
        or event.get("src_host")
        or event.get("srcIp")
        or event.get("source_ip")
    )

    if not src_ip or not is_public_ip(src_ip):
        return event

    rep = await asyncio.to_thread(build_reputation, str(src_ip))

    event["reputation"] = rep

    # Flat fields for attack-map/browser compatibility.
    event["rep_score"] = rep.get("score")
    event["threat_score"] = rep.get("score")

    score = rep.get("score") or 0
    event["threat_level"] = (
        "critical" if score >= 90 else
        "high" if score >= 70 else
        "medium" if score >= 40 else
        "low"
    )

    event["spamhaus_listed"] = rep.get("spamhaus", {}).get("listed")
    event["abuseipdb_score"] = rep.get("abuseipdb", {}).get("score")
    event["abuseipdb_total_reports"] = rep.get("abuseipdb", {}).get("total_reports")
    event["vt_malicious"] = rep.get("virustotal", {}).get("malicious")
    event["vt_suspicious"] = rep.get("virustotal", {}).get("suspicious")

    return event


# ---------------------------------------------------------------------------
# Event normalization
# ---------------------------------------------------------------------------

def first_present(obj: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = obj.get(key)
        if value not in (None, ""):
            return value

    return None


def parse_port(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None

        return int(value)
    except Exception:
        return None


def service_from_port(port: Optional[int]) -> str:
    mapping = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5000: "vnc",
        5900: "vnc",
        6379: "redis",
        9418: "git",
    }

    if port in mapping:
        return mapping[port]

    if port is None:
        return "unknown"

    return f"tcp/{port}"


def extract_from_logdata(logdata: Any, names: Iterable[str]) -> Any:
    if not isinstance(logdata, dict):
        return None

    lowered = {
        str(k).lower(): v
        for k, v in logdata.items()
    }

    for name in names:
        value = lowered.get(name.lower())

        if value not in (None, ""):
            return value

    return None


def normalize_opencanary(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src_ip = first_present(event, [
        "src_ip",
        "src_host",
        "source_ip",
        "source_host",
        "remote_host",
    ])

    dst_ip = first_present(event, [
        "dst_ip",
        "dst_host",
        "dest_ip",
        "destination_ip",
        "local_host",
    ])

    dst_port = parse_port(first_present(event, [
        "dst_port",
        "local_port",
        "port",
    ]))

    logdata = event.get("logdata")
    username = extract_from_logdata(logdata, [
        "username",
        "user",
        "login",
        "account",
    ])

    password = extract_from_logdata(logdata, [
        "password",
        "pass",
    ])

    protocol = (
        first_present(event, ["protocol", "service"])
        or service_from_port(dst_port)
    )

    timestamp = first_present(event, [
        "timestamp",
        "local_time_adjusted",
        "local_time",
        "utc_time",
        "time",
    ])

    if SERVER_PUBLIC_IP and (not dst_ip or is_bad_sensor_ip(dst_ip)):
        dst_ip = SERVER_PUBLIC_IP

    eventid = "cowrie.session.connect"

    if username is not None or password is not None:
        eventid = "cowrie.login.failed"

    normalized: Dict[str, Any] = {
        "eventid": eventid,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_host": src_ip,
        "dst_ip": dst_ip or "?",
        "dst_host": dst_ip or "?",
        "dst_port": dst_port,
        "protocol": protocol,
        "source": "opencanary",
        "sensor": "opencanary",
        "sensor_public_ip": SERVER_PUBLIC_IP,
        "server_public_ip": SERVER_PUBLIC_IP,
        "opencanary_logtype": event.get("logtype"),
        "opencanary_original": event,
    }

    if username is not None:
        normalized["username"] = username

    if password is not None:
        normalized["password"] = password

    return normalized


# ---------------------------------------------------------------------------
# WebSocket handling
# ---------------------------------------------------------------------------

async def ws_handler(websocket, path=None):
    clients.add(websocket)

    try:
        await websocket.wait_closed()
    finally:
        clients.discard(websocket)


async def broadcast(message: str) -> None:
    if not clients:
        return

    dead = []

    for websocket in list(clients):
        try:
            await websocket.send(message)
        except Exception:
            dead.append(websocket)

    for websocket in dead:
        clients.discard(websocket)


# ---------------------------------------------------------------------------
# Log processing
# ---------------------------------------------------------------------------

async def process_line(source: str, line: str) -> None:
    line = line.strip()

    if not line:
        return

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return

    if not isinstance(event, dict):
        print(
            f"Skipping non-object JSON from {source}: {type(event).__name__}",
            flush=True,
        )
        return

    try:
        if source == "cowrie":
            event["source"] = "cowrie"
            event["sensor"] = "cowrie"
            event["sensor_public_ip"] = SERVER_PUBLIC_IP
            event["server_public_ip"] = SERVER_PUBLIC_IP

            current_dst = (
                event.get("dst_ip")
                or event.get("dst_host")
                or event.get("dstIp")
                or event.get("dest_ip")
            )

            if SERVER_PUBLIC_IP and (
                not current_dst or is_bad_sensor_ip(current_dst)
            ):
                event["dst_ip"] = SERVER_PUBLIC_IP
                event["dst_host"] = SERVER_PUBLIC_IP

            event = await enrich_event(event)

            await broadcast(json.dumps(event, separators=(",", ":")))
            return

        if source == "opencanary":
            normalized = normalize_opencanary(event)

            if normalized:
                normalized = await enrich_event(normalized)
                await broadcast(json.dumps(normalized, separators=(",", ":")))

            return

    except Exception as exc:
        print(f"Failed processing {source} event: {exc}", flush=True)


async def wait_for_file(paths: List[str]) -> str:
    while True:
        for path in paths:
            if Path(path).exists():
                return path

        print(f"Waiting for log file: {', '.join(paths)}", flush=True)
        await asyncio.sleep(5)


async def tail_log(path: str, source: str) -> None:
    while True:
        try:
            print(f"Tailing {source}: {path}", flush=True)

            with open(path, "r", encoding="utf-8", errors="replace") as file:
                file.seek(0, os.SEEK_END)
                inode = os.fstat(file.fileno()).st_ino

                while True:
                    line = file.readline()

                    if line:
                        await process_line(source, line)
                        continue

                    await asyncio.sleep(0.5)

                    try:
                        stat_result = os.stat(path)

                        if stat_result.st_ino != inode:
                            print(f"Reopening rotated log: {path}", flush=True)
                            break

                        if stat_result.st_size < file.tell():
                            print(f"Reopening truncated log: {path}", flush=True)
                            break

                    except FileNotFoundError:
                        print(f"Log disappeared, waiting: {path}", flush=True)
                        break

        except Exception as exc:
            print(f"Error reading {path}: {exc}", flush=True)

        await asyncio.sleep(5)


async def tail_first_available(paths: List[str], source: str) -> None:
    while True:
        path = await wait_for_file(paths)
        await tail_log(path, source)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    server = await websockets.serve(ws_handler, WS_HOST, WS_PORT)

    print(
        f"Honeypot WebSocket bridge listening on {WS_HOST}:{WS_PORT}",
        flush=True,
    )

    tasks = [
        asyncio.create_task(tail_first_available([COWRIE_LOG], "cowrie")),
        asyncio.create_task(tail_first_available(OPENCANARY_LOGS, "opencanary")),
    ]

    try:
        await asyncio.Future()
    finally:
        for task in tasks:
            task.cancel()

        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())