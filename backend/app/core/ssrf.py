"""SSRF protection for user-supplied LLM endpoints.

Defences: scheme allow-list, no userinfo, host/suffix deny-list, port deny-list, DNS resolution validation of
EVERY returned address (covers decimal/octal/hex obfuscation, IPv4-mapped/6to4/Teredo IPv6), cloud-metadata blocking,
DNS-rebinding protection by connecting to the validated IP literal (single resolution, TLS verified against the
original hostname via SNI), no redirects, no env proxies, bounded response size.
"""
import asyncio, ipaddress, socket
from dataclasses import dataclass
from urllib.parse import urlsplit
import httpx


class SSRFError(ValueError):
    pass


BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata", "instance-data", "kubernetes.default.svc"}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".cluster.local", ".intranet", ".corp")
BLOCKED_PORTS = {22, 23, 25, 110, 135, 139, 143, 445, 465, 587, 993, 995, 1433, 1521, 2375, 2376, 3306, 3389,
                 5432, 5984, 6379, 9200, 9300, 11211, 27017}
ALWAYS_BLOCKED_IPS = {ipaddress.ip_address(x) for x in (
    "169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "192.0.0.192")}


def _unwrap(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip.teredo:
            return ip.teredo[1]
    return ip


def check_ip(ip, *, allow_private: bool) -> None:
    ip = _unwrap(ip)
    if ip in ALWAYS_BLOCKED_IPS or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise SSRFError(f"address {ip} is not allowed")
    if allow_private:
        return
    if not ip.is_global:
        raise SSRFError(f"address {ip} is private or reserved")


@dataclass(frozen=True)
class SafeTarget:
    scheme: str
    host: str
    port: int
    path_query: str
    ips: tuple[str, ...]


async def resolve_and_validate(url: str, *, allow_private: bool = False, allow_http: bool = False) -> SafeTarget:
    if not isinstance(url, str) or len(url) > 2048 or any(c in url for c in "\r\n\t "):
        raise SSRFError("invalid URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise SSRFError("invalid URL") from e
    if parts.scheme not in ("https", "http"):
        raise SSRFError("only http(s) URLs are allowed")
    if parts.scheme == "http" and not allow_http:
        raise SSRFError("plain http is not allowed")
    if "@" in parts.netloc or parts.username or parts.password:
        raise SSRFError("credentials in URL are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise SSRFError("missing host")
    try:
        host = host.encode("idna").decode()
    except UnicodeError as e:
        raise SSRFError("invalid host") from e
    port = port or (443 if parts.scheme == "https" else 80)
    if port in BLOCKED_PORTS:
        raise SSRFError(f"port {port} is not allowed")
    if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
        if not (allow_private and host == "localhost"):
            raise SSRFError("host is not allowed")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFError("host cannot be resolved") from e
    ips: list[str] = []
    for _fam, _t, _p, _c, sa in infos:
        ip = ipaddress.ip_address(sa[0].split("%")[0])
        check_ip(ip, allow_private=allow_private)  # every address must be acceptable
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise SSRFError("host cannot be resolved")
    pq = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return SafeTarget(parts.scheme, host, port, pq, tuple(ips))


@dataclass
class SafeResponse:
    status: int
    headers: dict
    content: bytes

    def json(self):
        import json
        return json.loads(self.content.decode("utf-8", "replace"))

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")


async def safe_request(method: str, url: str, *, headers: dict | None = None, json=None, timeout: float = 30.0,
                       max_bytes: int = 2_000_000, allow_private: bool = False, allow_http: bool = False,
                       transport: httpx.AsyncBaseTransport | None = None) -> SafeResponse:
    t = await resolve_and_validate(url, allow_private=allow_private, allow_http=allow_http)
    ip = t.ips[0]
    lit = f"[{ip}]" if ":" in ip else ip
    default_port = 443 if t.scheme == "https" else 80
    hosthdr = t.host if t.port == default_port else f"{t.host}:{t.port}"
    h = {k: v for k, v in (headers or {}).items() if k.lower() not in ("host", "content-length")}
    h["Host"] = hosthdr
    ext = {"sni_hostname": t.host} if t.scheme == "https" else {}
    pinned = f"{t.scheme}://{lit}:{t.port}{t.path_query}"
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False, transport=transport) as c:
        async with c.stream(method, pinned, headers=h, json=json, extensions=ext) as r:
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise SSRFError("response too large")
            if 300 <= r.status_code < 400:
                raise SSRFError("redirects are not followed")
            return SafeResponse(r.status_code, dict(r.headers), bytes(buf))
