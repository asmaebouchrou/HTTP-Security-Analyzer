"""Analizador educativo de cabeceras HTTP; no sustituye una auditoría."""

import argparse
import http.client
import ipaddress
import queue
import re
import socket
import ssl
import threading
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit


TIMEOUT = 5
MAX_REDIRECTS = 5
HEADERS = (
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "Referrer-Policy",
)


class AnalyzerError(Exception):
    """Error que se puede mostrar al usuario sin una traza interna."""


def validate_url(url):
    """Exige una URL explícita y evita credenciales y caracteres de control."""
    if not isinstance(url, str) or not url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise AnalyzerError("URL vacía o con espacios/caracteres de control.")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
        host = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if port not in (80, 443) or "\\" in url or "%" in host:
            raise ValueError()
        authority = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            authority += f":{port}"
        normalized = urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
        normalized.encode("ascii")
        return normalized, host, port
    except (ValueError, UnicodeError):
        raise AnalyzerError("URL incorrecta: usa http:// o https://, sin credenciales, con puerto 80 o 443.") from None


def public_ip(address):
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def resolve_public(host, port, timeout=TIMEOUT):
    """Limita la espera DNS y rechaza respuestas mixtas públicas/privadas."""
    results = queue.Queue()

    def resolve():
        try:
            results.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as exc:
            results.put(exc)

    threading.Thread(target=resolve, daemon=True).start()
    try:
        answers = results.get(timeout=timeout)
    except queue.Empty:
        raise AnalyzerError("Se agotó el tiempo de resolución DNS.") from None
    if isinstance(answers, Exception):
        raise AnalyzerError("No se pudo resolver el nombre del servidor.")
    addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    if not addresses or not all(public_ip(address) for address in addresses):
        raise AnalyzerError("Destino bloqueado: el DNS contiene direcciones locales, internas o no públicas.")
    return addresses


class PinnedConnection(http.client.HTTPConnection):
    """Conecta a la IP comprobada, conservando Host y verificación TLS."""

    def __init__(self, host, port, address, secure, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = address
        self.secure = secure

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)
        if self.secure:
            try:
                self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
            except Exception:
                self.sock.close()
                raise


def request_headers(url, host, port, address, timeout):
    parsed = urlsplit(url)
    connection = PinnedConnection(host, port, address, parsed.scheme == "https", timeout)
    try:
        target = urlunsplit(("", "", parsed.path, parsed.query, ""))
        # GET sin leer el cuerpo: algunos servidores no implementan HEAD igual que GET.
        connection.request("GET", target, headers={"User-Agent": "HTTP-Security-Analyzer/1.0", "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.getheaders()
    finally:
        connection.close()


def fetch_headers(url, timeout=TIMEOUT, max_redirects=MAX_REDIRECTS):
    seen = set()
    for step in range(max_redirects + 1):
        url, host, port = validate_url(url)
        if url in seen:
            raise AnalyzerError("Se ha detectado un bucle de redirecciones.")
        seen.add(url)
        addresses = resolve_public(host, port, timeout)
        try:
            status, pairs = request_headers(url, host, port, addresses[0], timeout)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise AnalyzerError(f"Error de conexión, TLS o respuesta HTTP: {exc}") from None
        headers = {}
        for name, value in pairs:
            headers.setdefault(name.lower(), []).append(value)
        if status in (301, 302, 303, 307, 308):
            locations = headers.get("location", [])
            if len(locations) != 1 or not locations[0]:
                raise AnalyzerError("Redirección sin una cabecera Location única y válida.")
            if any(ord(c) <= 32 or ord(c) == 127 for c in locations[0]):
                raise AnalyzerError("Location contiene espacios o caracteres de control.")
            if step == max_redirects:
                raise AnalyzerError("Se ha superado el límite de redirecciones.")
            destination = urljoin(url, locations[0])
            destination, _, _ = validate_url(destination)
            if urlsplit(url).scheme == "https" and urlsplit(destination).scheme != "https":
                raise AnalyzerError("Redirección bloqueada: degradación de HTTPS a HTTP.")
            url = destination
            continue
        return url, status, headers
    raise AnalyzerError("Se ha superado el límite de redirecciones.")


@dataclass
class Finding:
    name: str
    state: str
    value: str
    recommendation: str
    points: int


def review_value(name, value, https):
    """Reglas orientativas conservadoras, no un parser completo de políticas."""
    lower = value.lower().strip()
    if name == "Content-Security-Policy":
        directives = [part.strip().split() for part in lower.split(";") if part.strip()]
        defaults = [parts[1:] for parts in directives if parts[0] == "default-src"]
        if not defaults or not defaults[0] or any(token in lower for token in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:")):
            return "Define default-src y revisa comodines, data:, unsafe-inline y unsafe-eval. Adapta la política a la aplicación."
    elif name == "Strict-Transport-Security":
        ages = re.findall(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)", lower)
        age = ages[0].lstrip("0") if len(ages) == 1 else ""
        sufficient = len(age) > 8 or (len(age) == 8 and age >= "31536000")
        if not https or not sufficient:
            return "Sirve por HTTPS y configura max-age de al menos 31536000; valora includeSubDomains solo si todos los subdominios usan HTTPS."
    elif name == "X-Content-Type-Options":
        if lower != "nosniff":
            return "Configura el valor exacto nosniff."
    elif name == "Referrer-Policy":
        if lower not in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"):
            return "Valora no-referrer o strict-origin-when-cross-origin según las necesidades de la aplicación."
    return ""


def analyze_headers(headers, https=True):
    normalized = {name.lower(): ([value] if isinstance(value, str) else value) for name, value in headers.items()}
    findings = []
    for name in HEADERS:
        values = normalized.get(name.lower(), [])
        if not values:
            findings.append(Finding(name, "AUSENTE", "", f"Configura {name} en el servidor; comprueba su compatibilidad con tu aplicación.", 0))
            continue
        value = ", ".join(values)
        recommendation = "Revisa las cabeceras duplicadas y define una política inequívoca." if len(values) != 1 else review_value(name, value, https)
        findings.append(Finding(name, "REVISAR" if recommendation else "PRESENTE", value,
                                recommendation or "Supera las comprobaciones básicas; verifica su adecuación a la aplicación.", 10 if recommendation else 25))
    return findings, sum(item.points for item in findings)


def safe_text(value):
    # Impide que contenido del servidor introduzca secuencias de control en la terminal.
    return "".join(c if c.isprintable() else "?" for c in str(value))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Análisis educativo de cuatro cabeceras HTTP de seguridad.")
    parser.add_argument("url", nargs="?", help="URL pública con http:// o https://")
    args = parser.parse_args(argv)
    try:
        url = args.url if args.url is not None else input("URL que deseas analizar: ").strip()
        final_url, status, headers = fetch_headers(url)
        findings, score = analyze_headers(headers, urlsplit(final_url).scheme == "https")
        print(f"URL final: {safe_text(final_url)}\nEstado HTTP: {status}")
        if status >= 400:
            print("Aviso: se están analizando las cabeceras de una respuesta de error.")
        if urlsplit(final_url).scheme != "https":
            print("Aviso: la conexión HTTP no está cifrada. Configura HTTPS.")
        for finding in findings:
            print(f"\n{finding.name}: {finding.state}")
            if finding.value:
                print(f"  Valor: {safe_text(finding.value)}")
            print(f"  Recomendación: {finding.recommendation}")
        print(f"\nPuntuación orientativa: {score}/100. No equivale a Mozilla Observatory.")
        return 0
    except (AnalyzerError, EOFError, KeyboardInterrupt) as exc:
        print(f"Error: {safe_text(exc) or 'Operación cancelada.'}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
