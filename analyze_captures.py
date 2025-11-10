#!/usr/bin/env python3
"""Análisis automatizado de capturas generadas por monitor_ports.sh.

Características principales:
- Recorre un directorio (por defecto ./capturas) y procesa archivos .log y .pcap.
- Calcula los top orígenes/destinos y flujos agregados a partir de los logs tcpdump.
- Estima volumen (bytes) utilizando la longitud reportada por tcpdump cuando está disponible.
- Identifica flujos potencialmente sospechosos (destinos públicos con alto volumen).
- Opcionalmente, invoca tshark/capinfos para obtener estadísticas avanzadas de los pcap.

Requisitos opcionales:
- tshark (wireshark-cli) y capinfos para secciones avanzadas. El script funciona sin ellos.
"""
from __future__ import annotations
import argparse
import ipaddress
import re
import socket
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ServiceMap = Dict[str, int]

# Puertos conocidos por nombre que suelen aparecer en tcpdump
KNOWN_SERVICE_PORTS: ServiceMap = {
    "https": 443,
    "http": 80,
    "domain": 53,
    "mdns": 5353,
    "ws-discovery": 3702,
    "bootpc": 68,
    "bootps": 67,
    "ntp": 123,
}

MULTICAST_PREFIXES = (
    ipaddress.ip_network("224.0.0.0/4"),  # IPv4 multicast
    ipaddress.ip_network("ff00::/8"),     # IPv6 multicast
)

PRIV_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
)

FLOW_RE = re.compile(
    r"(?P<src>[0-9a-fA-F:\.]+)\.(?P<src_port>[^ >]+)\s*>\s*(?P<dst>[0-9a-fA-F:\.]+)\.(?P<dst_port>[^: ]+)"
)
LENGTH_RE = re.compile(r"length\s+(?P<len>\d+)")
PROTO_RE = re.compile(r"\b(UDP|TCP|ICMP|ICMP6)\b", re.IGNORECASE)
TIMESTAMP_RE = re.compile(r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\.(?P<ms>\d+)")


@dataclass
class FlowStats:
    packets: int = 0
    bytes: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    protocols: Counter = None  # type: ignore

    def __post_init__(self) -> None:
        if self.protocols is None:
            self.protocols = Counter()

    def update(self, byte_count: int, timestamp: Optional[float], proto: str) -> None:
        self.packets += 1
        self.bytes += byte_count
        if timestamp is not None:
            if self.first_ts is None or timestamp < self.first_ts:
                self.first_ts = timestamp
            if self.last_ts is None or timestamp > self.last_ts:
                self.last_ts = timestamp
        if proto:
            self.protocols[proto.upper()] += 1

    @property
    def duration(self) -> Optional[float]:
        if self.first_ts is None or self.last_ts is None:
            return None
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class AnalysisResult:
    source_counts: Counter
    dest_counts: Counter
    flow_stats: Dict[Tuple[str, str, str], FlowStats]
    timeline: Dict[int, int]
    errors: List[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analiza logs/pcap generados por monitor_ports.sh y resalta tráfico sospechoso"
    )
    parser.add_argument(
        "--path",
        default="./capturas",
        help="Directorio raíz con logs y pcaps (por defecto ./capturas)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Número de elementos a mostrar en los rankings (por defecto 10)",
    )
    parser.add_argument(
        "--max-pcaps",
        type=int,
        default=1,
        help="Analizar a lo sumo N pcaps grandes con tshark/capinfos (por defecto 1)",
    )
    parser.add_argument(
        "--skip-pcap",
        action="store_true",
        help="No invocar herramientas externas (tshark/capinfos)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emitir un resumen en formato JSON además del texto",
    )
    parser.add_argument(
        "--suspect-threshold",
        type=float,
        default=5.0,
        help="MB mínimos para marcar un flujo a destino público como sospechoso (defecto 5 MB)",
    )
    return parser.parse_args()


def find_capture_files(base: Path) -> Tuple[List[Path], List[Path]]:
    logs, pcaps = [], []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".log", ".txt"}:
            logs.append(path)
        elif path.suffix.lower() in {".pcap", ".pcapng"}:
            pcaps.append(path)
    return logs, pcaps


def service_to_port(port_str: str) -> str:
    try:
        return str(int(port_str))
    except ValueError:
        normalized = port_str.lower()
        if normalized in KNOWN_SERVICE_PORTS:
            return str(KNOWN_SERVICE_PORTS[normalized])
        try:
            return str(socket.getservbyname(normalized))
        except OSError:
            return normalized


def parse_timestamp(line: str) -> Optional[float]:
    match = TIMESTAMP_RE.search(line)
    if not match:
        return None
    h = int(match.group("h"))
    m = int(match.group("m"))
    s = int(match.group("s"))
    ms = int(match.group("ms"))
    return h * 3600 + m * 60 + s + ms / (10 ** len(match.group("ms")))


def parse_logs(log_files: Iterable[Path]) -> AnalysisResult:
    source = Counter()
    dest = Counter()
    flows: Dict[Tuple[str, str, str], FlowStats] = {}
    timeline = defaultdict(int)
    errors: List[str] = []

    for logfile in log_files:
        try:
            content = logfile.read_text(errors="ignore")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"No se pudo leer {logfile}: {exc}")
            continue

        for line in content.splitlines():
            if ">" not in line:
                continue
            match = FLOW_RE.search(line)
            if not match:
                continue
            src_ip = match.group("src")
            dst_ip = match.group("dst")
            dst_port_raw = match.group("dst_port")
            dst_port = service_to_port(dst_port_raw)
            timestamp = parse_timestamp(line)
            if timestamp is not None:
                timeline[int(timestamp // 60)] += 1
            byte_match = LENGTH_RE.search(line)
            byte_count = int(byte_match.group("len")) if byte_match else 0
            proto_match = PROTO_RE.search(line)
            proto = proto_match.group(1).upper() if proto_match else ""

            try:
                ipaddress.ip_address(dst_ip)
            except ValueError:
                # tcpdump puede añadir sufijos como "Android-3.local" cuando resuelve nombres.
                # Intentamos limpiar mediante split por espacios si hubiese.
                dst_ip = dst_ip.split()[0]

            try:
                ipaddress.ip_address(src_ip)
            except ValueError:
                src_ip = src_ip.split()[0]

            key = (src_ip, dst_ip, dst_port)
            if key not in flows:
                flows[key] = FlowStats()
            flows[key].update(byte_count, timestamp, proto)
            source[src_ip] += 1
            dest[dst_ip] += 1

    return AnalysisResult(source, dest, flows, dict(timeline), errors)


def human_bytes(num_bytes: int) -> str:
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PB"


def is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        return addr.is_private
    for net in PRIV_NETS:
        if addr in net:
            return True
    return False


def is_multicast(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in MULTICAST_PREFIXES:
        if addr in net:
            return True
    return False


def summarize_logs(result: AnalysisResult, top_n: int, suspect_threshold_mb: float) -> Dict[str, List[Dict[str, object]]]:
    summary: Dict[str, List[Dict[str, object]]] = {"top_sources": [], "top_destinations": [], "flows": [], "suspects": []}

    for ip, count in result.source_counts.most_common(top_n):
        summary["top_sources"].append({"ip": ip, "packets": count})
    for ip, count in result.dest_counts.most_common(top_n):
        summary["top_destinations"].append({"ip": ip, "packets": count})

    flow_items = sorted(result.flow_stats.items(), key=lambda kv: kv[1].bytes, reverse=True)[:top_n]
    for (src, dst, port), stats in flow_items:
        summary["flows"].append(
            {
                "src": src,
                "dst": dst,
                "dst_port": port,
                "packets": stats.packets,
                "bytes": stats.bytes,
                "bytes_h": human_bytes(stats.bytes),
                "duration": stats.duration,
                "protocols": dict(stats.protocols),
            }
        )

    threshold_bytes = suspect_threshold_mb * 1024 * 1024
    for (src, dst, port), stats in result.flow_stats.items():
        if stats.bytes < threshold_bytes:
            continue
        if is_multicast(dst) or is_private(dst):
            continue
        summary["suspects"].append(
            {
                "src": src,
                "dst": dst,
                "dst_port": port,
                "bytes": stats.bytes,
                "bytes_h": human_bytes(stats.bytes),
                "packets": stats.packets,
                "protocols": dict(stats.protocols),
            }
        )

    summary["timeline"] = []
    if result.timeline:
        minutes = sorted(result.timeline.items())
        counts = [count for _, count in minutes]
        for minute, count in minutes:
            summary["timeline"].append({"minute": minute, "packets": count})
        summary["timeline_summary"] = {
            "total_minutes": len(minutes),
            "avg_packets": statistics.fmean(counts) if counts else 0.0,
            "max_packets": max(counts),
        }

    if result.errors:
        summary["errors"] = result.errors

    return summary


def run_command(cmd: List[str], timeout: int = 30) -> Optional[str]:
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip()
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as exc:
        return exc.stdout.strip() if exc.stdout else None
    except subprocess.TimeoutExpired:
        return "Tiempo de espera excedido"


def analyze_pcaps(pcaps: List[Path], max_pcaps: int) -> List[Dict[str, object]]:
    if not pcaps or not shutil_which("capinfos"):
        return []

    sorted_pcaps = sorted(pcaps, key=lambda p: p.stat().st_size, reverse=True)[:max_pcaps]
    results: List[Dict[str, object]] = []
    for pcap in sorted_pcaps:
        info_output = run_command(["capinfos", str(pcap)])
        conv_output = None
        proto_output = None
        if shutil_which("tshark"):
            conv_output = run_command(["tshark", "-r", str(pcap), "-q", "-z", "conv,ip"])
            proto_output = run_command(["tshark", "-r", str(pcap), "-q", "-z", "io,phs"])
        results.append({
            "pcap": str(pcap),
            "capinfos": info_output,
            "conversations": conv_output,
            "protocols": proto_output,
        })
    return results


def shutil_which(binary: str) -> bool:
    from shutil import which

    return which(binary) is not None


def print_text_report(summary: Dict[str, List[Dict[str, object]]], pcap_info: List[Dict[str, object]], top_n: int) -> None:
    print("\n=== TOP IP ORIGEN ===")
    for item in summary.get("top_sources", []):
        print(f"{item['ip']:>18}  {item['packets']} pkt")

    print("\n=== TOP IP DESTINO ===")
    for item in summary.get("top_destinations", []):
        print(f"{item['ip']:>18}  {item['packets']} pkt")

    print("\n=== FLOWS PRINCIPALES ===")
    for item in summary.get("flows", []):
        proto = ",".join(f"{k}:{v}" for k, v in item.get("protocols", {}).items())
        print(
            f"{item['src']} -> {item['dst']}:{item['dst_port']} | "
            f"{item['packets']} pkt | {item['bytes_h']} | protos {proto or 'N/A'}"
        )

    suspects = summary.get("suspects", [])
    print("\n=== SOSPECHOSOS (destino público) ===")
    if not suspects:
        print("(ninguno supera el umbral configurado)")
    else:
        for item in suspects:
            proto = ",".join(f"{k}:{v}" for k, v in item.get("protocols", {}).items())
            print(
                f"{item['src']} -> {item['dst']}:{item['dst_port']} | {item['packets']} pkt | "
                f"{item['bytes_h']} | protos {proto or 'N/A'}"
            )

    if summary.get("timeline"):
        print("\n=== DISTRIBUCIÓN TEMPORAL (por minuto) ===")
        t_summary = summary.get("timeline_summary", {})
        print(
            f"Minutos activos: {t_summary.get('total_minutes', 0)}, "
            f"promedio pkt/min: {t_summary.get('avg_packets', 0):.1f}, "
            f"pico pkt/min: {t_summary.get('max_packets', 0)}"
        )

    if summary.get("errors"):
        print("\n=== LOGS SIN PROCESAR ===")
        for err in summary["errors"]:
            print(f"  - {err}")

    if pcap_info:
        print("\n=== DETALLE PCAP (capinfos / tshark) ===")
        for entry in pcap_info:
            print(f"\nArchivo: {entry['pcap']}")
            if entry.get("capinfos"):
                print("-- capinfos --")
                print(entry["capinfos"])
            if entry.get("conversations"):
                print("-- tshark conv,ip --")
                print(entry["conversations"])
            if entry.get("protocols"):
                print("-- tshark io,phs --")
                print(entry["protocols"])


def emit_json(summary: Dict[str, List[Dict[str, object]]], pcap_info: List[Dict[str, object]]) -> None:
    import json

    payload = {"summary": summary, "pcaps": pcap_info}
    print("\n=== JSON ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main() -> int:
    args = parse_args()
    base = Path(args.path).expanduser().resolve()
    if not base.exists():
        print(f"El directorio {base} no existe", file=sys.stderr)
        return 1

    log_files, pcaps = find_capture_files(base)
    if not log_files and not pcaps:
        print(f"No se encontraron logs ni pcaps en {base}")
        return 0

    print(f"Analizando {len(log_files)} log(s) y {len(pcaps)} pcap(s) en {base}\n")

    analysis = parse_logs(log_files)
    summary = summarize_logs(analysis, args.top, args.suspect_threshold)

    pcap_info: List[Dict[str, object]] = []
    if not args.skip_pcap:
        pcap_info = analyze_pcaps(pcaps, args.max_pcaps)
    else:
        print("(Se omitió el análisis de pcaps por petición del usuario)")

    print_text_report(summary, pcap_info, args.top)
    if args.json:
        emit_json(summary, pcap_info)

    return 0


if __name__ == "__main__":
    sys.exit(main())
