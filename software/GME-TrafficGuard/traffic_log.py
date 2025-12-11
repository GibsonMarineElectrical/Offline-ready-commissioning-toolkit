#!/usr/bin/env python3
import csv
import argparse
from collections import Counter

def analyze(csv_path: str, local_ip: str, top_n: int = 10) -> None:
    inbound = Counter()        # remote_ip -> bytes received by local_ip
    outbound = Counter()       # remote_ip -> bytes sent by local_ip
    proto_in = Counter()       # protocol -> bytes in
    proto_out = Counter()      # protocol -> bytes out
    total_in = 0
    total_out = 0

    with open(csv_path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)

        # Basic sanity check
        required = {"Source", "Destination", "Length"}
        if reader.fieldnames is None:
            raise SystemExit("Could not read CSV header – check the file.")
        missing = required - set(reader.fieldnames)
        if missing:
            raise SystemExit(
                f"CSV is missing required columns: {', '.join(sorted(missing))}"
            )

        for row in reader:
            src = row["Source"].strip()
            dst = row["Destination"].strip()
            proto = row.get("Protocol", "").strip()

            try:
                length = int(row["Length"])
            except (TypeError, ValueError):
                continue  # skip malformed rows

            # Outbound: local_ip is Source
            if src == local_ip and dst != local_ip:
                outbound[dst] += length
                total_out += length
                if proto:
                    proto_out[proto] += length

            # Inbound: local_ip is Destination
            elif dst == local_ip and src != local_ip:
                inbound[src] += length
                total_in += length
                if proto:
                    proto_in[proto] += length

    # Combined totals per remote IP
    combined = Counter()
    for ip, b in inbound.items():
        combined[ip] += b
    for ip, b in outbound.items():
        combined[ip] += b

    print(f"\nLocal IP under analysis: {local_ip}")
    print(f"Total outbound (sent):    {total_out} bytes")
    print(f"Total inbound (received): {total_in} bytes\n")

    def print_table(title: str, counter: Counter, label: str) -> None:
        print(title)
        print("-" * len(title))
        if not counter:
            print("  (no matching traffic)\n")
            return
        print(f"{'Rank':>4}  {'Remote IP':<18}  {'Bytes ' + label:>14}")
        for i, (ip, bytes_) in enumerate(counter.most_common(top_n), start=1):
            print(f"{i:>4}  {ip:<18}  {bytes_:>14}")
        print()

    print_table(
        f"Top {top_n} outbound peers (data sent from {local_ip})",
        outbound,
        "sent"
    )
    print_table(
        f"Top {top_n} inbound peers (data received by {local_ip})",
        inbound,
        "received"
    )

    print(f"Top {top_n} peers by total traffic (in + out)")
    print("-" * 44)
    if combined:
        print(f"{'Rank':>4}  {'Remote IP':<18}  {'Bytes total':>14}  {'In':>10}  {'Out':>10}")
        for i, (ip, total) in enumerate(combined.most_common(top_n), start=1):
            print(f"{i:>4}  {ip:<18}  {total:>14}  {inbound[ip]:>10}  {outbound[ip]:>10}")
    else:
        print("  (no matching traffic)")
    print()

    if proto_in or proto_out:
        print(f"Top {top_n} protocols by bytes (inbound)")
        print("-" * 44)
        if proto_in:
            for i, (proto, bytes_) in enumerate(proto_in.most_common(top_n), start=1):
                print(f"{i:>4}  {proto:<15} {bytes_:>14}")
        else:
            print("  (no inbound protocols)")
        print()

        print(f"Top {top_n} protocols by bytes (outbound)")
        print("-" * 45)
        if proto_out:
            for i, (proto, bytes_) in enumerate(proto_out.most_common(top_n), start=1):
                print(f"{i:>4}  {proto:<15} {bytes_:>14}")
        else:
            print("  (no outbound protocols)")
        print()

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a Wireshark CSV to find top bandwidth consumers for a given local IP."
    )
    parser.add_argument("csv_path", help="Path to Wireshark CSV export (File → Export Packet Dissections → CSV)")
    parser.add_argument("local_ip", help="Local IP address to analyze (e.g. 192.168.1.175)")
    parser.add_argument(
        "-n", "--top",
        type=int,
        default=10,
        help="Number of top entries to display (default: 10)"
    )
    args = parser.parse_args()
    analyze(args.csv_path, args.local_ip, args.top)

if __name__ == "__main__":
    main()
