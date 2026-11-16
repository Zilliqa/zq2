#!/usr/bin/env python3
"""Verify the gZIL correction against saved RPC evidence; --live repeats the RPC reads."""

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct
import urllib.request


ROOT = Path(__file__).resolve().parent
TOKEN = "0xa845c1034cd077bd8d32be0447239c7e4be6cb21"
ORIGINAL_SHA256 = "447a2ce01b39d5e539de383835ef9c2514bf3cd9920ae771c235efaa389c9719"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_list(path):
    raw = path.read_bytes()
    regions, count = struct.unpack_from("<IQ", raw)
    offset = 12 + 28 * regions
    require(len(raw) == offset + count * 36, f"Invalid length: {path}")
    sources = []
    for i in range(regions):
        start = 12 + 28 * i
        first = struct.unpack_from("<Q", raw, start)[0]
        sources.append((first, "0x" + raw[start + 8:start + 28].hex()))
    require(sources and sources[0][0] == 0, "Missing first region")
    balances = {}
    region = 0
    for i in range(count):
        while region + 1 < regions and sources[region + 1][0] <= i:
            region += 1
        start = offset + i * 36
        user = "0x" + raw[start:start + 20].hex()
        key = (sources[region][1], user)
        require(key not in balances, f"Duplicate entry: {key}")
        balances[key] = int.from_bytes(raw[start + 20:start + 36], "little")
    return balances


def decode_event(log):
    raw = bytes.fromhex(log["data"][2:])
    offset = int.from_bytes(raw[:32], "big")
    size = int.from_bytes(raw[offset:offset + 32], "big")
    return json.loads(raw[offset + 32:offset + 32 + size])


def verify(live=False):
    evidence = json.loads((ROOT / "gzil_corrections_002.evidence.json").read_text())
    queries = evidence["queries"] + evidence["receipt_queries"]
    if live:
        for row in queries:
            request = urllib.request.Request(
                evidence["endpoint"], data=json.dumps(row["request"]).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                row["response"] = json.load(response)
    for row in queries:
        require("result" in row["response"], f"RPC failure: {row}")

    original_path = ROOT / "escrow_lodge_001.bin"
    require(hashlib.sha256(original_path.read_bytes()).hexdigest() == ORIGINAL_SHA256,
            "Shipped migration file changed")
    original = read_list(original_path)
    deltas = collections.Counter()
    transfers = 0
    for row in evidence["receipt_queries"]:
        receipt = row["response"]["result"]
        require(receipt["transactionHash"] == row["request"]["params"][0], "Wrong receipt")
        require(evidence["snapshot_block"] < int(receipt["blockNumber"], 16)
                < evidence["interop_disabled_at"], "Transfer outside correction window")
        for log in receipt["logs"]:
            if log["address"].lower() != TOKEN:
                continue
            require(receipt["status"] == "0x1" and not log["removed"], "Invalid transfer receipt")
            event = decode_event(log)
            if event["_eventname"] == "IncreasedAllowance":
                continue
            require(event["_eventname"] in ("TransferSuccess", "TransferFromSuccess"),
                    f"Unexpected gZIL event: {event}")
            params = {p["vname"]: p["value"] for p in event["params"]}
            amount = int(params["amount"])
            deltas[params["sender"]] -= amount
            deltas[params["recipient"]] += amount
            transfers += 1
    require(sum(deltas.values()) == 0, "Transfer deltas change total supply")
    expected = {(TOKEN, user): original.get((TOKEN, user), 0) + delta
                for user, delta in deltas.items() if delta}
    correction = read_list(ROOT / "escrow_lodge_002.bin")
    require(correction == expected, "Binary differs from transfer reconstruction")
    with (ROOT / "gzil_corrections_002.csv").open() as f:
        rows = list(csv.DictReader(f))
    csv_entries = {(TOKEN, row["address"]): int(row["amount"]) for row in rows}
    require(len(csv_entries) == len(rows) and csv_entries == expected,
            "CSV differs from transfer reconstruction")

    verified = set()
    escrow_verified = set()
    whitelist_verified = False
    supply_verified = False
    for row in evidence["queries"]:
        method, params = row["request"]["method"], row["request"]["params"]
        result = row["response"]["result"]
        if method == "GetSmartContractSubState" and params[1] == "balances":
            user = params[2][0]
            actual = int(result.get("balances", {}).get(user, "0"))
            require(actual == original.get((TOKEN, user), 0) + deltas[user],
                    f"Scilla state differs from transfers: {user}")
            verified.add(user)
        elif method == "eth_call":
            data = params[0]["data"]
            if data.startswith("0xf7888aec"):  # balanceOf(address,address)
                user = "0x" + data[-40:]
                require(int(result, 16) == original.get((TOKEN, user), 0),
                        f"Escrow changed or already claimed: {user}")
                escrow_verified.add(user)
            elif data.startswith("0x3af32abf"):  # isWhitelisted(address)
                require(int(result, 16) == 0, "gZIL is already claimable; review before rollout")
                whitelist_verified = True
        elif method == "GetSmartContractSubState" and params[1] == "total_supply":
            total = sum(amount for (token, _), amount in original.items() if token == TOKEN)
            require(int(result["total_supply"]) == total, "gZIL supply mismatch")
            supply_verified = True
    require(verified == set(deltas), "Missing balance verification for transfer participants")
    require(escrow_verified == set(deltas), "Missing escrow verification for transfer participants")
    require(whitelist_verified and supply_verified, "Missing whitelist or total supply verification")
    require(len(expected) == 7 and transfers == 11, "Unexpected correction scope")
    print(f"Verified {len(expected)} corrections from {transfers} transfers; total supply unchanged.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Repeat reads against api.zilliqa.com")
    verify(parser.parse_args().live)
