#!/usr/bin/env python3
"""
check_pkey_membership.py — Read-only UFM REST API check of a node's pkey membership.

Verifies whether a node's HCA ports are members of a given pkey, and reports
Index-0 and full/limited membership per port. Intended as pre-change (SOP Step 3
checkpoint) and post-change verification evidence for JIRA — it performs GET
requests only and never modifies UFM state.

Usage:
    ./check_pkey_membership.py <hostname> <pkey> [options]

Examples:
    ./check_pkey_membership.py research-b300-inference-015 0x678
    ./check_pkey_membership.py research-b300-inference-015 0x8678   # membership bit auto-stripped
    UFM_HOST=ufm-vip.example.com UFM_USER=admin UFM_PASS=... \
        ./check_pkey_membership.py research-b300-inference-031 0x678 --json

Environment variables (can also be passed as flags):
    UFM_HOST   UFM VIP hostname/IP (required unless --host given)
    UFM_USER   UFM username (default: admin)
    UFM_PASS   UFM password
    UFM_TOKEN  UFM API token (used instead of user/pass if set)

Exit codes:
    0  all of the node's HCA ports are members of the pkey
    1  node found, but some/all ports are NOT members
    2  usage / connection / lookup error
"""

import argparse
import json
import os
import ssl
import sys
import base64
import urllib.request
import urllib.error

MEMBERSHIP_BIT = 0x8000


def normalize_pkey(raw: str) -> str:
    """Return the 15-bit pkey as 0x-prefixed lowercase hex, stripping the
    full-membership bit (0x8000) if present — e.g. 0x8678 -> 0x678."""
    try:
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 16)
    except ValueError:
        sys.exit(f"error: '{raw}' is not a valid hex pkey (e.g. 0x678)")
    if value & MEMBERSHIP_BIT:
        stripped = value & ~MEMBERSHIP_BIT
        print(f"note: {raw} includes the full-membership bit (0x8000); "
              f"querying partition key 0x{stripped:x}", file=sys.stderr)
        value = stripped
    if not 0 < value <= 0x7FFF:
        sys.exit(f"error: pkey 0x{value:x} out of range (0x1–0x7fff)")
    return f"0x{value:x}"


class UfmClient:
    def __init__(self, host: str, user: str, password: str, token: str,
                 verify_tls: bool, timeout: int = 30):
        self.base = f"https://{host}/ufmRest"
        self.timeout = timeout
        self.headers = {"Accept": "application/json"}
        if token:
            self.base = f"https://{host}/ufmRestV3"
            self.headers["Authorization"] = f"Basic {base64.b64encode(f'{token}:'.encode()).decode()}"
        elif user and password:
            cred = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {cred}"
        else:
            sys.exit("error: provide UFM_TOKEN or UFM_USER/UFM_PASS (or --user/--password)")
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path: str):
        url = f"{self.base}{path}"
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            sys.exit(f"error: UFM API {e.code} on GET {path}: {e.read().decode()[:300]}")
        except urllib.error.URLError as e:
            sys.exit(f"error: cannot reach UFM at {url}: {e.reason}")


def find_system(client: UfmClient, hostname: str):
    """Locate the system by (case-insensitive) name match; return its record."""
    systems = client.get("/resources/systems")
    wanted = hostname.lower()
    exact = [s for s in systems
             if s.get("system_name", "").lower() == wanted
             or s.get("name", "").lower() == wanted]
    if exact:
        return exact[0]
    partial = [s for s in systems
               if wanted in s.get("system_name", "").lower()
               or wanted in s.get("name", "").lower()]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        names = ", ".join(sorted(s.get("system_name") or s.get("name", "?") for s in partial))
        sys.exit(f"error: hostname '{hostname}' matches multiple systems: {names}")
    sys.exit(f"error: no system named '{hostname}' found in this UFM instance "
             f"(check you are on the correct fabric/UFM VIP)")


def get_system_ports(client: UfmClient, system_guid: str):
    """Return the system's HCA port records (guid, port number, state)."""
    ports = client.get(f"/resources/ports?system={system_guid}")
    return [p for p in ports if p.get("guid")]


def _norm_guid(guid: str) -> str:
    return str(guid).lower().replace("0x", "").lstrip("0") or "0"


def get_pkey_members(client: UfmClient, pkey: str, debug: bool = False):
    """Return {guid: {index0, membership}} for the pkey's member GUIDs.

    Handles the response shapes seen across UFM versions:
      A) wrapped:      {"0x678": {"guids": [...], ...}}
      B) zero-padded:  {"0x0678": {"guids": [...], ...}}
      C) flat:         {"guids": [...], "partition": "api_pkey_0x678", ...}
    """
    data = client.get(f"/resources/pkeys/{pkey}?guids_data=true")
    if debug:
        print("DEBUG raw pkey response:\n" + json.dumps(data, indent=2)[:4000],
              file=sys.stderr)

    entry = None
    if isinstance(data, dict):
        if isinstance(data.get("guids"), list):            # shape C (flat)
            entry = data
        else:                                              # shapes A/B (wrapped)
            want = int(pkey, 16)
            for k, v in data.items():
                try:
                    if int(str(k), 16) == want and isinstance(v, dict):
                        entry = v
                        break
                except ValueError:
                    continue
    elif isinstance(data, list):                           # some builds return a list
        want = int(pkey, 16)
        for v in data:
            try:
                if int(str(v.get("pkey", v.get("partition", "-1"))).split("_")[-1], 16) == want:
                    entry = v
                    break
            except (ValueError, AttributeError):
                continue
    entry = entry or {}

    members = {}
    for g in entry.get("guids", []):
        guid = g.get("guid") or g.get("port_guid") or ""
        if not guid:
            continue
        membership = g.get("membership", g.get("member", "?"))
        members[_norm_guid(guid)] = {
            "index0": bool(g.get("index0", g.get("index_0", False))),
            "membership": str(membership).lower(),
        }
    return members, entry


def main():
    ap = argparse.ArgumentParser(description="Read-only UFM pkey membership check for a node")
    ap.add_argument("hostname", help="node hostname as known to UFM (e.g. research-b300-inference-015)")
    ap.add_argument("pkey", help="pkey in hex, with or without membership bit (0x678 or 0x8678)")
    ap.add_argument("--host", default=os.environ.get("UFM_HOST"), help="UFM VIP (or set UFM_HOST)")
    ap.add_argument("--user", default=os.environ.get("UFM_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("UFM_PASS"))
    ap.add_argument("--token", default=os.environ.get("UFM_TOKEN"), help="API token (uses ufmRestV3)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed UFM certs)")
    ap.add_argument("--expect-ports", type=int, default=8,
                    help="expected HCA port count for the node (default: 8)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--debug", action="store_true",
                    help="dump raw UFM API responses to stderr")
    args = ap.parse_args()

    if not args.host:
        sys.exit("error: UFM host not set (use --host or UFM_HOST)")

    pkey = normalize_pkey(args.pkey)
    client = UfmClient(args.host, args.user, args.password, args.token,
                       verify_tls=not args.insecure)

    system = find_system(client, args.hostname)
    sys_name = system.get("system_name") or system.get("name")
    sys_guid = system.get("guid") or system.get("system_guid")

    ports = get_system_ports(client, sys_guid)
    members, pkey_entry = get_pkey_members(client, pkey, debug=args.debug)

    if not members:
        print(f"WARNING: pkey {pkey} returned 0 member GUIDs — either the partition "
              f"is empty or this UFM version uses an unrecognised response shape. "
              f"Re-run with --debug to inspect the raw payload.", file=sys.stderr)

    rows, member_count, index0_count = [], 0, 0
    for p in sorted(ports, key=lambda x: str(x.get("num", x.get("port_num", x.get("number", ""))))):
        m = members.get(_norm_guid(p["guid"]))
        is_member = m is not None
        member_count += is_member
        index0_count += bool(m and m["index0"])
        rows.append({
            "port_guid": p["guid"],
            "port_num": p.get("num", p.get("port_num", p.get("number", p.get("external_number")))),
            "state": p.get("logical_state", p.get("state", "?")),
            "member": is_member,
            "index0": m["index0"] if m else None,
            "membership": m["membership"] if m else None,
        })

    result = {
        "ufm_host": args.host,
        "system": sys_name,
        "system_guid": sys_guid,
        "pkey": pkey,
        "pkey_total_member_guids": len(members),
        "pkey_ip_over_ib": pkey_entry.get("ip_over_ib"),
        "node_ports_found": len(rows),
        "node_ports_expected": args.expect_ports,
        "node_ports_in_pkey": member_count,
        "node_ports_index0": index0_count,
        "all_ports_member": bool(rows) and member_count == len(rows),
        "ports": rows,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nUFM:    {args.host}")
        print(f"Node:   {sys_name}  (guid {sys_guid})")
        print(f"Pkey:   {pkey}  ({len(members)} member GUIDs total in partition)\n")
        print(f"{'Port GUID':<22}{'Port':<6}{'State':<10}{'Member':<8}{'Index-0':<9}Membership")
        print("-" * 68)
        for r in rows:
            print(f"{r['port_guid']:<22}{str(r['port_num']):<6}{str(r['state']):<10}"
                  f"{'YES' if r['member'] else 'NO':<8}"
                  f"{('YES' if r['index0'] else 'no') if r['member'] else '-':<9}"
                  f"{r['membership'] or '-'}")
        print("-" * 68)
        print(f"Summary: {member_count}/{len(rows)} ports in {pkey}, "
              f"{index0_count} flagged Index-0 "
              f"(expected {args.expect_ports} ports on node)")
        if len(rows) != args.expect_ports:
            print(f"WARNING: found {len(rows)} ports, expected {args.expect_ports} — "
                  f"verify node HCA inventory before proceeding.")

    if not rows:
        sys.exit(2)
    sys.exit(0 if member_count == len(rows) else 1)


if __name__ == "__main__":
    main()
