#!/usr/bin/env python3
## ~omadjoudj

"""
check_index0_exclusivity.py — Read-only UFM check that a node's HCA ports hold
Index-0 membership in EXACTLY ONE pkey.

Scans all pkeys on the UFM instance, finds every partition each of the node's
ports belongs to, and verifies that across the whole node there is exactly one
pkey where the ports are flagged Index-0 (and that all ports agree on it).
Useful pre/post-change evidence: after moving a node to a new partition, this
confirms no stale Index-0 membership remains in the old pkey.

GET requests only — never modifies UFM state.

Usage:
    ./check_index0_exclusivity.py <hostname> [options]

Examples:
    ./check_index0_exclusivity.py research-b300-inference-015 --insecure
    UFM_HOST=10.166.0.208 UFM_USER=admin UFM_PASS=... \
        ./check_index0_exclusivity.py research-b300-inference-013 --insecure --json

Environment variables (can also be passed as flags):
    UFM_HOST   UFM VIP hostname/IP (required unless --host given)
    UFM_USER   UFM username (default: admin)
    UFM_PASS   UFM password
    UFM_TOKEN  UFM API token (used instead of user/pass if set)

Exit codes:
    0  node has Index-0 membership in exactly one pkey, consistent on all ports
    1  violation: zero, multiple, or inconsistent Index-0 memberships
    2  usage / connection / lookup error
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

MEMBERSHIP_BIT = 0x8000


def _norm_guid(guid: str) -> str:
    return str(guid).lower().replace("0x", "").lstrip("0") or "0"


def _norm_pkey(raw) -> str:
    """Normalize any pkey representation to 0x-prefixed 15-bit hex."""
    try:
        value = int(str(raw), 16)
    except ValueError:
        return str(raw)
    return f"0x{value & ~MEMBERSHIP_BIT:x}"


class UfmClient:
    def __init__(self, host, user, password, token, verify_tls, timeout=60):
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

    def get(self, path):
        url = f"{self.base}{path}"
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            sys.exit(f"error: UFM API {e.code} on GET {path}: {e.read().decode()[:300]}")
        except urllib.error.URLError as e:
            sys.exit(f"error: cannot reach UFM at {url}: {e.reason}")


def find_system(client, hostname):
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


def get_system_ports(client, system_guid):
    ports = client.get(f"/resources/ports?system={system_guid}")
    return [p for p in ports if p.get("guid")]


def iter_pkey_entries(data):
    """Yield (pkey, entry_dict) from all known /resources/pkeys?guids_data=true shapes."""
    if isinstance(data, dict):
        # {"0x678": {"guids": [...]}, "0x699": {...}, ...}
        for k, v in data.items():
            if isinstance(v, dict):
                yield _norm_pkey(k), v
    elif isinstance(data, list):
        # [{"pkey": "0x678", "guids": [...]}, ...]
        for v in data:
            if isinstance(v, dict):
                key = v.get("pkey") or str(v.get("partition", "")).split("_")[-1]
                if key:
                    yield _norm_pkey(key), v


def entry_members(entry):
    """Return {norm_guid: {index0, membership}} from a pkey entry."""
    members = {}
    for g in entry.get("guids", []) or []:
        guid = g.get("guid") or g.get("port_guid") or ""
        if not guid:
            continue
        members[_norm_guid(guid)] = {
            "index0": bool(g.get("index0", g.get("index_0", False))),
            "membership": str(g.get("membership", g.get("member", "?"))).lower(),
        }
    return members


def main():
    ap = argparse.ArgumentParser(
        description="Read-only UFM check: node holds Index-0 membership in exactly one pkey")
    ap.add_argument("hostname", help="node hostname as known to UFM")
    ap.add_argument("--host", default=os.environ.get("UFM_HOST"), help="UFM VIP (or set UFM_HOST)")
    ap.add_argument("--user", default=os.environ.get("UFM_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("UFM_PASS"))
    ap.add_argument("--token", default=os.environ.get("UFM_TOKEN"), help="API token (uses ufmRestV3)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--expect-ports", type=int, default=8,
                    help="expected HCA port count for the node (default: 8)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--debug", action="store_true", help="dump raw pkeys payload to stderr")
    args = ap.parse_args()

    if not args.host:
        sys.exit("error: UFM host not set (use --host or UFM_HOST)")

    client = UfmClient(args.host, args.user, args.password, args.token,
                       verify_tls=not args.insecure)

    system = find_system(client, args.hostname)
    sys_name = system.get("system_name") or system.get("name")
    sys_guid = system.get("guid") or system.get("system_guid")
    ports = get_system_ports(client, sys_guid)
    port_guids = {_norm_guid(p["guid"]): p["guid"] for p in ports}

    all_pkeys = client.get("/resources/pkeys?guids_data=true")
    if args.debug:
        print("DEBUG raw pkeys response:\n" + json.dumps(all_pkeys, indent=2)[:6000],
              file=sys.stderr)

    # memberships[pkey] = {"index0_ports": [...], "other_ports": [...], "membership": set()}
    memberships = {}
    pkeys_scanned = 0
    for pkey, entry in iter_pkey_entries(all_pkeys):
        pkeys_scanned += 1
        members = entry_members(entry)
        hit_index0, hit_other, kinds = [], [], set()
        for ng, orig in port_guids.items():
            m = members.get(ng)
            if not m:
                continue
            kinds.add(m["membership"])
            (hit_index0 if m["index0"] else hit_other).append(orig)
        if hit_index0 or hit_other:
            memberships[pkey] = {
                "index0_ports": sorted(hit_index0),
                "non_index0_ports": sorted(hit_other),
                "membership_types": sorted(kinds),
            }

    index0_pkeys = {k: v for k, v in memberships.items() if v["index0_ports"]}
    full_index0_pkeys = {k: v for k, v in index0_pkeys.items()
                         if len(v["index0_ports"]) == len(port_guids)}
    partial = {k: v for k, v in index0_pkeys.items()
               if 0 < len(v["index0_ports"]) < len(port_guids)}

    compliant = (len(index0_pkeys) == 1
                 and len(full_index0_pkeys) == 1
                 and len(port_guids) > 0)

    result = {
        "ufm_host": args.host,
        "system": sys_name,
        "system_guid": sys_guid,
        "node_ports_found": len(port_guids),
        "node_ports_expected": args.expect_ports,
        "pkeys_scanned": pkeys_scanned,
        "memberships": memberships,
        "index0_pkeys": sorted(index0_pkeys),
        "index0_pkey_count": len(index0_pkeys),
        "compliant_single_index0": compliant,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nUFM:    {args.host}")
        print(f"Node:   {sys_name}  (guid {sys_guid}, {len(port_guids)} ports, "
              f"{pkeys_scanned} pkeys scanned)\n")
        if not memberships:
            print("Node ports are not members of ANY pkey.")
        else:
            print(f"{'Pkey':<10}{'Index-0 ports':<16}{'non-Index-0 ports':<20}Membership")
            print("-" * 62)
            for pk in sorted(memberships):
                v = memberships[pk]
                print(f"{pk:<10}{len(v['index0_ports']):>7}/{len(port_guids):<8}"
                      f"{len(v['non_index0_ports']):>9}/{len(port_guids):<10}"
                      f"{','.join(v['membership_types'])}")
            print("-" * 62)
        print(f"\nIndex-0 memberships: {sorted(index0_pkeys) or 'none'}")
        if partial:
            for pk, v in partial.items():
                print(f"WARNING: pkey {pk} has PARTIAL Index-0 coverage "
                      f"({len(v['index0_ports'])}/{len(port_guids)} ports) — inconsistent node state.")
        if len(port_guids) != args.expect_ports:
            print(f"WARNING: found {len(port_guids)} ports, expected {args.expect_ports}.")
        if compliant:
            print(f"RESULT: PASS — node is Index-0 member of exactly one pkey "
                  f"({next(iter(index0_pkeys))}) on all {len(port_guids)} ports.")
        elif not index0_pkeys:
            print("RESULT: FAIL — node has NO Index-0 membership in any pkey.")
        else:
            print(f"RESULT: FAIL — node has Index-0 membership in "
                  f"{len(index0_pkeys)} pkeys: {', '.join(sorted(index0_pkeys))}.")

    if not port_guids:
        sys.exit(2)
    sys.exit(0 if compliant else 1)


if __name__ == "__main__":
    main()
