"""Upgrades the live OpenTimestamps stamp and records its state in `vectors/ots_live.json`.

Run at least 6 hours after the stamp and again after 24 hours with
`uv run python libs/proofs/py/scripts/upgrade_ots.py [--bitcoin-node URL]`. The reference client
(LGPL-3.0) runs as an external tool, `ots upgrade` then `ots verify`; it is never imported. Our
reader then reads the upgraded proof. A Bitcoin attestation counts as anchored only when its
computed root equals the block's Merkle root, fetched from a public Esplora explorer; without a
Bitcoin node, `ots verify` can only report the root to check.
"""

import argparse
import base64
import datetime
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

import httpx
from fourth_proofs import ProofError, ots_status
from live_run import OTS, OTS_LIVE, save_vectors

ESPLORA = "https://blockstream.info/api"


def header_order(explorer_root_hex: str) -> bytes:
    """Merkle root in block header byte order from the reversed hex explorers print."""
    root = bytes.fromhex(explorer_root_hex)
    if len(root) != 32:  # noqa: PLR2004
        raise ValueError("a Merkle root is 32 bytes")
    return root[::-1]


def block_merkle_root(height: int) -> bytes:
    block_hash = httpx.get(f"{ESPLORA}/block-height/{height}", timeout=30)
    block_hash.raise_for_status()
    block = httpx.get(f"{ESPLORA}/block/{block_hash.text.strip()}", timeout=30)
    block.raise_for_status()
    return header_order(block.json()["merkle_root"])


def hours_between(start_iso: str, end: datetime.datetime) -> float:
    return round((end - datetime.datetime.fromisoformat(start_iso)).total_seconds() / 3600, 2)


def run_ots(*args: str) -> dict[str, Any]:
    result = subprocess.run([*OTS, *args], check=False, capture_output=True, text=True)
    return {"returncode": result.returncode, "output": (result.stdout + result.stderr)[-2000:]}


def upgrade(
    path: Path = OTS_LIVE, *, record: bool = True, bitcoin_node: str | None = None
) -> dict[str, Any]:
    """Upgrade the stored stamp, read it with `ots_status` and optionally record the result."""
    vectors = cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))
    digest_hex = cast("str", vectors["data_sha256"])
    digest = bytes.fromhex(digest_hex)
    with tempfile.TemporaryDirectory() as directory:
        proof_path = Path(directory) / "imprint.ots"
        proof_path.write_bytes(base64.b64decode(vectors["pending"]["proof"]))
        upgraded = run_ots("upgrade", str(proof_path))
        node = ["--bitcoin-node", bitcoin_node] if bitcoin_node else ["--no-bitcoin"]
        verified = run_ots(*node, "verify", "-d", digest_hex, str(proof_path))
        proof = proof_path.read_bytes()
    checked_at = datetime.datetime.now(datetime.UTC)
    status = ots_status(proof, digest)
    result: dict[str, Any] = {
        "checked_at": checked_at.isoformat(timespec="seconds"),
        "hours_after_stamp": hours_between(vectors["stamped_at"], checked_at),
        "kind": status.kind,
        "block_height": None,
        "ots_upgrade": upgraded,
        "ots_verify": verified,
    }
    height = status.unverified_anchor_height
    if height is not None:
        root = block_merkle_root(height)
        try:
            anchored = ots_status(proof, digest, block_merkle_roots={height: root})
        except ProofError as error:
            result["kind"] = f"rejected: {error}"
        else:
            result.update(kind=anchored.kind, block_height=anchored.block_height)
            vectors.setdefault(
                "anchored",
                {
                    "proof": base64.b64encode(proof).decode(),
                    "calendars": anchored.calendars,
                    "block_height": height,
                    "block_merkle_root": root.hex(),
                    "block_merkle_root_source": f"{ESPLORA}/block-height/{height}",
                    "first_seen_hours_after_stamp": result["hours_after_stamp"],
                },
            )
    if record:
        vectors["upgrades"].append(result)
        save_vectors(path, vectors)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-node", help="Bitcoin node URL for `ots verify`")
    parser.add_argument("--dry-run", action="store_true", help="do not record the result")
    args = parser.parse_args()
    result = upgrade(record=not args.dry_run, bitcoin_node=args.bitcoin_node)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
