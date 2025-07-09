# python_backend/quantum_algorithms.py

import subprocess
import os

def get_supported_kex(ssh_bin_path="/home/dinesh/openssh/openssh/ssh"):

    """
    Fetch Kyber-based key exchange algorithms from compiled ssh binary.
    """
    ssh_bin = os.path.abspath(ssh_bin_path)
    try:
        output = subprocess.check_output([ssh_bin, "-Q", "kex"]).decode().splitlines()
        kyber_algos = [k for k in output if "kyber" in k.lower()]
        return kyber_algos
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] KEX algorithm fetch failed: {e}")
        return []


def get_supported_signatures():
    """
    Since ssh -Q hostkey is unsupported, return hardcoded known-safe signature types.
    Includes MLDSA aliases for Dilithium and Falcon.
    """
    return [
        "mldsa65",     # Likely Dilithium3
        "mldsa87",     # Likely Falcon512 or Dilithium5
        "dilithium2",
        "dilithium3",
        "dilithium5",
        "falcon512",
        "falcon1024"
    ]


def get_default_signature_name(sig_code):
    """
    Optional mapping for display purposes.
    Converts internal names like mldsa65 → Dilithium3
    """
    alias_map = {
        "mldsa65": "Dilithium3",
        "mldsa87": "Falcon512",
        "dilithium3": "Dilithium3",
        "falcon512": "Falcon512"
    }
    return alias_map.get(sig_code, sig_code)
