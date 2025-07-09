import subprocess
import os

class OQSSSHManager:
    def __init__(self, ssh_bin_path="/home/dinesh/openssh/openssh/ssh", ssh_port=2222):
        """
        ssh_bin_path: Full path to OQS-enabled ssh binary
        ssh_port: Port where the SSH server is running (default: 2222)
        """
        self.ssh_bin = os.path.abspath(ssh_bin_path)
        self.port = ssh_port

    def establish_quantum_tunnel(self, user, host, kem_algo, sig_algo,
                                  local_forward_port=None,
                                  remote_target_host=None,
                                  remote_target_port=None):
        """
        Start a quantum-safe SSH tunnel using specified KEM and Signature algorithms.
        Optionally forwards a local port to a remote host:port.
        """
        ssh_cmd = [
            self.ssh_bin,
            "-p", str(self.port),
            "-o", f"KexAlgorithms={kem_algo}",
            "-o", f"HostKeyAlgorithms=ssh-{sig_algo}",
        ]

        # Optional: local port forwarding
        if local_forward_port and remote_target_host and remote_target_port:
            forwarding = f"{local_forward_port}:{remote_target_host}:{remote_target_port}"
            ssh_cmd += ["-L", forwarding]

        # Add SSH target
        ssh_cmd += ["-N", f"{user}@{host}"]

        print(f"[INFO] Launching SSH with command: {' '.join(ssh_cmd)}")

        try:
            process = subprocess.Popen(ssh_cmd)
            return process
        except Exception as e:
            print(f"[ERROR] Failed to start SSH tunnel: {e}")
            return None
