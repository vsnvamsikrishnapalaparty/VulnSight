import os
from pathlib import Path

# Detects OS-level container context signals from the extracted filesystem (All modes)
def detect_container_context(rootfs_path: Path) -> dict:

    runs_as_root = False
    suid_binaries = []
    dangerous_tools = []
    base_image_eol = False

    # Detecting if root user exists with UID 0
    passwd_path = rootfs_path / "etc/passwd"
    if passwd_path.exists():
        try:
            for line in passwd_path.read_text().splitlines():
                if line.startswith("root:") and ":0:" in line:
                    runs_as_root = True
                    break
        except Exception:
            pass

    # Detecting SUID binaries
    for dirpath, _, filenames in os.walk(rootfs_path):
        for f in filenames:
            full = Path(dirpath) / f
            try:
                st = full.stat()
                if st.st_mode & 0o4000:  # SUID bit
                    suid_binaries.append(str(full))
            except Exception:
                continue

    # Detecting dangerous tools
    tool_list = ["bash", "sh", "zsh", "ksh", "nc", "netcat", "socat", "curl", "wget"]
    for t in tool_list:
        for prefix in ["bin", "usr/bin", "sbin", "usr/sbin"]:
            if (rootfs_path / prefix / t).exists():
                dangerous_tools.append(t)

    dangerous_tools = sorted(set(dangerous_tools))

    return {
        "runs_as_root": runs_as_root,
        "suid_binaries": suid_binaries,
        "dangerous_tools": dangerous_tools,
        "base_image_eol": base_image_eol,
    }

# Detects cloud-level context signals for cloud instances (Host mode only)
def detect_cloud_context(rootfs_path: Path) -> dict:

    provider = None

    # Detects AWS EC2 instance
    if (rootfs_path / "var/lib/cloud/instance").exists():
        provider = "aws"
    if (rootfs_path / "var/log/cloud-init.log").exists():
        try:
            txt = (rootfs_path / "var/log/cloud-init.log").read_text().lower()
            if "amazon" in txt or "aws" in txt:
                provider = "aws"
        except Exception:
            pass

    # Detects GCP instance
    if (rootfs_path / "var/log/google.log").exists():
        provider = "gcp"
    if (rootfs_path / "etc/default/instance_configs.cfg").exists():
        provider = "gcp"

    # Detects Azure instance
    if (rootfs_path / "var/lib/waagent").exists():
        provider = "azure"
    if (rootfs_path / "etc/waagent.conf").exists():
        provider = "azure"

    identity_attached = False
    identity_scope_broad = False

    # AWS IAM role hints
    if provider == "aws":
        if (rootfs_path / "var/lib/amazon/ssm").exists():
            identity_attached = True

    # GCP service account hints
    if provider == "gcp":
        sa_dir = rootfs_path / "var/lib/google"
        if sa_dir.exists():
            identity_attached = True

    # Azure managed identity hints
    if provider == "azure":
        if (rootfs_path / "var/lib/waagent").exists():
            identity_attached = True

    # Detecting Network exposure from filesystem
    ssh_open = False
    all_ports_open = False
    public_ip = False

    sshd_config = rootfs_path / "etc/ssh/sshd_config"
    if sshd_config.exists():
        try:
            txt = sshd_config.read_text().lower()
            if "passwordauthentication yes" in txt:
                ssh_open = True
            if "permitrootlogin yes" in txt:
                ssh_open = True
        except Exception:
            pass

    # Checking cloud-init logs for public IP assignment (sometimes)
    cloud_log = rootfs_path / "var/log/cloud-init.log"
    if cloud_log.exists():
        try:
            txt = cloud_log.read_text().lower()
            if "public-ipv4" in txt or "public-ipv6" in txt:
                public_ip = True
        except Exception:
            pass

    metadata_hardening = True
    secure_boot_disabled = False
    serial_port_enabled = False
    disk_encryption_disabled = False

    # Azure secure boot hints
    if provider == "azure":
        wa = rootfs_path / "etc/waagent.conf"
        if wa.exists():
            try:
                txt = wa.read_text().lower()
                if "provisioning.deletekeys=no" in txt:
                    secure_boot_disabled = True
            except Exception:
                pass

    # GCP serial port hints
    if provider == "gcp":
        cfg = rootfs_path / "etc/default/instance_configs.cfg"
        if cfg.exists():
            try:
                txt = cfg.read_text().lower()
                if "enable_serial_port=true" in txt:
                    serial_port_enabled = True
            except Exception:
                pass

    return {
        "provider": provider,
        "public_ip": public_ip,
        "metadata_hardening": metadata_hardening,
        "identity_attached": identity_attached,
        "identity_scope_broad": identity_scope_broad,
        "ssh_open": ssh_open,
        "all_ports_open": all_ports_open,
        "disk_encryption_disabled": disk_encryption_disabled,
        "secure_boot_disabled": secure_boot_disabled,
        "serial_port_enabled": serial_port_enabled,
    }


# Unified function for the Container/Cloud-instance context
def detect_context(mode: str, rootfs_path: Path) -> dict:
    """
    Unified context detector.
    Always returns:
    {
        "container": {...},
        "cloud": {...}
    }
    """

    ctx = {}

    # Always detect container context
    ctx["container"] = detect_container_context(rootfs_path)

    # Only detect cloud context in host mode
    if mode == "host":
        ctx["cloud"] = detect_cloud_context(rootfs_path)
    else:
        ctx["cloud"] = {}

    return ctx
