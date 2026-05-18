import shutil
import subprocess
import httpx

REQUIRED_BINARIES = {
    "docker": "Docker is required for container scanning.",
    "syft": "Syft is required for SBOM generation.",
    "grype": "Grype is required for vulnerability scanning.",
}

def check_binary_exists(binary: str) -> bool:
    """Check if a binary exists in PATH."""
    return shutil.which(binary) is not None

def check_dependencies():
    """Check required and optional dependencies and print status messages."""
    print("\n=== Dependency Check ===")

    # Required tools
    for binary, message in REQUIRED_BINARIES.items():
        if not check_binary_exists(binary):
            print(f"[!] Missing: {binary}")
            print(f"    → {message}")
        else:
            print(f"[✓] Found: {binary}")

    print("========================\n")
