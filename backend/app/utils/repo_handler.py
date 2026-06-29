"""
utils/repo_handler.py

Handles getting source code onto local disk so we can scan it:
- Cloning a GitHub repo (public repos, via HTTPS)
- Extracting an uploaded ZIP file
- Finding all scannable code files inside
- Cleaning up temp folders when we're done

Everything goes into the OS temp directory (on Windows this is typically
under AppData/Local/Temp) under a unique folder name per scan, so multiple
scans never collide.
"""

import os
import re
import shutil
import tempfile
import logging
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from git import Repo, GitCommandError

logger = logging.getLogger("shieldlabs.repo_handler")


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

# Extensions we know how to parse (matches scanners/ast_parser.py)
SCANNABLE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}

# Folders we never want to scan — they're noise, not the user's code
IGNORED_DIRS = {
    "node_modules", "venv", "env", ".venv", "__pycache__",
    ".git", "dist", "build", ".next", "vendor", "site-packages"
}

# Max ZIP size we'll accept (100MB), to match the roadmap's limit
MAX_ZIP_SIZE_BYTES = 100 * 1024 * 1024


# ─────────────────────────────────────────────
# GITHUB URL VALIDATION
# ─────────────────────────────────────────────

# Matches: https://github.com/user/repo  or  github.com/user/repo  (with optional .git, trailing slash)
GITHUB_URL_PATTERN = re.compile(
    r'^(https?://)?github\.com/([\w.-]+)/([\w.-]+?)(\.git)?/?$'
)


def validate_github_url(url: str) -> bool:
    """
    Checks that a string looks like a real GitHub repo URL.

    We deliberately keep this strict — it's a security tool, so we
    don't want to accidentally try to clone something that isn't
    actually a GitHub repo (e.g. someone pasting a random domain
    to make our server make requests to it).

    Args:
        url: The URL string to check

    Returns:
        True if it matches the expected GitHub repo pattern
    """
    return bool(GITHUB_URL_PATTERN.match(url.strip()))


def _normalize_github_url(url: str) -> str:
    """
    Turns any valid GitHub URL variant into a clean clonable HTTPS URL.

    "github.com/user/repo"           → "https://github.com/user/repo.git"
    "https://github.com/user/repo/"  → "https://github.com/user/repo.git"
    """
    match = GITHUB_URL_PATTERN.match(url.strip())
    if not match:
        raise ValueError(f"Invalid GitHub URL: {url}")

    user, repo = match.group(2), match.group(3)
    return f"https://github.com/{user}/{repo}.git"


# ─────────────────────────────────────────────
# DOWNLOAD / EXTRACT
# ─────────────────────────────────────────────

def download_github_repo(url: str, branch: str = "main") -> str:
    """
    Clones a public GitHub repo into a unique temp folder.

    Args:
        url: GitHub repo URL (any common format)
        branch: Which branch to clone (default "main";
                falls back to "master" automatically if "main" doesn't exist)

    Returns:
        Path to the cloned repo on disk

    Raises:
        ValueError: If the URL isn't a valid GitHub URL
        RuntimeError: If cloning fails (repo doesn't exist, private, network error)
    """
    if not validate_github_url(url):
        raise ValueError(f"'{url}' doesn't look like a valid GitHub repo URL")

    clone_url = _normalize_github_url(url)

    # tempfile.mkdtemp() creates a unique folder so concurrent scans
    # never overwrite each other. prefix makes it easy to spot in the temp dir.
    dest_path = tempfile.mkdtemp(prefix="shieldlabs_repo_")

    logger.info(f"Cloning {clone_url} (branch={branch}) into {dest_path}")

    try:
        # depth=1 means "shallow clone" — only the latest commit, not
        # the entire git history. We only need the current code, and
        # this is much faster + smaller for big repos.
        Repo.clone_from(clone_url, dest_path, branch=branch, depth=1)

    except GitCommandError as e:
        # "main" might not exist — try "master" as a fallback before giving up
        if branch == "main":
            logger.warning("Branch 'main' not found, trying 'master'...")
            shutil.rmtree(dest_path, ignore_errors=True)
            dest_path = tempfile.mkdtemp(prefix="shieldlabs_repo_")
            try:
                Repo.clone_from(clone_url, dest_path, branch="master", depth=1)
            except GitCommandError as e2:
                shutil.rmtree(dest_path, ignore_errors=True)
                raise RuntimeError(
                    f"Could not clone repo. It may be private, deleted, "
                    f"or have neither a 'main' nor 'master' branch. Details: {e2}"
                )
        else:
            shutil.rmtree(dest_path, ignore_errors=True)
            raise RuntimeError(f"Could not clone repo '{url}': {e}")

    logger.info(f"Successfully cloned to {dest_path}")
    return dest_path


def extract_zip(file_path: str) -> str:
    """
    Extracts an uploaded ZIP file into a unique temp folder.

    Args:
        file_path: Path to the .zip file on disk (e.g. from a FastAPI upload)

    Returns:
        Path to the extracted folder

    Raises:
        ValueError: If the file is too large or isn't a valid ZIP
    """
    # Check size first — don't even try to open huge files
    size = os.path.getsize(file_path)
    if size > MAX_ZIP_SIZE_BYTES:
        raise ValueError(
            f"ZIP file is {size / 1024 / 1024:.1f}MB — max allowed is "
            f"{MAX_ZIP_SIZE_BYTES / 1024 / 1024:.0f}MB"
        )

    if not zipfile.is_zipfile(file_path):
        raise ValueError(f"'{file_path}' is not a valid ZIP file")

    dest_path = tempfile.mkdtemp(prefix="shieldlabs_zip_")
    logger.info(f"Extracting {file_path} into {dest_path}")

    with zipfile.ZipFile(file_path, "r") as zf:
        # Guard against "zip slip" — a malicious ZIP whose entries contain
        # "../../etc/something" to escape the destination folder. We check
        # every entry's resolved path is still inside dest_path before extracting.
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(dest_path, member))
            if not member_path.startswith(os.path.realpath(dest_path)):
                raise ValueError(f"Unsafe ZIP entry detected: {member}")

        zf.extractall(dest_path)

    logger.info(f"Successfully extracted to {dest_path}")
    return dest_path


# ─────────────────────────────────────────────
# FILE DISCOVERY
# ─────────────────────────────────────────────

def get_all_code_files(repo_path: str) -> list[str]:
    """
    Walks a directory tree and returns every file we know how to scan
    (based on SCANNABLE_EXTENSIONS), skipping noise folders like
    node_modules, venv, .git, etc.

    Args:
        repo_path: Root folder to search (from download_github_repo
                   or extract_zip)

    Returns:
        List of absolute file paths
    """
    code_files = []

    for root, dirs, files in os.walk(repo_path):
        # Modifying `dirs` in place tells os.walk() to skip descending
        # into these folders entirely — much faster than filtering after
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for filename in files:
            ext = Path(filename).suffix
            if ext in SCANNABLE_EXTENSIONS:
                code_files.append(os.path.join(root, filename))

    logger.info(f"Found {len(code_files)} scannable files in {repo_path}")
    return code_files


# ─────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────

def cleanup_temp_repo(repo_path: str) -> None:
    """
    Deletes a temp repo/zip folder after scanning is done.

    IMPORTANT: Always call this when a scan finishes (success OR failure).
    Otherwise temp folders pile up on disk forever. Use try/finally
    wherever you call download_github_repo/extract_zip.

    Args:
        repo_path: The folder to delete
    """
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)
        logger.info(f"Cleaned up temp folder: {repo_path}")
    else:
        logger.warning(f"Tried to clean up non-existent path: {repo_path}")