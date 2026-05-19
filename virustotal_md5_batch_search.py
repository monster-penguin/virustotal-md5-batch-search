#!/usr/bin/env python3
"""
VirusTotal MD5 Batch Search & File Hunter
─────────────────────────────────────────
Stage 1 — Batch MD5 hash search on VirusTotal
Stage 2 — Detailed analysis of confirmed hashes
Stage 3 — File Hunter: locate, download, and verify actual files

Run any stage standalone, or chain 1 → 2 → 3 in a single session.
Session state (API keys, hash lists, JSON paths) carries forward automatically.

Stage 3 dependencies:
    pip install requests rarfile py7zr python-magic
    sudo apt install unrar   # or: brew install unrar
"""

import hashlib
import io
import json
import os
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ── Optional archive dependencies — checked at runtime ────────
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    import rarfile
    HAS_RAR = True
except ImportError:
    HAS_RAR = False

try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False


# ─────────────────────────────────────────────────────────────
# Session state — shared across all stages in one run
# ─────────────────────────────────────────────────────────────
SESSION_STATE: Dict[str, Any] = {
    "vt_api_key":       None,   # VirusTotal API key (Stages 1 + 2)
    "github_token":     None,   # GitHub token (Stage 3)
    "hybrid_api_key":   None,   # Hybrid Analysis key (Stage 3, optional)
    "md5_hashes":       [],     # full raw hash list from Stage 1 input
    "stage1_results":   {},     # {md5: {found, malicious, error}}
    "stage1_json_path": None,
    "stage2_results":   {},     # {md5: detailed_result}
    "stage2_json_path": None,
    "blocklist":        set(),  # exact owner/repo strings to never download from
    "known_binaries":   [],     # repos to walk via Contents API
    "config_path":      None,   # path to the config/md5 file
}



# ─────────────────────────────────────────────────────────────
# Config file parser
# ─────────────────────────────────────────────────────────────
_KNOWN_SECTIONS = {
    "virustotal api", "github token", "hybrid analysis api",
    "blocklist", "known_binaries", "md5s",
}


def parse_config_file(path: str) -> dict:
    """
    Parse a config file with section headers.
    Sections: [virustotal api], [github token], [hybrid analysis api],
              [blocklist], [known_binaries], [md5s]
    Returns a dict with parsed values ready to load into SESSION_STATE.
    Falls back to treating the file as a plain md5 list if no sections found.
    """
    raw: Dict[str, list] = {s: [] for s in _KNOWN_SECTIONS}
    current = None
    has_sections = False

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                header = line[1:-1].lower()
                current = header if header in _KNOWN_SECTIONS else None
                if current:
                    has_sections = True
            elif current:
                raw[current].append(line)

    if not has_sections:
        # Plain md5 list — treat entire file as [md5s]
        with open(path) as f:
            raw["md5s"] = [l.strip() for l in f if l.strip()]

    return {
        "vt_api_key":     raw["virustotal api"][0]     if raw["virustotal api"]     else None,
        "github_token":   raw["github token"][0]       if raw["github token"]       else None,
        "hybrid_api_key": raw["hybrid analysis api"][0] if raw["hybrid analysis api"] else None,
        "blocklist":      set(raw["blocklist"]),
        "known_binaries": raw["known_binaries"],
        "md5s":           [h for h in raw["md5s"] if h],
    }


def find_config_file() -> Optional[Path]:
    """Find any file named config.* in the script directory."""
    for f in SCRIPT_DIR.iterdir():
        if f.is_file() and f.stem.lower() == "config":
            return f
    return None


def load_config_into_session(path: str):
    """Parse config file and populate SESSION_STATE with any values found."""
    cfg = parse_config_file(path)
    SESSION_STATE["config_path"] = path

    if cfg["vt_api_key"]     and not SESSION_STATE["vt_api_key"]:
        SESSION_STATE["vt_api_key"]     = cfg["vt_api_key"]
    if cfg["github_token"]   and not SESSION_STATE["github_token"]:
        SESSION_STATE["github_token"]   = cfg["github_token"]
    if cfg["hybrid_api_key"] and not SESSION_STATE["hybrid_api_key"]:
        SESSION_STATE["hybrid_api_key"] = cfg["hybrid_api_key"]
    if cfg["blocklist"]:
        SESSION_STATE["blocklist"]      = cfg["blocklist"]
    if cfg["known_binaries"]:
        SESSION_STATE["known_binaries"] = cfg["known_binaries"]
    if cfg["md5s"] and not SESSION_STATE["md5_hashes"]:
        SESSION_STATE["md5_hashes"]     = cfg["md5s"]

    return cfg


def auto_load_config():
    """Silently load config file from script directory if present."""
    cfg_path = find_config_file()
    if cfg_path:
        load_config_into_session(str(cfg_path))
        print(f"Config loaded      : {cfg_path.name}")


# ─────────────────────────────────────────────────────────────
# GitHub Contents API — repo index + full-depth walker
# ─────────────────────────────────────────────────────────────
_repo_index: Dict[str, Dict[str, str]] = {}   # {repo: {filename: download_url}}


def _walk_repo_tree(repo: str, path: str, token: str, index: dict, depth: int = 0):
    """Recursively walk a GitHub repo via Contents API, building filename→url index."""
    if depth > 30:
        return
    try:
        r = HTTP_SESSION.get(
            f"https://api.github.com/repos/{repo}/contents/{path}",
            headers={
                "Authorization": f"token {token}",
                "Accept":        "application/vnd.github.v3+json",
            },
            timeout=15,
        )
        if r.status_code == 200:
            items = r.json()
            if not isinstance(items, list):
                return
            for item in items:
                if item["type"] == "file":
                    dl = item.get("download_url") or ""
                    index[item["name"]] = dl
                elif item["type"] == "dir":
                    time.sleep(0.3)
                    _walk_repo_tree(repo, item["path"], token, index, depth + 1)
        elif r.status_code == 403:
            print(f"\n      ✗ Contents API rate limit on {repo} — pausing 60s")
            time.sleep(60)
            _walk_repo_tree(repo, path, token, index, depth)
        time.sleep(0.3)
    except requests.RequestException:
        pass


def build_repo_index(repo: str) -> Dict[str, str]:
    """Build (or return cached) filename→download_url index for a known_binary repo."""
    if repo in _repo_index:
        return _repo_index[repo]

    token = SESSION_STATE.get("github_token", "")
    if not token:
        return {}

    print(f"      Indexing {repo} ...", end=" ", flush=True)
    index: Dict[str, str] = {}
    _walk_repo_tree(repo, "", token, index)
    _repo_index[repo] = index
    print(f"{len(index)} file(s)")
    return index


def search_github_contents(filename: str, match_type: str) -> List[SearchHit]:
    """Search all known_binary repos for an exact filename match via Contents API."""
    hits = []
    for repo in SESSION_STATE.get("known_binaries", []):
        index = build_repo_index(repo)
        if filename in index and index[filename]:
            hits.append(SearchHit(
                url        = index[filename],
                source     = f"GitHub Contents ({repo})",
                match_type = match_type,
                confidence = "high",
                matched_on = filename,
            ))
    return hits


def is_github_blocklisted(url: str) -> bool:
    """Return True if URL is from a blocklisted owner/repo."""
    blocklist = SESSION_STATE.get("blocklist", set())
    if not blocklist:
        return False
    if "raw.githubusercontent.com" in url:
        try:
            parts = url.replace("https://raw.githubusercontent.com/", "").split("/")
            return f"{parts[0]}/{parts[1]}" in blocklist
        except IndexError:
            pass
    return False


SCRIPT_DIR = Path(__file__).resolve().parent

DOWNLOAD_CAP_BYTES = 3 * 1024 ** 3   # 3 GB hard cap
MAX_ARCHIVE_DEPTH  = 6
REQUEST_DELAY      = 1.5             # seconds between outbound requests
FOUND_DIR          = SCRIPT_DIR / "found"
TEMP_BASE          = SCRIPT_DIR / "stage3_temp"
MAX_ALIASES        = 10
MAX_PARENTS        = 20




# ─────────────────────────────────────────────────────────────
# Stage 3 data structures
# ─────────────────────────────────────────────────────────────
@dataclass
class TargetFile:
    md5:        str
    sha256:     str           = ""
    sha1:       str           = ""
    names:      List[str]     = field(default_factory=list)
    file_type:  str           = ""
    size_bytes: Optional[int] = None
    parents:    List[Dict]    = field(default_factory=list)


@dataclass
class SearchHit:
    url:        str
    source:     str
    match_type: str   # direct_hash | parent_hash | direct_name | parent_name | alias_name
    confidence: str   # high | medium | low
    matched_on: str
    verified:   bool = False


@dataclass
class PrimaryResult:
    target:            TargetFile
    direct_hits:       List[SearchHit] = field(default_factory=list)
    parent_hits:       List[SearchHit] = field(default_factory=list)
    unresolved:        List[SearchHit] = field(default_factory=list)
    skipped_downloads: List[Dict]      = field(default_factory=list)
    stage1_extended:   List[Dict]      = field(default_factory=list)
    saved_path:        Optional[str]   = None
    found:             bool            = False


# ─────────────────────────────────────────────────────────────
# Shared HTTP session (Stage 3 searches + downloads)
# ─────────────────────────────────────────────────────────────
HTTP_SESSION = requests.Session()
HTTP_SESSION.headers.update({"User-Agent": "vt-file-hunter/1.0"})


# ─────────────────────────────────────────────────────────────
# VirusTotal — Stage 1: Batch Searcher
# ─────────────────────────────────────────────────────────────
class VirusTotalBatchSearcher:
    REQUEST_DELAY = 15
    API_URL       = "https://www.virustotal.com/api/v3/files"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})
        self.results = {}
        self.errors  = {}

    def search_hash(self, md5_hash: str) -> Dict[str, Any]:
        try:
            r = self.session.get(f"{self.API_URL}/{md5_hash}", timeout=10)
            if r.status_code == 200:
                stats = (
                    r.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                return {
                    "found":     True,
                    "malicious": stats.get("malicious", 0) > 0,
                    "error":     None,
                }
            elif r.status_code == 404:
                return {"found": False, "malicious": False, "error": None}
            elif r.status_code == 401:
                print("ERROR: Invalid API key.")
                sys.exit(1)
            elif r.status_code == 429:
                print("WARNING: Rate limited. Waiting 60 seconds...")
                time.sleep(60)
                return self.search_hash(md5_hash)
            else:
                msg = f"HTTP {r.status_code}"
                self.errors[md5_hash] = msg
                return {"found": None, "malicious": None, "error": msg}
        except requests.exceptions.Timeout:
            self.errors[md5_hash] = "Request timeout"
            return {"found": None, "malicious": None, "error": "Request timeout"}
        except requests.exceptions.RequestException as e:
            self.errors[md5_hash] = str(e)
            return {"found": None, "malicious": None, "error": str(e)}

    def search_batch(self, md5_hashes: List[str], verbose: bool = True) -> Dict[str, Any]:
        total = len(md5_hashes)
        print(f"\n{'='*60}")
        print(f"VirusTotal Batch Search")
        print(f"{'='*60}")
        print(f"Total hashes   : {total}")
        print(f"Rate limit     : 1 request every {self.REQUEST_DELAY}s")
        print(f"Estimated time : {(total * self.REQUEST_DELAY) / 60:.1f} minutes")
        print(f"{'='*60}\n")

        start = time.time()
        for i, md5_hash in enumerate(md5_hashes, 1):
            md5_hash = md5_hash.strip().lower()
            if verbose:
                print(f"[{i}/{total}] Searching {md5_hash}...", end=" ", flush=True)
            result = self.search_hash(md5_hash)
            self.results[md5_hash] = result
            if verbose:
                if result["error"]:
                    status = "ERROR"
                elif result["found"] is True:
                    status = "FOUND - MALICIOUS" if result["malicious"] else "FOUND - CLEAN"
                elif result["found"] is False:
                    status = "NOT IN DATABASE"
                else:
                    status = "UNKNOWN"
                print(status)
            if i < total:
                time.sleep(self.REQUEST_DELAY)

        elapsed      = time.time() - start
        found_count  = len([v for v in self.results.values() if v["found"] is True])
        not_found    = len([v for v in self.results.values() if v["found"] is False])
        malicious    = len([v for v in self.results.values() if v.get("malicious")])
        print(f"\n{'='*60}")
        print(f"Completed in {elapsed:.1f}s")
        print(f"  In database     : {found_count}  (malicious: {malicious}, clean: {found_count - malicious})")
        print(f"  Not in database : {not_found}")
        if self.errors:
            print(f"  Errors          : {len(self.errors)}")
        print(f"{'='*60}\n")
        return self.results

    def export_json(self, output_file: str = None) -> str:
        if output_file is None:
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = str(SCRIPT_DIR / f"virustotal_results_{ts}.json")
        found_count = len([v for v in self.results.values() if v["found"] is True])
        not_found   = len([v for v in self.results.values() if v["found"] is False])
        malicious   = len([v for v in self.results.values() if v.get("malicious")])
        export_data = {
            "timestamp":             datetime.now().isoformat(),
            "total_hashes_searched": len(self.results),
            "in_virustotal_database": {
                "count":     found_count,
                "malicious": malicious,
                "clean":     found_count - malicious,
            },
            "not_in_virustotal_database": not_found,
            "errors":       len(self.errors),
            "results":      self.results,
            "error_details": self.errors if self.errors else None,
        }
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)
        print(f"Results exported to: {output_file}\n")
        return output_file


# ─────────────────────────────────────────────────────────────
# VirusTotal — Stage 2: Detailed Analyzer
# ─────────────────────────────────────────────────────────────
class VirusTotalDetailedAnalyzer:
    REQUEST_DELAY = 15
    API_URL       = "https://www.virustotal.com/api/v3/files"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})
        self.detailed_results = {}
        self.errors           = {}

    def _fmt_ts(self, ts: int) -> Optional[str]:
        if not ts:
            return None
        try:
            from datetime import timezone
            return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return None

    def extract_file_details(self, md5_hash: str, response_data: dict) -> Dict[str, Any]:
        try:
            attrs = response_data.get("data", {}).get("attributes", {})
            return {
                "md5": md5_hash,
                "basic_properties": {
                    "md5":        attrs.get("md5"),
                    "sha256":     attrs.get("sha256"),
                    "sha1":       attrs.get("sha1"),
                    "file_type":  attrs.get("type_description"),
                    "magic":      attrs.get("magic"),
                    "size_bytes": attrs.get("size"),
                },
                "history": {
                    "first_seen_itw":   self._fmt_ts(attrs.get("first_seen_itw_date")),
                    "first_submission": self._fmt_ts(attrs.get("first_submission_date")),
                    "last_submission":  self._fmt_ts(attrs.get("last_submission_date")),
                    "last_analysis":    self._fmt_ts(attrs.get("last_analysis_date")),
                },
                "names":            attrs.get("names") or None,
                "execution_parents": None,
            }
        except Exception as e:
            return {"md5": md5_hash, "error": f"Failed to parse: {e}"}

    def get_execution_parents(self, sha256: str) -> Optional[List[Dict]]:
        try:
            r = self.session.get(
                f"{self.API_URL}/{sha256}/execution_parents",
                timeout=10,
                params={"limit": 40},
            )
            if r.status_code == 200:
                parents = []
                for parent in r.json().get("data", []):
                    try:
                        a    = parent.get("attributes", {})
                        name = a.get("meaningful_name") or a.get("name") or parent.get("id", "Unknown")
                        parents.append({
                            "type":             a.get("type_description"),
                            "name":             name,
                            "sha256":           parent.get("id"),
                            "size":             a.get("size"),
                            "first_submission": self._fmt_ts(a.get("first_submission_date")),
                            "last_analysis":    self._fmt_ts(a.get("last_analysis_date")),
                            "detections":       a.get("last_analysis_stats", {}).get("malicious", 0),
                        })
                    except Exception:
                        continue
                return parents if parents else None
            elif r.status_code == 429:
                print("WARNING: Rate limited on execution parents. Waiting 60s...")
                time.sleep(60)
                return self.get_execution_parents(sha256)
            return None
        except Exception:
            return None

    def get_file_details(self, md5_hash: str) -> Dict[str, Any]:
        try:
            r = self.session.get(f"{self.API_URL}/{md5_hash}", timeout=10)
            if r.status_code == 200:
                result = self.extract_file_details(md5_hash, r.json())
                sha256 = result["basic_properties"].get("sha256")
                time.sleep(1)
                if sha256:
                    result["execution_parents"] = self.get_execution_parents(sha256)
                return result
            elif r.status_code == 404:
                self.errors[md5_hash] = "Hash not found"
                return {"md5": md5_hash, "error": "Hash not found"}
            elif r.status_code == 401:
                print("ERROR: Invalid API key.")
                sys.exit(1)
            elif r.status_code == 429:
                print("WARNING: Rate limited. Waiting 60s...")
                time.sleep(60)
                return self.get_file_details(md5_hash)
            else:
                msg = f"HTTP {r.status_code}"
                self.errors[md5_hash] = msg
                return {"md5": md5_hash, "error": msg}
        except requests.exceptions.Timeout:
            self.errors[md5_hash] = "Request timeout"
            return {"md5": md5_hash, "error": "Request timeout"}
        except requests.exceptions.RequestException as e:
            self.errors[md5_hash] = str(e)
            return {"md5": md5_hash, "error": str(e)}

    def analyze_batch(self, md5_hashes: List[str], verbose: bool = True) -> Dict[str, Any]:
        total          = len(md5_hashes)
        adjusted_delay = self.REQUEST_DELAY * 2
        print(f"\n{'='*60}")
        print(f"VirusTotal Detailed Analysis (Stage 2)")
        print(f"{'='*60}")
        print(f"Total hashes   : {total}")
        print(f"API calls/hash : 2 (file info + execution parents)")
        print(f"Estimated time : {(total * adjusted_delay) / 60:.1f} minutes")
        print(f"{'='*60}\n")

        start = time.time()
        for i, md5_hash in enumerate(md5_hashes, 1):
            md5_hash = md5_hash.strip().lower()
            if verbose:
                print(f"[{i}/{total}] Fetching details for {md5_hash}...", end=" ", flush=True)
            result = self.get_file_details(md5_hash)
            self.detailed_results[md5_hash] = result
            if verbose:
                print("OK" if "error" not in result else "ERROR")
            if i < total:
                time.sleep(self.REQUEST_DELAY)

        elapsed    = time.time() - start
        successful = len([v for v in self.detailed_results.values() if "error" not in v])
        print(f"\n{'='*60}")
        print(f"Completed in {elapsed:.1f}s  |  Successful: {successful}")
        if self.errors:
            print(f"Errors: {len(self.errors)}")
        print(f"{'='*60}\n")
        return self.detailed_results

    def export_json(self, output_file: str = None) -> str:
        if output_file is None:
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = str(SCRIPT_DIR / f"virustotal_detailed_analysis_{ts}.json")
        successful = len([v for v in self.detailed_results.values() if "error" not in v])
        export_data = {
            "timestamp":             datetime.now().isoformat(),
            "total_hashes_analyzed": len(self.detailed_results),
            "successful_analyses":   successful,
            "errors":                len(self.errors),
            "details":               self.detailed_results,
            "error_details":         self.errors if self.errors else None,
        }
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)
        print(f"Detailed results exported to: {output_file}\n")
        return output_file


# ─────────────────────────────────────────────────────────────
# Shared loaders
# ─────────────────────────────────────────────────────────────
def load_md5_list(input_source: str) -> List[str]:
    """Load MD5 hashes from file (sectioned or plain) or comma-separated string."""
    if Path(input_source).exists():
        cfg = parse_config_file(input_source)
        if cfg["md5s"]:
            return cfg["md5s"]
        # Fallback: plain file with no sections — already handled inside parse_config_file
        return cfg["md5s"]
    return [h.strip() for h in input_source.split(",") if h.strip()]


def load_found_hashes_from_json(json_file: str) -> List[str]:
    try:
        with open(json_file) as f:
            data = json.load(f)
        return [
            md5 for md5, result in data.get("results", {}).items()
            if isinstance(result, dict) and result.get("found") is True
        ]
    except Exception as e:
        print(f"ERROR: Failed to load hashes from JSON: {e}")
        sys.exit(1)


def load_all_hashes_from_stage1_json(json_file: str) -> List[str]:
    """Load ALL md5s from Stage 1 JSON regardless of found/not-found status."""
    try:
        with open(json_file) as f:
            data = json.load(f)
        return list(data.get("results", {}).keys())
    except Exception as e:
        print(f"ERROR: Failed to load Stage 1 JSON: {e}")
        return []


# ─────────────────────────────────────────────────────────────
# Stage 3 utilities
# ─────────────────────────────────────────────────────────────
def load_stage2(path: str) -> List[TargetFile]:
    with open(path) as f:
        data = json.load(f)
    targets = []
    for md5, entry in data.get("details", {}).items():
        if "error" in entry:
            continue
        props   = entry.get("basic_properties", {}) or {}
        names   = entry.get("names") or []
        parents = [
            p for p in (entry.get("execution_parents") or [])
            if p and p.get("name")
        ]
        targets.append(TargetFile(
            md5        = md5,
            sha256     = props.get("sha256", ""),
            sha1       = props.get("sha1", ""),
            names      = names[:MAX_ALIASES],
            file_type  = props.get("file_type", ""),
            size_bytes = props.get("size_bytes"),
            parents    = parents[:MAX_PARENTS],
        ))
    return targets


def guess_extension(target: TargetFile) -> str:
    for name in target.names:
        suffix = Path(name).suffix.lstrip(".")
        if suffix:
            return suffix
    ft = (target.file_type or "").lower()
    if "pe32" in ft or "executable" in ft: return "exe"
    if "dll"  in ft: return "dll"
    if "zip"  in ft: return "zip"
    if "pdf"  in ft: return "pdf"
    return "bin"


def ext_from_name_or_magic(name: str, data: bytes) -> str:
    """Guess extension from archive member filename, falling back to magic bytes."""
    suffix = Path(name).suffix.lstrip(".")
    if suffix:
        return suffix
    if data[:2]  == b"MZ":                   return "exe"
    if data[:4]  == b"PK\x03\x04":           return "zip"
    if data[:6]  == b"Rar!\x1a\x07":         return "rar"
    if data[:6]  == b"7z\xbc\xaf\x27\x1c":   return "7z"
    if data[:4]  == b"%PDF":                  return "pdf"
    return "bin"


def verify_hashes(data: bytes, target: TargetFile) -> bool:
    if target.md5    and hashlib.md5(data).hexdigest().lower()    == target.md5.lower():    return True
    if target.sha256 and hashlib.sha256(data).hexdigest().lower() == target.sha256.lower(): return True
    if target.sha1   and hashlib.sha1(data).hexdigest().lower()   == target.sha1.lower():   return True
    return False


def md5_of(data: bytes) -> str:
    return hashlib.md5(data).hexdigest().lower()


# ─────────────────────────────────────────────────────────────
# Downloader — 3 GB hard cap
# ─────────────────────────────────────────────────────────────
def download_file(url: str, skipped_list: List[Dict]) -> Optional[bytes]:
    """
    Download url with a 3 GB hard cap.
    Checks Content-Length before pulling a single byte.
    Streams and aborts mid-download if cap is crossed.
    """
    try:
        r = HTTP_SESSION.get(url, stream=True, timeout=30)
        if r.status_code != 200:
            return None

        cl = r.headers.get("Content-Length")
        if cl:
            cl_int = int(cl)
            if cl_int > DOWNLOAD_CAP_BYTES:
                skipped_list.append({
                    "url":                 url,
                    "reason":              "SKIPPED_DOWNLOAD_TOO_LARGE",
                    "reported_size_bytes": cl_int,
                    "actual_size_bytes":   None,
                    "cap_bytes":           DOWNLOAD_CAP_BYTES,
                })
                print(f"      ✗ Skipped — Content-Length {cl_int / 1024**3:.2f} GB exceeds 3 GB cap")
                r.close()
                return None

        buf        = io.BytesIO()
        downloaded = 0
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            downloaded += len(chunk)
            if downloaded > DOWNLOAD_CAP_BYTES:
                skipped_list.append({
                    "url":                 url,
                    "reason":              "SKIPPED_DOWNLOAD_TOO_LARGE",
                    "reported_size_bytes": int(cl) if cl else None,
                    "actual_size_bytes":   downloaded,
                    "cap_bytes":           DOWNLOAD_CAP_BYTES,
                })
                print(f"      ✗ Aborted mid-download at {downloaded / 1024**3:.2f} GB — exceeds 3 GB cap")
                r.close()
                return None
            buf.write(chunk)

        data = buf.getvalue()

        # Detect GitHub LFS pointer and resolve to real file
        if url.startswith("https://raw.githubusercontent.com/") and is_lfs_pointer(data):
            print(f"      → LFS pointer — resolving...", end=" ", flush=True)
            oid, size = parse_lfs_pointer(data)
            if oid and size:
                real_url = resolve_github_lfs(url, oid, size)
                if real_url:
                    print(f"OK", flush=True)
                    return download_file(real_url, skipped_list)
                else:
                    print(f"resolution failed", flush=True)
                    return None
            return None

        return data

    except requests.RequestException as e:
        print(f"      ✗ Download failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────
# Magic-byte archive detection
# ─────────────────────────────────────────────────────────────
MAGIC_SIGS = {
    b"PK\x03\x04":          "zip",
    b"Rar!\x1a\x07":        "rar",
    b"7z\xbc\xaf\x27\x1c":  "7z",
}


def detect_archive_type(data: bytes) -> Optional[str]:
    if HAS_MAGIC:
        try:
            mime = magic.from_buffer(data[:2048], mime=True)
            if "zip"   in mime:                        return "zip"
            if "x-rar" in mime or "vnd.rar" in mime:  return "rar"
            if "x-7z"  in mime:                        return "7z"
        except Exception:
            pass
    for sig, fmt in MAGIC_SIGS.items():
        if data[:len(sig)] == sig:
            return fmt
    return None


# ─────────────────────────────────────────────────────────────
# Archive walker — 6 layers, ZIP / RAR / 7z
# Checks every extracted member against:
#   1. Primary target hashes (returns match)
#   2. Full Stage 1 hash set (saves immediately, continues walking)
# ─────────────────────────────────────────────────────────────
def walk_archive(
    data:                 bytes,
    target:               TargetFile,
    temp_dir:             Path,
    stage1_hash_set:      set,
    stage1_extended_hits: List[Dict],
    saved_stage1:         set,
    depth:                int       = 0,
    trail:                List[str] = None,
) -> Optional[Tuple[bytes, List[str]]]:
    if trail is None:
        trail = []
    if depth >= MAX_ARCHIVE_DEPTH:
        return None

    archive_type = detect_archive_type(data)
    if not archive_type:
        return None

    layer_dir = temp_dir / f"depth_{depth}"
    layer_dir.mkdir(parents=True, exist_ok=True)

    members: List[Tuple[str, bytes]] = []

    try:
        if archive_type == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    try:
                        members.append((name, zf.read(name)))
                    except Exception:
                        continue

        elif archive_type == "rar":
            if not HAS_RAR:
                print(f"      ✗ RAR at depth {depth} — pip install rarfile (+ unrar binary)")
                return None
            tmp = layer_dir / "_temp.rar"
            tmp.write_bytes(data)
            with rarfile.RarFile(str(tmp)) as rf:
                for name in rf.namelist():
                    try:
                        members.append((name, rf.read(name)))
                    except Exception:
                        continue

        elif archive_type == "7z":
            if not HAS_7Z:
                print(f"      ✗ 7z at depth {depth} — pip install py7zr")
                return None
            tmp = layer_dir / "_temp.7z"
            tmp.write_bytes(data)
            with py7zr.SevenZipFile(str(tmp), mode="r") as zf:
                for name, bio in zf.readall().items():
                    members.append((name, bio.read()))

    except Exception as e:
        print(f"      ✗ Extraction error at depth {depth}: {e}")
        return None

    primary_result: Optional[Tuple[bytes, List[str]]] = None

    for name, member_data in members:
        if not member_data:
            continue

        current_trail = trail + [name]
        member_md5    = md5_of(member_data)

        # ── Primary target check ──
        if verify_hashes(member_data, target):
            print(f"      ✔ Primary match at depth {depth}: {' → '.join(current_trail)}")
            primary_result = (member_data, current_trail)
            # Keep walking — don't break; still want Stage 1 extended hits

        # ── Stage 1 extended scan ──
        if (
            stage1_hash_set
            and member_md5 in stage1_hash_set
            and member_md5 not in saved_stage1
            and member_md5 != target.md5.lower()   # primary target handled above
        ):
            ext = ext_from_name_or_magic(name, member_data)
            out = FOUND_DIR / f"{member_md5}.{ext}"
            FOUND_DIR.mkdir(exist_ok=True)
            out.write_bytes(member_data)
            saved_stage1.add(member_md5)
            trail_str = " → ".join(current_trail)
            stage1_extended_hits.append({
                "md5":            member_md5,
                "match_type":     "stage1_extended_match",
                "found_in_trail": trail_str,
                "depth":          depth,
                "saved_as":       str(out),
            })
            print(f"      ✔ Stage 1 extended match [{member_md5}] depth {depth}: {trail_str}")

        # ── Recurse into nested archives ──
        if depth + 1 < MAX_ARCHIVE_DEPTH:
            sub = walk_archive(
                member_data, target, temp_dir,
                stage1_hash_set, stage1_extended_hits, saved_stage1,
                depth + 1, current_trail,
            )
            if sub and primary_result is None:
                primary_result = sub

    return primary_result


# ─────────────────────────────────────────────────────────────
# Search sources
# ─────────────────────────────────────────────────────────────
def search_hybrid(hash_val: str, match_type: str, matched_on: str) -> List[SearchHit]:
    api_key = SESSION_STATE.get("hybrid_api_key")
    if not api_key:
        return []
    hits = []
    try:
        r = HTTP_SESSION.post(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            headers={
                "api-key":      api_key,
                "User-Agent":   "Falcon Sandbox",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"hash": hash_val},
            timeout=15,
        )
        if r.status_code == 200:
            for entry in (r.json() or []):
                sha = entry.get("sha256", "")
                if sha:
                    hits.append(SearchHit(
                        url        = f"https://www.hybrid-analysis.com/sample/{sha}",
                        source     = "Hybrid Analysis",
                        match_type = match_type,
                        confidence = "high",
                        matched_on = matched_on,
                    ))
    except requests.RequestException:
        pass
    time.sleep(REQUEST_DELAY)
    return hits


# ─────────────────────────────────────────────────────────────
# GitHub LFS detection and resolution
# ─────────────────────────────────────────────────────────────
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"


def is_lfs_pointer(data: bytes) -> bool:
    return data[:len(LFS_POINTER_PREFIX)] == LFS_POINTER_PREFIX


def parse_lfs_pointer(data: bytes) -> Tuple[Optional[str], Optional[int]]:
    """Parse SHA256 OID and size from an LFS pointer file."""
    oid  = None
    size = None
    for line in data.decode("utf-8", errors="ignore").splitlines():
        if line.startswith("oid sha256:"):
            oid = line.split("oid sha256:")[1].strip()
        elif line.startswith("size "):
            try:
                size = int(line.split("size ")[1].strip())
            except ValueError:
                pass
    return oid, size


def resolve_github_lfs(raw_url: str, oid: str, size: int) -> Optional[str]:
    """
    Call the GitHub LFS batch API to get the real download URL.
    Parses owner/repo from the raw.githubusercontent.com URL.
    Uses the GitHub token already in session.
    """
    token = SESSION_STATE.get("github_token", "")
    try:
        parts = raw_url.replace("https://raw.githubusercontent.com/", "").split("/")
        owner, repo = parts[0], parts[1]
    except (IndexError, AttributeError):
        return None

    try:
        r = HTTP_SESSION.post(
            f"https://github.com/{owner}/{repo}.git/info/lfs/objects/batch",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type":  "application/vnd.git-lfs+json",
                "Accept":        "application/vnd.git-lfs+json",
            },
            json={
                "operation": "download",
                "transfers": ["basic"],
                "objects":   [{"oid": oid, "size": size}],
            },
            timeout=15,
        )
        if r.status_code == 200:
            objects = r.json().get("objects", [])
            if objects:
                return objects[0].get("actions", {}).get("download", {}).get("href")
    except requests.RequestException:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# Source: Internet Archive Collections API
# ─────────────────────────────────────────────────────────────
def search_archive_collections(filename: str, match_type: str) -> List[SearchHit]:
    """
    Search Internet Archive directly within No-Intro, Redump, TOSEC,
    and software collections — not via CDX crawl index.
    """
    hits = []
    try:
        r = HTTP_SESSION.get(
            "https://archive.org/advancedsearch.php",
            params={
                "q":      (
                    f'"{filename}" AND ('
                    f'collection:No-Intro OR collection:Redump OR '
                    f'collection:TOSEC OR mediatype:software)'
                ),
                "fl[]":   "identifier",
                "output": "json",
                "rows":   5,
            },
            timeout=20,
        )
        if r.status_code == 200:
            docs = r.json().get("response", {}).get("docs", [])
            for doc in docs:
                identifier = doc.get("identifier", "")
                if identifier:
                    hits.append(SearchHit(
                        url        = f"https://archive.org/download/{identifier}/{filename}",
                        source     = "Internet Archive",
                        match_type = match_type,
                        confidence = "medium",
                        matched_on = filename,
                    ))
    except requests.RequestException as e:
        print(f" error: {e}", flush=True)
    time.sleep(REQUEST_DELAY)
    return hits


# ─────────────────────────────────────────────────────────────
# Source: Hugging Face datasets
# ─────────────────────────────────────────────────────────────
def search_huggingface(filename: str, match_type: str) -> List[SearchHit]:
    hits = []
    try:
        r = HTTP_SESSION.get(
            "https://huggingface.co/api/datasets",
            params={"search": filename, "limit": 5},
            timeout=15,
        )
        if r.status_code == 200:
            for dataset in r.json():
                dataset_id = dataset.get("id", "")
                if dataset_id:
                    hits.append(SearchHit(
                        url        = f"https://huggingface.co/datasets/{dataset_id}/resolve/main/{filename}",
                        source     = "Hugging Face",
                        match_type = match_type,
                        confidence = "medium",
                        matched_on = filename,
                    ))
    except requests.RequestException:
        pass
    time.sleep(REQUEST_DELAY)
    return hits


def search_github(query: str, match_type: str) -> List[SearchHit]:
    token = SESSION_STATE.get("github_token")
    if not token:
        return []
    hits = []
    try:
        r = HTTP_SESSION.get(
            "https://api.github.com/search/code",
            headers={
                "Authorization": f"token {token}",
                "Accept":        "application/vnd.github.v3+json",
            },
            params={"q": query, "per_page": 5},
            timeout=15,
        )
        if r.status_code == 200:
            for item in r.json().get("items", []):
                raw = (
                    item.get("html_url", "")
                    .replace("github.com", "raw.githubusercontent.com")
                    .replace("/blob/", "/")
                )
                if is_github_blocklisted(raw):
                    continue
                hits.append(SearchHit(
                    url        = raw,
                    source     = "GitHub",
                    match_type = match_type,
                    confidence = "low",
                    matched_on = query,
                ))
        elif r.status_code == 403:
            print("      ✗ GitHub rate limit — pausing 60s")
            time.sleep(60)
    except requests.RequestException:
        pass
    time.sleep(REQUEST_DELAY)
    return hits


# ─────────────────────────────────────────────────────────────
# Download + verify a single candidate hit
# ─────────────────────────────────────────────────────────────
def attempt_verify(
    hit:                  SearchHit,
    target:               TargetFile,
    temp_dir:             Path,
    skipped_list:         List[Dict],
    stage1_hash_set:      set,
    stage1_extended_hits: List[Dict],
    saved_stage1:         set,
) -> Tuple[bool, Optional[bytes], Optional[List[str]]]:
    data = download_file(hit.url, skipped_list)
    if not data:
        return False, None, None

    if verify_hashes(data, target):
        return True, data, None

    result = walk_archive(
        data, target, temp_dir,
        stage1_hash_set, stage1_extended_hits, saved_stage1,
    )
    if result:
        return True, result[0], result[1]

    return False, None, None


# ─────────────────────────────────────────────────────────────
# Process one primary target
# ─────────────────────────────────────────────────────────────
def process_target(
    target:          TargetFile,
    seen_hashes:     set,
    seen_names:      set,
    stage1_hash_set: set,
    saved_stage1:    set,
    index:           int,
    total:           int,
) -> PrimaryResult:

    result   = PrimaryResult(target=target)
    ext      = guess_extension(target)
    temp_dir = TEMP_BASE / target.md5
    temp_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'─'*60}")
    print(f"[{index}/{total}] {target.md5}")
    print(f"  SHA256  : {target.sha256 or 'N/A'}")
    print(f"  Names   : {', '.join(target.names[:3]) or 'N/A'}")
    print(f"  Parents : {len(target.parents)}")

    all_hits: List[SearchHit] = []

    # ── Phase 2: Hash searches ──────────────────────────────
    print("\n  [Phase 2] Hash searches")

    for hash_val in [target.sha256, target.md5]:
        if hash_val and hash_val not in seen_hashes:
            seen_hashes.add(hash_val)
            label = "sha256" if len(hash_val) == 64 else "md5"
            print(f"    Hybrid ← primary {label}: {hash_val[:16]}...", end=" ", flush=True)
            h = search_hybrid(hash_val, "direct_hash", hash_val)
            print(f"{len(h)} hit(s)")
            all_hits.extend(h)

    for parent in target.parents:
        sha   = parent.get("sha256", "")
        pname = parent.get("name", "unknown")
        if sha and sha not in seen_hashes:
            seen_hashes.add(sha)
            print(f"    Hybrid ← parent [{pname[:28]}]: {sha[:16]}...", end=" ", flush=True)
            h = search_hybrid(sha, "parent_hash", sha)
            print(f"{len(h)} hit(s)")
            all_hits.extend(h)

    # ── Phase 3: Name searches ──────────────────────────────
    print("\n  [Phase 3] Name searches")

    # Priority: primary name → parent names → aliases
    name_queue: List[Tuple[str, str]] = []
    if target.names:
        if target.names[0] not in seen_names:
            name_queue.append(("direct_name", target.names[0]))
    for parent in target.parents:
        pname = parent.get("name", "")
        if pname and pname not in seen_names:
            name_queue.append(("parent_name", pname))
    for alias in target.names[1:]:
        if alias and alias not in seen_names:
            name_queue.append(("alias_name", alias))

    for match_type, name in name_queue:
        seen_names.add(name)
        print(f"\n    [{match_type}] {name}")

        print(f"      Archive.org  ...", end=" ", flush=True)
        h = search_archive_collections(name, match_type)
        print(f"{len(h)} hit(s)")
        all_hits.extend(h)

        print(f"      Hugging Face ...", end=" ", flush=True)
        h = search_huggingface(name, match_type)
        print(f"{len(h)} hit(s)")
        all_hits.extend(h)

        print(f"      GitHub       ...", end=" ", flush=True)
        h = search_github(name, match_type)
        print(f"{len(h)} hit(s)")
        all_hits.extend(h)

        if SESSION_STATE.get("known_binaries"):
            h = search_github_contents(name, match_type)
            if h:
                print(f"      Contents API ... {len(h)} hit(s)")
                all_hits.extend(h)

    # ── Phase 4: Download & verify ──────────────────────────
    print(f"\n  [Phase 4] Verifying {len(all_hits)} candidate(s)")

    for hit in all_hits:
        if result.found:
            result.unresolved.append(hit)
            continue

        print(f"    ↓ [{hit.match_type}] {hit.source}: {hit.url[:65]}")
        verified, file_bytes, trail = attempt_verify(
            hit, target, temp_dir,
            result.skipped_downloads,
            stage1_hash_set, result.stage1_extended, saved_stage1,
        )

        if verified:
            hit.verified = True
            FOUND_DIR.mkdir(exist_ok=True)
            out_path = FOUND_DIR / f"{target.md5}.{ext}"
            out_path.write_bytes(file_bytes)
            result.saved_path = str(out_path)
            result.found      = True

            if trail:
                hit.matched_on += f" → extracted: {' → '.join(trail)}"
                result.parent_hits.append(hit)
            elif hit.match_type in ("direct_hash", "direct_name"):
                result.direct_hits.append(hit)
            else:
                result.parent_hits.append(hit)

            print(f"    ✔ VERIFIED — saved as {out_path.name}")
        else:
            result.unresolved.append(hit)

    # ── Cleanup temp for this primary ──────────────────────
    try:
        shutil.rmtree(temp_dir)
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────────
# Stage 3 summary + report
# ─────────────────────────────────────────────────────────────
def print_stage3_summary(results: List[PrimaryResult]):
    print(f"\n{'='*60}")
    print(f"{'STAGE 3 SUMMARY':^60}")
    print(f"{'='*60}")
    print(f"{'MD5':<34} {'Status':<12} Source / Note")
    print(f"{'─'*60}")
    for r in results:
        if r.found:
            hits   = r.direct_hits + r.parent_hits
            source = hits[0].source if hits else "unknown"
            status = "FOUND"
        else:
            source = f"{len(r.unresolved)} unresolved"
            status = "NOT FOUND"
        print(f"{r.target.md5:<34} {status:<12} {source}")

    found_count    = sum(1 for r in results if r.found)
    skipped_count  = sum(len(r.skipped_downloads) for r in results)
    extended_count = sum(len(r.stage1_extended)   for r in results)
    print(f"{'─'*60}")
    print(f"Primary targets found    : {found_count}/{len(results)}")
    print(f"Stage 1 extended matches : {extended_count} additional file(s) recovered")
    print(f"Downloads skipped (>3 GB): {skipped_count}")
    print(f"{'='*60}")


def export_stage3_report(results: List[PrimaryResult]) -> str:
    def hit_dict(h: SearchHit) -> dict:
        return {
            "url":        h.url,
            "source":     h.source,
            "match_type": h.match_type,
            "confidence": h.confidence,
            "matched_on": h.matched_on,
            "verified":   h.verified,
        }

    report = {
        "timestamp":             datetime.now().isoformat(),
        "total_primaries":       len(results),
        "found":                 sum(1 for r in results if r.found),
        "not_found":             sum(1 for r in results if not r.found),
        "stage1_extended_total": sum(len(r.stage1_extended) for r in results),
        "results": [
            {
                "md5":                   r.target.md5,
                "sha256":                r.target.sha256,
                "names":                 r.target.names,
                "found":                 r.found,
                "saved_path":            r.saved_path,
                "direct_hits":           [hit_dict(h) for h in r.direct_hits],
                "parent_hits":           [hit_dict(h) for h in r.parent_hits],
                "stage1_extended_hits":  r.stage1_extended,
                "unresolved_candidates": [hit_dict(h) for h in r.unresolved],
                "skipped_downloads":     r.skipped_downloads,
            }
            for r in results
        ],
    }

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = str(SCRIPT_DIR / f"stage3_report_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {out_file}")
    return out_file


# ─────────────────────────────────────────────────────────────
# Stage runners
# ─────────────────────────────────────────────────────────────
def stage1_search():
    # Use hashes already loaded from config if available
    if SESSION_STATE["md5_hashes"]:
        print(f"\nUsing {len(SESSION_STATE['md5_hashes'])} hash(es) from config.")
        md5_list = SESSION_STATE["md5_hashes"]
    else:
        print("\nEnter MD5 hashes to search:")
        print("  - Path to config/MD5 file, OR")
        print("  - Comma-separated MD5 values")
        input_source = input("\nInput: ").strip()
        if not input_source:
            print("ERROR: No input provided.")
            return
        if Path(input_source).exists():
            load_config_into_session(input_source)
        if not SESSION_STATE["vt_api_key"]:
            SESSION_STATE["vt_api_key"] = input("VirusTotal API key: ").strip()
        try:
            md5_list = load_md5_list(input_source)
        except Exception as e:
            print(f"ERROR: {e}")
            return

    valid_hashes = [
        h for h in md5_list
        if len(h) == 32 and all(c in "0123456789abcdefABCDEF" for c in h)
    ]
    skipped = len(md5_list) - len(valid_hashes)
    if skipped:
        print(f"WARNING: Skipped {skipped} invalid MD5 format(s)")
    if not valid_hashes:
        print("ERROR: No valid MD5 hashes to search.")
        return

    # Store full list in session for Stage 3 extended scan
    SESSION_STATE["md5_hashes"] = valid_hashes
    print(f"\nLoaded {len(valid_hashes)} valid MD5 hash(es)")

    searcher = VirusTotalBatchSearcher(SESSION_STATE["vt_api_key"])
    searcher.search_batch(valid_hashes)
    SESSION_STATE["stage1_results"] = searcher.results

    out = searcher.export_json()
    SESSION_STATE["stage1_json_path"] = out

    found_count = len([v for v in searcher.results.values() if v.get("found") is True])
    if found_count > 0:
        cont = input(f"\n{found_count} hash(es) found. Continue to Stage 2? (y/N): ").strip().lower()
        if cont == "y":
            stage2_analyze()


def stage2_analyze():
    # Use session if Stage 1 already ran, otherwise prompt
    if SESSION_STATE["stage1_results"]:
        found_hashes = [
            md5 for md5, r in SESSION_STATE["stage1_results"].items()
            if r.get("found") is True
        ]
        print(f"\nUsing {len(found_hashes)} found hash(es) from current session.")
    else:
        json_file = input("\nPath to Stage 1 JSON output file: ").strip()
        if not json_file or not Path(json_file).exists():
            print("ERROR: File not found.")
            return
        found_hashes = load_found_hashes_from_json(json_file)
        # Load all hashes into session for Stage 3 extended scan
        SESSION_STATE["md5_hashes"]       = load_all_hashes_from_stage1_json(json_file)
        SESSION_STATE["stage1_json_path"] = json_file

    if not found_hashes:
        print("ERROR: No hashes marked as found.")
        return

    analyzer = VirusTotalDetailedAnalyzer(SESSION_STATE["vt_api_key"])
    analyzer.analyze_batch(found_hashes)
    SESSION_STATE["stage2_results"] = analyzer.detailed_results

    out = analyzer.export_json()
    SESSION_STATE["stage2_json_path"] = out

    successful = len([v for v in analyzer.detailed_results.values() if "error" not in v])
    if successful > 0:
        cont = input(f"\n{successful} hash(es) analyzed. Continue to Stage 3? (y/N): ").strip().lower()
        if cont == "y":
            stage3_hunt()


def stage3_hunt():
    # ── Credentials ───────────────────────────────────────
    if not SESSION_STATE["github_token"]:
        while True:
            token = input("\nGitHub token (required): ").strip()
            if token:
                SESSION_STATE["github_token"] = token
                break
            print("  GitHub token is required.")
    else:
        print(f"\nGitHub token       : loaded from config")

    if SESSION_STATE["hybrid_api_key"] is None:
        key = input("Hybrid Analysis API key (optional, Enter to skip): ").strip()
        SESSION_STATE["hybrid_api_key"] = key or ""
        print(f"  {'✔ Hybrid Analysis enabled' if key else '⚠ Hybrid Analysis skipped'}")
    else:
        status = "enabled" if SESSION_STATE["hybrid_api_key"] else "skipped"
        print(f"Hybrid Analysis API: loaded from config ({status})")

    # ── Report blocklist / known_binaries ─────────────────
    if SESSION_STATE["blocklist"]:
        print(f"Blocklist          : {len(SESSION_STATE['blocklist'])} repo(s)")
    if SESSION_STATE["known_binaries"]:
        print(f"Known binaries     : {len(SESSION_STATE['known_binaries'])} repo(s)")

    # ── Stage 2 JSON ──────────────────────────────────────
    if SESSION_STATE["stage2_json_path"]:
        stage2_path = SESSION_STATE["stage2_json_path"]
        print(f"\nUsing Stage 2 JSON from session: {stage2_path}")
    else:
        stage2_path = input("\nPath to Stage 2 JSON: ").strip()
        if not stage2_path or not Path(stage2_path).exists():
            print("ERROR: File not found.")
            return
        SESSION_STATE["stage2_json_path"] = stage2_path

    targets = load_stage2(stage2_path)
    if not targets:
        print("ERROR: No valid entries in Stage 2 JSON.")
        return

    # ── Stage 1 hash set for extended scanning ────────────
    if SESSION_STATE["md5_hashes"]:
        stage1_hashes = set(h.lower() for h in SESSION_STATE["md5_hashes"])
        print(f"Stage 1 extended scan: {len(stage1_hashes)} hash(es) from session")
    else:
        s1_input = input("Path to Stage 1 hash list or JSON (Enter to skip): ").strip()
        stage1_hashes = set()
        if s1_input and Path(s1_input).exists():
            if s1_input.endswith(".json"):
                hashes = load_all_hashes_from_stage1_json(s1_input)
            else:
                hashes = load_md5_list(s1_input)
            stage1_hashes = set(h.lower() for h in hashes)
            print(f"Stage 1 extended scan: {len(stage1_hashes)} hash(es) loaded")
        else:
            print("Stage 1 extended scan: skipped")

    # ── Dependency check ──────────────────────────────────
    print("\nDependency check:")
    print(f"  python-magic : {'✔' if HAS_MAGIC else '✗  pip install python-magic'}")
    print(f"  rarfile      : {'✔' if HAS_RAR   else '✗  pip install rarfile (+ unrar binary)'}")
    print(f"  py7zr        : {'✔' if HAS_7Z    else '✗  pip install py7zr'}")

    print(f"\nLoaded {len(targets)} primary target(s)")
    print(f"  Total aliases : {sum(len(t.names)   for t in targets)}")
    print(f"  Total parents : {sum(len(t.parents) for t in targets)}")

    # ── Run ───────────────────────────────────────────────
    if TEMP_BASE.exists():
        shutil.rmtree(TEMP_BASE)
    TEMP_BASE.mkdir()

    seen_hashes:  set = set()
    seen_names:   set = set()
    saved_stage1: set = set()   # prevents duplicate Stage 1 saves
    results:      List[PrimaryResult] = []
    start = datetime.now()

    for i, target in enumerate(targets, 1):
        r = process_target(
            target, seen_hashes, seen_names,
            stage1_hashes, saved_stage1,
            i, len(targets),
        )
        results.append(r)

    try:
        shutil.rmtree(TEMP_BASE)
    except Exception:
        pass

    elapsed = int((datetime.now() - start).total_seconds())
    print(f"\nCompleted in {elapsed}s")
    print_stage3_summary(results)
    export_stage3_report(results)


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print("  VirusTotal MD5 Batch Search & File Hunter")
    print("=" * 60 + "\n")

    auto_load_config()

    print("Choose operation:")
    print("  1 - Stage 1: Search for MD5 hashes")
    print("  2 - Stage 2: Detailed analysis of found hashes")
    print("  3 - Stage 3: File Hunter")
    choice = input("\nSelect (1 / 2 / 3): ").strip()

    if choice in ("1", "2"):
        if not SESSION_STATE["vt_api_key"]:
            api_key = input("\nVirusTotal API key: ").strip()
            if not api_key:
                print("ERROR: VirusTotal API key is required for Stages 1 and 2.")
                sys.exit(1)
            SESSION_STATE["vt_api_key"] = api_key

    if choice == "1":
        stage1_search()
    elif choice == "2":
        stage2_analyze()
    elif choice == "3":
        stage3_hunt()
    else:
        print("ERROR: Invalid choice.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        try:
            shutil.rmtree(TEMP_BASE)
        except Exception:
            pass
        sys.exit(0)
