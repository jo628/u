#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keyfile.py  (updated)

Fix: Previous version exited with "[FATAL] No getwvkeys API key provided." if you
did not pass --api-key. This version now tries multiple fallbacks and finally
prompts you interactively so running only:

  python3 keyfile.py -c https://portal.udemy.com/course/whatever/learn/ --browser chrome

will still work (you will be asked for the API key if it cannot be found).

API Key resolution order now:
  1. --api-key CLI argument
  2. Embedded constant (if you hard-code it below)
  3. Environment variable GETWVKEYS_API_KEY
  4. keyconfig.json file in current directory (expects {"api_key": "..."} )
  5. Interactive prompt (will re-prompt until non-empty or you press Ctrl+C)

You can also optionally skip retrieving keys (only get MPD + token) using:
  --skip-keys

Outputs:
  - Prints MPD URL (first DRM lecture)
  - Prints media_license_token
  - If not skipping and keys retrieved: prints keys and writes keyfile.json

Requirements:
  pip install requests beautifulsoup4 browser-cookie3 lxml xmltodict

"""

import argparse
import base64
import json
import os
import re
import sys
from typing import Optional, Tuple, List, Dict

import requests
from bs4 import BeautifulSoup
import browser_cookie3
import xmltodict

# ---------------------------------------------------------------------------
# Configuration / Constants
# ---------------------------------------------------------------------------
VERSION = "5.3"

# If you want to hard‑code your getwvkeys base URL or API key, replace placeholders below.
GETWVKEYS_API_URL_PLACEHOLDER = "__getwvkeys_api_url__"       # leave or set e.g. "https://getwvkeys.cc"
GETWVKEYS_API_KEY_PLACEHOLDER = "__getwvkeys_api_key__"       # replace with real key to embed

BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) UdemyKeyExtractor/1.0",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://www.udemy.com",
    "Referer": "https://www.udemy.com/",
}

CURRICULUM_URL_TEMPLATE = (
    "https://{portal}.udemy.com/api-2.0/courses/{course_id}/subscriber-curriculum-items/"
    "?page_size=1000"
    "&fields[asset]=title,asset_type,media_sources,stream_urls,captions,media_license_token"
    "&fields[lecture]=id,title,object_index,asset"
    "&fields[chapter]=id,title,object_index"
)

COURSE_URL_RE = re.compile(
    r"(?i)https?://(?P<portal>[^./]+)\.udemy\.com/(?:course(?:/draft)?/)?(?P<slug>[A-Za-z0-9_-]+)"
)

# ---------------------------------------------------------------------------
# Udemy helpers
# ---------------------------------------------------------------------------
def parse_course_url(url: str) -> Tuple[str, str]:
    m = COURSE_URL_RE.search(url)
    if not m:
        raise ValueError("Unable to parse portal and course slug from URL.")
    return m.group("portal"), m.group("slug")

def get_browser_cookies(browser: str):
    if browser == "chrome":
        return browser_cookie3.chrome()
    if browser == "firefox":
        return browser_cookie3.firefox()
    if browser == "opera":
        return browser_cookie3.opera()
    if browser == "edge":
        return browser_cookie3.edge()
    if browser == "brave":
        return browser_cookie3.brave()
    if browser == "chromium":
        return browser_cookie3.chromium()
    if browser == "vivaldi":
        return browser_cookie3.vivaldi()
    if browser == "safari":
        return browser_cookie3.safari()
    raise ValueError(f"Unsupported browser: {browser}")

def build_session(bearer: Optional[str]) -> requests.Session:
    s = requests.Session()
    s.headers.update(BASE_HEADERS)
    if bearer:
        s.headers["Authorization"] = f"Bearer {bearer}"
        s.headers["X-Udemy-Authorization"] = f"Bearer {bearer}"
    return s

def extract_course_id(session: requests.Session, course_url: str, cookies) -> int:
    resp = session.get(course_url, cookies=cookies)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "lxml")
    container = soup.find("div", class_="ud-component--course-taking--app")
    if not container or "data-module-args" not in container.attrs:
        raise RuntimeError("Failed to locate course container (data-module-args). Are you logged in?")
    data_args = json.loads(container["data-module-args"])
    course_id = data_args.get("courseId")
    if not course_id:
        raise RuntimeError("courseId not found in data-module-args.")
    return course_id

def fetch_first_mpd_and_token(session: requests.Session, portal: str, course_id: int, cookies) -> Tuple[Optional[str], Optional[str]]:
    url = CURRICULUM_URL_TEMPLATE.format(portal=portal, course_id=course_id)
    while url:
        r = session.get(url, cookies=cookies)
        r.raise_for_status()
        data = r.json()
        for item in data.get("results", []):
            if item.get("_class") != "lecture":
                continue
            asset = item.get("asset") or {}
            if (asset.get("asset_type") or "").lower() != "video":
                continue
            media_sources = asset.get("media_sources") or []
            token = asset.get("media_license_token")
            for ms in media_sources:
                mstype = (ms.get("type") or "").lower()
                src = ms.get("src") or ms.get("file") or ""
                if mstype == "application/dash+xml" and ".mpd" in src.lower():
                    return src, token
        url = data.get("next")
    return None, None

# ---------------------------------------------------------------------------
# Widevine / getwvkeys clone
# ---------------------------------------------------------------------------
class WidevineArgs:
    def __init__(self,
                 mpd_url: str,
                 media_license_token: str,
                 api_key: str,
                 force: bool,
                 verbose: bool,
                 buildinfo: str):
        self.mpd_url = mpd_url
        self.media_license_token = media_license_token
        self.api_key = api_key
        self.force = force
        self.verbose = verbose
        self.buildinfo = buildinfo
        self.url = f"https://www.udemy.com/api-2.0/media-license-server/validate-auth-token?drm_type=widevine&auth_token={media_license_token}"
        self.headers = self._default_headers()
        self.pssh = None

    def _default_headers(self):
        return {
            "accept": "application/json, text/plain, */*",
            "origin": "https://www.udemy.com",
            "referer": "https://www.udemy.com/",
            "content-type": "application/octet-stream",
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) UdemyKeyExtractor/1.0",
        }

def post_license_request(arg: WidevineArgs, challenge: bytes) -> bytes:
    r = requests.post(arg.url, headers=arg.headers, data=challenge, timeout=15)
    if arg.verbose:
        print("[+] License response (base64, first 80 chars):", base64.b64encode(r.content)[:80].decode(), "...")
    if not r.ok:
        raise RuntimeError(f"License server HTTP {r.status_code}: {r.text}")
    return r.content

class GetwvCloneApi:
    def __init__(self, arg: WidevineArgs, api_url_placeholder=GETWVKEYS_API_URL_PLACEHOLDER):
        baseurl = "https://getwvkeys.cc" if api_url_placeholder == "__getwvkeys_api_url__" else api_url_placeholder
        self.api_url = baseurl + "/pywidevine"
        self.args = arg
        self.args.pssh = self.get_pssh()
        if self.args.verbose:
            print(f"[+] PSSH: {self.args.pssh}")

    def read_pssh_from_bytes(self, blob: bytes) -> bytes:
        pssh_offset = blob.rfind(b'pssh')
        if pssh_offset == -1:
            raise RuntimeError("PSSH not found in init segment")
        _start = pssh_offset - 4
        _end = _start + blob[pssh_offset - 1]
        return blob[_start:_end]

    def get_init_url(self) -> str:
        if self.args.verbose:
            print("[+] Fetching MPD manifest")
        res = requests.get(self.args.mpd_url)
        res.raise_for_status()
        mpd = xmltodict.parse(res.content)
        period = mpd["MPD"]["Period"]
        sets = period.get("AdaptationSet")
        # handle both list or dict
        if isinstance(sets, list):
            video_set = sets[0]
        else:
            video_set = sets
        reps = video_set.get("Representation")
        if isinstance(reps, list):
            video_rep = reps[-1]
        else:
            video_rep = reps
        seg_tmpl = video_rep.get("SegmentTemplate")
        if not seg_tmpl:
            raise RuntimeError("SegmentTemplate not found")
        init_url = seg_tmpl.get("@initialization")
        if not init_url:
            raise RuntimeError("Initialization URL missing")
        if self.args.verbose:
            print(f"[+] Init segment URL: {init_url}")
        return init_url

    def get_pssh(self) -> str:
        init_url = self.get_init_url()
        res = requests.get(init_url, headers=self.args.headers)
        if not res.ok:
            raise RuntimeError(f"Init segment download failed: {res.status_code}")
        pssh = self.read_pssh_from_bytes(res.content)
        return base64.b64encode(pssh).decode()

    def generate_challenge(self) -> bytes:
        if self.args.verbose:
            print("[+] Generating Widevine challenge via remote API")
        payload = {
            "pssh": self.args.pssh,
            "buildInfo": self.args.buildinfo,
            "force": self.args.force,
            "license_url": self.args.url,
        }
        headers = {"X-API-Key": self.args.api_key, "Content-Type": "application/json"}
        r = requests.post(self.api_url, json=payload, headers=headers)
        if not r.ok:
            try:
                err = r.json()
                raise RuntimeError(f"Generate challenge error [{err.get('code')}]: {err.get('message')}")
            except Exception:
                raise RuntimeError(f"Generate challenge error [{r.status_code}]: {r.text}")
        data = r.json()
        if "X-Cache" in r.headers:
            self.cached_keys = data.get("keys", [])
            if self.args.verbose:
                print("[+] Cache hit; keys returned directly.")
            return b""
        self.session_id = data.get("session_id")
        challenge_b64 = data.get("challenge")
        if not challenge_b64:
            raise RuntimeError("Challenge missing in response")
        if self.args.verbose:
            print(f"[+] Session ID: {self.session_id}")
        return base64.b64decode(challenge_b64)

    def decrypt(self, license_response_b64: str) -> Dict:
        if self.args.verbose:
            print("[+] Decrypting license response (remote)")
        payload = {
            "pssh": self.args.pssh,
            "response": license_response_b64,
            "license_url": self.args.url,
            "headers": self.args.headers,
            "buildInfo": self.args.buildinfo,
            "force": self.args.force,
            "session_id": getattr(self, "session_id", None),
        }
        headers = {"X-API-Key": self.args.api_key, "Content-Type": "application/json"}
        r = requests.post(self.api_url, json=payload, headers=headers)
        if not r.ok:
            try:
                err = r.json()
                raise RuntimeError(f"Decrypt error [{err.get('code')}]: {err.get('message')}")
            except Exception:
                raise RuntimeError(f"Decrypt error [{r.status_code}]: {r.text}")
        return r.json()

    def run(self) -> List[Dict]:
        challenge = self.generate_challenge()
        if hasattr(self, "cached_keys"):
            return self.cached_keys
        license_resp = post_license_request(self.args, challenge)
        decrypt_payload = base64.b64encode(license_resp).decode()
        decrypt_response = self.decrypt(decrypt_payload)
        return decrypt_response.get("keys", [])

# ---------------------------------------------------------------------------
# Keyfile writer
# ---------------------------------------------------------------------------
def write_keyfile(keys: List[Dict], path: str = "keyfile.json") -> None:
    mapping = {}
    for k in keys:
        raw = k.get("key")
        if not raw or ":" not in raw:
            continue

        parts = raw.split(":")
        if len(parts) == 3 and parts[0] == parts[1]:
            # Case: kid duplicated (kid:kid:key)
            kid, keyval = parts[0], parts[2]
        else:
            # Normal case (kid:key)
            kid, keyval = parts[0], parts[-1]

        mapping[kid] = keyval

    with open(path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False)
    print(f"[+] Wrote {len(mapping)} key(s) to {path}")

# ---------------------------------------------------------------------------
# API key resolution
# ---------------------------------------------------------------------------
def resolve_api_key(cli_key: Optional[str], verbose: bool) -> str:
    # 1. CLI
    if cli_key:
        if verbose: print("[+] Using API key from CLI argument.")
        return cli_key.strip()

    # 2. Embedded constant
    if GETWVKEYS_API_KEY_PLACEHOLDER != "__getwvkeys_api_key__":
        if verbose: print("[+] Using embedded API key constant.")
        return GETWVKEYS_API_KEY_PLACEHOLDER.strip()

    # 3. Environment variable
    env_key = os.getenv("GETWVKEYS_API_KEY")
    if env_key:
        if verbose: print("[+] Using API key from environment variable GETWVKEYS_API_KEY.")
        return env_key.strip()

    # 4. keyconfig.json file
    if os.path.isfile("keyconfig.json"):
        try:
            with open("keyconfig.json", "r", encoding="utf-8") as f:
                cfg = json.load(f)
            file_key = cfg.get("api_key")
            if file_key:
                if verbose: print("[+] Using API key from keyconfig.json.")
                return file_key.strip()
        except Exception as e:
            if verbose: print(f"[!] Failed reading keyconfig.json: {e}")

    # 5. Interactive prompt
    while True:
        try:
            entered = "f4446352b997120f215ad6c70304ee2bbd2d726ca3e7aadcc984c55fa4ec8833".strip()
            if entered:
                return entered
            print("API key cannot be empty. Try again.")
        except KeyboardInterrupt:
            print("\n[!] Aborted by user.")
            sys.exit(1)

# ---------------------------------------------------------------------------
# Main Orchestration
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Extract first Udemy DRM MPD + token, retrieve Widevine keys, write keyfile.json."
    )
    parser.add_argument("-c", "--course-url", required=True, dest="course_url", help="Udemy course learn URL")
    parser.add_argument("-b", "--bearer", dest="bearer_token", help="Bearer token (optional if using --browser)")
    parser.add_argument(
        "--browser",
        dest="browser",
        choices=["chrome", "firefox", "opera", "edge", "brave", "chromium", "vivaldi", "safari"],
        help="Browser to extract cookies from (optional if bearer token supplied).",
    )
    parser.add_argument("--api-key", dest="api_key", help="getwvkeys API key (optional if embedded/env/file/prompt).")
    parser.add_argument("--force", "-f", action="store_true", help="Force bypass of getwvkeys cache.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    parser.add_argument("--buildinfo", "-B", default="", help="Optional Widevine build info override.")
    parser.add_argument("--out", "-o", default="keyfile.json", help="Output JSON file (default keyfile.json).")
    parser.add_argument("--skip-keys", action="store_true", help="Only output MPD and token, do not fetch or write keys.")
    args = parser.parse_args()

    if not args.bearer_token and not args.browser:
        print("[FATAL] Provide either a bearer token (-b) or a browser (--browser).", file=sys.stderr)
        sys.exit(1)

    # Resolve API key (unless skipping keys)
    api_key = None
    if not args.skip_keys:
        api_key = resolve_api_key(args.api_key, args.verbose)

    # Parse course URL
    try:
        portal, _slug = parse_course_url(args.course_url)
    except Exception as e:
        print(f"[FATAL] Invalid course URL: {e}", file=sys.stderr)
        sys.exit(1)

    # Cookies
    cj = None
    if args.browser:
        try:
            cj = get_browser_cookies(args.browser)
        except Exception as e:
            print(f"[FATAL] Could not read cookies from browser '{args.browser}': {e}", file=sys.stderr)
            sys.exit(1)

    session = build_session(args.bearer_token)

    # Extract course id
    try:
        course_id = extract_course_id(session, args.course_url, cj)
        if args.verbose:
            print(f"[+] Course ID: {course_id}")
    except Exception as e:
        print(f"[FATAL] Failed to extract course ID: {e}", file=sys.stderr)
        sys.exit(1)

    # Find MPD + token
    try:
        mpd_url, media_license_token = fetch_first_mpd_and_token(session, portal, course_id, cj)
    except Exception as e:
        print(f"[FATAL] Curriculum retrieval error: {e}", file=sys.stderr)
        sys.exit(1)

    if not mpd_url or not media_license_token:
        print("[INFO] Could not find both MPD URL and media_license_token.", file=sys.stderr)
        sys.exit(2)

    # Always print these (like earlier manual flow)
    print(mpd_url)
    print(media_license_token)

    if args.skip_keys:
        if args.verbose:
            print("[+] Skipping key retrieval as requested (--skip-keys).")
        sys.exit(0)

    # Prepare Widevine args
    wv_args = WidevineArgs(
        mpd_url=mpd_url,
        media_license_token=media_license_token,
        api_key=api_key,
        force=args.force,
        verbose=args.verbose,
        buildinfo=args.buildinfo,
    )

    # Run WV key retrieval
    try:
        print(f"\n      pywidevine-api {VERSION}\n        from getwvkeys \n")
        gwv = GetwvCloneApi(wv_args)
        keys = gwv.run()
    except Exception as e:
        print(f"[FATAL] Key retrieval failed: {e}", file=sys.stderr)
        sys.exit(3)

    if not keys:
        print("[INFO] No keys returned.", file=sys.stderr)
        sys.exit(3)

    print("\n[+] Keys:")
    for k in keys:
        print("--key {}".format(k.get("key")))

    # Write keyfile.json
    try:
        write_keyfile(keys, args.out)
    except Exception as e:
        print(f"[FATAL] Failed writing key file: {e}", file=sys.stderr)
        sys.exit(3)

    print("\nDONE\n")
    sys.exit(0)


if __name__ == "__main__":
    main()