"""A snapshot: every feed response on disk, listed in manifest.json with its URL,
fetch time, HTTP status, size and SHA-256.

Online (fetch), a response not yet in the snapshot is downloaded. Offline
(build), every response must be in the manifest and match its hash, so a build
reads only what the manifest records and a rerun gives the same bytes.
"""

import datetime
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "phpfixed-sync/0.1"
# Extra User-Agent text per host, only for feeds whose terms ask for
# identification (owner's answer 8). None of the five feeds does.
CONTACT = {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Snapshot:
    def __init__(self, path, online=False):
        self.path, self.online, self._last = path, online, 0.0
        manifest = os.path.join(path, "manifest.json")
        if os.path.exists(manifest):
            with open(manifest) as fh:
                self.manifest = json.load(fh)
        elif online:
            self.manifest = {"created": _now(), "entries": {}}
        else:
            raise FileNotFoundError(manifest)
        self.date = self.manifest["created"][:10]

    def get(self, url, body=None):
        """The response bytes, or None when the feed did not answer 200."""
        key = url if body is None else f"{url} {body}"
        e = self.manifest["entries"].get(key)
        if e is None:
            if not self.online:
                raise KeyError(f"not in the snapshot: {key}")
            e = self.manifest["entries"][key] = self._fetch(key, url, body)
        if e["status"] != 200:
            return None
        with open(os.path.join(self.path, e["file"]), "rb") as fh:
            data = fh.read()
        if hashlib.sha256(data).hexdigest() != e["sha256"]:
            raise ValueError(f"SHA-256 differs from the manifest: {key}")
        return data

    def _fetch(self, key, url, body):
        time.sleep(max(0.0, self._last + 1 - time.monotonic()))  # 1 request per second
        ua = " ".join(filter(None, (UA, CONTACT.get(urllib.parse.urlsplit(url).hostname))))
        headers = {"User-Agent": ua, **({"Content-Type": "application/json"} if body else {})}
        req = urllib.request.Request(url, data=body.encode() if body else None, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                status, data = r.status, r.read()
        except urllib.error.HTTPError as err:
            status, data = err.code, b""
        self._last = time.monotonic()
        name = "files/" + hashlib.sha256(key.encode()).hexdigest()[:32]
        os.makedirs(os.path.join(self.path, "files"), exist_ok=True)
        with open(os.path.join(self.path, name), "wb") as fh:
            fh.write(data)
        return {"url": url, "body": body, "file": name, "fetched": _now(), "status": status,
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def save(self):
        with open(os.path.join(self.path, "manifest.json"), "w") as fh:
            json.dump(self.manifest, fh, indent=1, sort_keys=True)
