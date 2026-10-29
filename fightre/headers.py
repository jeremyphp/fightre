"""Protocol-layer header analysis.

Everything here is comparable arithmetic over headers a real browser always
sends.  The design rule is *contradiction*, not *absence*: a missing header is
weak evidence (proxies strip things), a header that contradicts another header
is strong evidence.

Exit points:

* :func:`ua_family` / :func:`chrome_major` -- cheap UA parsing
* :func:`analyze` -- returns ``Signal`` objects for the scoring engine
* :func:`order_inversions` -- header-order deviation for a claimed engine
"""

from __future__ import annotations

import re
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from . import signals as sig
from .signals import Signal

BOT_MARKERS: Tuple[str, ...] = (
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "python-httpx",
    "go-http-client",
    "okhttp/",
    "java/",
    "libwww-perl",
    "httpie/",
    "node-fetch",
    "axios/",
    "aiohttp/",
    "scrapy/",
    "headlesschrome",
    "phantomjs",
    "selenium",
    "puppeteer",
    "playwright",
    "htmlunit",
    "webkit2png",
)

SINGLETON_HEADERS = frozenset(
    {"host", "content-length", "content-type", "user-agent", "authorization", "origin"}
)

# Typical on-the-wire ordering per engine.  Unknown headers are ignored, so the
# comparison only ever measures the relative order of well-known headers.
CHROME_ORDER: Tuple[str, ...] = (
    "host", "connection", "cache-control", "pragma", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie",
)
FIREFOX_ORDER: Tuple[str, ...] = (
    "host", "user-agent", "accept", "accept-language", "accept-encoding", "connection",
    "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "referer", "cookie", "te",
)
SAFARI_ORDER: Tuple[str, ...] = (
    "host", "accept", "accept-language", "accept-encoding", "connection", "user-agent",
    "referer", "cookie",
)

_PLATFORM_MAP: Tuple[Tuple[str, str], ...] = (
    ("windows nt", "Windows"),
    ("macintosh", "macOS"),
    ("android", "Android"),
    ("iphone", "iOS"),
    ("ipad", "iOS"),
    ("cros", "Chrome OS"),
    ("linux", "Linux"),
)

_CHROME_MAJOR = re.compile(r"(?:chrome|chromium|crios)/?(\d{1,3})", re.I)
_FIREFOX_MAJOR = re.compile(r"firefox/(\d{1,3})", re.I)
_EDGE_MAJOR = re.compile(r"edg(?:e|ios|a)?/(\d{1,3})", re.I)


def ua_family(ua: str) -> str:
    text = (ua or "").lower()
    if "edg/" in text or "edge/" in text:
        return "edge"
    if "firefox/" in text:
        return "firefox"
    if "chrome/" in text or "chromium/" in text:
        return "chrome"
    if "safari/" in text and "version/" in text:
        return "safari"
    return "other"


def chrome_major(ua: str) -> Optional[int]:
    match = _CHROME_MAJOR.search(ua or "") or _EDGE_MAJOR.search(ua or "")
    if match:
        return int(match.group(1))
    match = _FIREFOX_MAJOR.search(ua or "")
    return int(match.group(1)) if match else None


def expected_platform(ua: str) -> Optional[str]:
    text = (ua or "").lower()
    for marker, platform in _PLATFORM_MAP:
        if marker in text:
            return platform
    return None


def brand_majors(sec_ch_ua: str) -> List[int]:
    return [int(m) for m in re.findall(r'v="?(\d{1,3})"?', sec_ch_ua or "")]


def order_inversions(
    raw_pairs: Sequence[Tuple[str, str]], expected: Sequence[str]
) -> Tuple[int, int]:
    """Count out-of-order header pairs among headers present in *expected*."""
    index = {name: position for position, name in enumerate(expected)}
    sequence = [index[name.lower()] for name, _ in raw_pairs if name.lower() in index]
    inversions = 0
    for i, left in enumerate(sequence):
        for right in sequence[i + 1 :]:
            if left > right:
                inversions += 1
    return inversions, len(sequence)


def analyze(
    headers: Mapping[str, str],
    raw_pairs: Optional[Sequence[Tuple[str, str]]] = None,
    http_version: str = "1.1",
) -> List[Signal]:
    """Return protocol signals for one request.

    *headers* keys must be lowercase.  *raw_pairs* preserves original casing and
    duplicates; pass it whenever the server framework exposes it (ASGI does).
    """
    found: List[Signal] = []
    lookup = {k.lower(): v for k, v in headers.items()}
    ua = lookup.get("user-agent", "")
    ua_l = ua.lower()

    # 1. scripting clients announce themselves
    for marker in BOT_MARKERS:
        if marker in ua_l:
            found.append(sig.make("proto.bot_user_agent", f"marker {marker!r}"))
            break
    if not ua:
        found.append(sig.make("proto.missing_browser_headers", "no User-Agent at all"))

    # 2. request smuggling probes: CL + TE together, or conflicting CL values
    if "content-length" in lookup and "transfer-encoding" in lookup:
        found.append(sig.make("proto.smuggling_probe", "Content-Length + Transfer-Encoding"))
    if raw_pairs:
        lengths = {value.strip() for name, value in raw_pairs if name.lower() == "content-length"}
        if len(lengths) > 1:
            found.append(sig.make("proto.smuggling_probe", "conflicting Content-Length values"))

    # 3. client hints must agree with the User-Agent
    family = ua_family(ua)
    major = chrome_major(ua)
    ch_ua = lookup.get("sec-ch-ua", "")
    ch_platform = lookup.get("sec-ch-ua-platform", "").strip('"')
    if family in ("chrome", "edge") and major and major >= 90:
        if not ch_ua:
            found.append(sig.make("proto.missing_browser_headers", "sec-ch-ua absent"))
        else:
            majors = brand_majors(ch_ua)
            if majors and major not in majors:
                found.append(
                    sig.make(
                        "proto.ua_client_hints_mismatch",
                        f"UA major {major} not in sec-ch-ua {sorted(set(majors))}",
                    )
                )
        if ch_platform:
            want = expected_platform(ua)
            if want and ch_platform != want:
                found.append(
                    sig.make(
                        "proto.ua_client_hints_mismatch",
                        f"platform {ch_platform!r} vs UA {want!r}",
                    )
                )

    # 4. a browser UA without the fetch metadata that browser always sends
    if family in ("chrome", "edge") and major and major >= 76:
        if "sec-fetch-site" not in lookup:
            found.append(sig.make("proto.missing_browser_headers", "no sec-fetch-site"))
    if family == "firefox" and major and major >= 90 and "sec-fetch-dest" not in lookup:
        found.append(sig.make("proto.missing_browser_headers", "no sec-fetch-dest"))

    # 5. compression negotiation a modern browser always offers
    encoding = lookup.get("accept-encoding", "")
    if family in ("chrome", "edge", "firefox") and encoding and "br" not in encoding.lower():
        found.append(sig.make("proto.accept_encoding_mismatch", f"Accept-Encoding={encoding!r}"))

    # 6. duplicates of singleton headers
    if raw_pairs:
        counts: Dict[str, int] = {}
        for name, _ in raw_pairs:
            key = name.lower()
            if key in SINGLETON_HEADERS:
                counts[key] = counts.get(key, 0) + 1
        duplicates = sorted(k for k, n in counts.items() if n > 1)
        if duplicates:
            found.append(sig.make("proto.duplicate_header", ", ".join(duplicates)))

    # 7. header ordering vs the claimed engine
    if raw_pairs and len(raw_pairs) >= 6:
        expected: Sequence[str]
        if family in ("chrome", "edge"):
            expected = CHROME_ORDER
        elif family == "firefox":
            expected = FIREFOX_ORDER
        elif family == "safari":
            expected = SAFARI_ORDER
        else:
            expected = ()
        if expected:
            inversions, covered = order_inversions(raw_pairs, expected)
            if covered >= 6 and inversions >= 3:
                found.append(
                    sig.make(
                        "proto.header_order_anomaly",
                        f"{inversions} inversions across {covered} known headers",
                    )
                )

    return found


__all__ = [
    "BOT_MARKERS",
    "analyze",
    "brand_majors",
    "chrome_major",
    "expected_platform",
    "order_inversions",
    "ua_family",
]
