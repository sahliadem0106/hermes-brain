---
name: hunter-l3-buffer-over-read
description: "Use when hunting Buffer Over-read on a target. Loads the L3 technique sheet: Buffer over-read (out-of-bounds read / OOB read) is a memory-safety bug class where a parser, converter, or copy routine reads past the end of an allocated buffer (heap or stack) because a length is t"
domain: cybersecurity
subdomain: web
tags:
- web
- buffer-over-read
- hunting
- l3
version: '1.0'
---

# Buffer Over-read — Technique Sheet

## Overview
Buffer over-read (out-of-bounds read / OOB read) is a memory-safety bug class where a parser, converter, or copy routine reads past the end of an allocated buffer (heap or stack) because a length is trusted, miscomputed, sign-extended, or never checked. In bug bounty it pays through two channels: (1) **memory disclosure** — beyond-bounds bytes flow back to the attacker (Heartbleed-style leaks of keys, cookies, request bodies), and (2) **crash/DoS confirmed via ASAN** — where the crash itself plus an ASAN heap-buffer-overflow report is the accepted evidence for CVE-issuing programs (Python, PHP, curl, tcpdump, Apache httpd via Internet Bug Bounty). The dominant hunting vector in these records is **malicious input to parsers**: file formats (pcap, TIFF/EXIF, phar, WDDX/XML, protobuf-ish frames) and protocol endpoints (WebSocket, FTP listings, TLS, TFTP servers).

## Distinct sub-patterns

### 1. Length-field trust in framing protocols (Heartbleed family)
- Endpoint shape: TLS heartbeat extension handler; analogous: Apache mod_lua WebSocket `r:wsread()` / `lua_websocket_readbytes()` with frame payload-length param `len`.
- Payload that fired (mod_lua WS, verbatim): `\x82\x7f\x00\x00\x00\x00\x00\x00\x40\x00` — a WS frame claiming a 0x4000-byte payload length. Heartbleed: no payload, just a heartbeat request with a length field exceeding the actual data.
- Root cause: code `memcpy()`s `len` bytes from a buffer that holds fewer bytes — `ap_get_brigade()/apr_bucket_read()` return fewer bytes than requested; OpenSSL heartbeat skipped the bounds check on the length field entirely.
- Impact: mod_lua PoC exfiltrated 0x4000 bytes of httpd heap (attacker-controlled amount, repeatable, hard to detect); Heartbleed revealed up to 64KB of memory per heartbeat to a connected client or server.
- Exemplars: id=1595290, id=6626.

### 2. Sign-extension / integer-underflow on a length or size parameter
- Endpoint shape: `ap_rwrite()`/`r:puts()` with `int nbyte` (httpd); curl TFTP `tftp_send_first` with `mode, blksize` and `CURLOPT_TFTP_NO_OPTIONS`.
- Payloads that fired (verbatim):
  - mod_lua: `function handle(r) local s = r:requestbody() r:puts(s) end` with a 0x80000000-byte body — negative `int nbyte` sign-extends to a gigantic `apr_size_t len` when passed to `buffer_output()`, creating a bucket far larger than the buffer.
  - curl TFTP: integer underflow in the blksize bounds check disabled the `strlen(filename)` validation, so a malicious TFTP server could make curl send heap memory beyond the allocated chunk (OOB *send* — leak toward the server).
- Impact: httpd returned a block of data other than the base64 of 'a' at the end of the response (beyond-bounds heap to the attacker); curl leaked heap contents to a malicious server.
- Exemplars: id=1595299, id=3508321.

### 3. Using a length/index derived from one buffer against a different, shorter buffer
- Endpoint shape: mod_isapi `HSE_REQ_MAP_URL_TO_PATH` (param `file`, buf_data supplied by the ISAPI DLL).
- Payload that fired (verbatim C):
```
DWORD WINAPI HttpExtensionProc(EXTENSION_CONTROL_BLOCK* pECB) {
    char buf[] = "";
    DWORD bufSize = sizeof(buf);
    pECB->ServerSupportFunction(
        pECB->ConnID, HSE_REQ_MAP_URL_TO_PATH, buf, &bufSize, NULL);
    return HSE_STATUS_SUCCESS;
}
```
- Root cause: `mod_isapi.c` uses `strlen(r->filename)` as an index into the unrelated, shorter `file` buffer, reading `file[len-1]` past its end (one byte past a 0-byte string here).
- Impact: one byte read from `len-1` bytes beyond the buffer; beyond-bounds data could be returned to the ISAPI DLL and thence to the attacker, or crash the server.
- Related: curl `redirect_url()` (id=3751715) — `protsep = base + strlen(scheme) + 3` assumes a `scheme://` prefix that isn't there when `CURLU_NO_GUESS_SCHEME` is set on a guessed scheme, so `strchr` walks past the short heap buffer. Trigger (verbatim): `curl_url_set(u, CURLUPART_URL, "a.b", CURLU_GUESS_SCHEME); curl_url_set(u, CURLUPART_URL, "/x", CURLU_NO_GUESS_SCHEME);` — ASAN heap-buffer-overflow READ of size 34.
- Exemplars: id=1595296, id=3751715.

### 4. String/byte-scanning past the NUL terminator or end-of-input (parser eof bugs)
- Endpoint shapes (all verified): PHP `wddx_deserialize()` → `timelib_meridian()` on a `<dateTime>` element; PHP `phar_detect_phar_fname_ext` on a crafted phar filename; `phar_parse_pharfile` with crafted `__HALT_COMPILER()` placement; PHP `xmlrpc_decode()` base64 decoding of malformed input; PHP `php_strip_tags_ex` (CVE-2020-7059); PHP `exif_read_data` TIFF IFD tag / `php_jpg_get16` / `exif_scan_thumbnail` (CVE-2019-9640); Python `scan_eol`, `bytearray.find`, `PyFloat_FromString`/`PyNumber_Long`; tcpdump BEEP `l_strnstart()` via `strncmp`; curl `GTime2str` in x509asn1.c.
- Payloads that fired (verbatim where available):
  - WDDX (id=248659): `<?xml version='1.0'?> <!DOCTYPE wddxPacket SYSTEM 'wddx_0100.dtd'> <wddxPacket version='1.0'><header/><data><struct><var name='aDateTime'><dateTime>I06.00am 0</dateTime></var></struct></data></wddxP...` — `timelib_meridian()` reads 1 byte past a 10-byte heap string (CVE-2017-11145).
  - Phar (id=475499): `new Phar(file_get_contents('poc.phar'),0,'test.phar')` — READ of size 26 past a 64-byte region (CVE-2019-9021).
- Root causes: memcmp/strncmp/strlen loops without checking remaining buffer length; missing null-termination before strlen. Notable variant (id=2629968): `GTime2str` sets `fracl=-1` and passes it to `Curl_dyn_addf`, which then runs `strlen` beyond the certificate buffer — a specially-crafted TLS certificate crashed libcurl clients built with gnutls/schannel/sectransp/mbedtls.
- Impact: ASAN heap-buffer-overflows; memory leak where decoded output is echoed (xmlrpc_decode, WDDX), up to RCE noted for `php_strip_tags_ex`.
- Exemplars: id=248659, id=475499, id=2629968, id=477897, id=778834.

### 5. Exact-boundary / off-by-one on fixed-size buffers
- Endpoint shapes: curl `curl_url_get()` punycode conversion (IDN exactly 256 bytes, no null-termination → adjacent stack contents/pointer values leak into the returned string); curl CLI URL globbing `tool_urlglob.c` `glob_range`; shoco `shoco_decompress` (global buffer over-read, READ of size 4, CVE-2017-11367); tcpdump `rpki_rtr_pdu_print` (4-byte read 13 bytes past a 69-byte region, CVE-2017-13050), `pgm_print` (EXTRACT_32BITS past a 95-byte region, CVE-2017-13019), `vtp_print` (1-byte read past a 284-byte region, CVE-2017-13033), `aoe_print`/`lookup_emem` (CVE-2017-16808).
- Payloads: globbing (verbatim): `http://ur%20[0-60000000000000000000` — the range parser reads 1 byte past a 24-byte heap buffer on a malformed numeric range (CVE-2017-1000101). Punycode: no explicit payload; condition is a name of exactly 256 bytes. tcpdump payloads are crafted pcap files (payload not stated beyond `./tcpdump -nr <file>`).
- Root cause: bounds checks that are off by one, missing termination on exact-size input, or fixed-size reads (EXTRACT_32BITS / 4-byte reads) without verifying remaining length.
- Exemplars: id=2621062, id=255587, id=250581, id=802863.

### 6. Malicious file/protocol parsers on the *client* side (tcpdump pcaps, crafted certificates, I2P garlic)
- Endpoint shapes: tcpdump `ip6_print` (CVE-2017-12985), `rt6_print` (CVE-2017-12986), `parse_elements` 802.11 (CVE-2017-13008), `mobility_print` (CVE-2017-13009), `handle_mlppp` via `EXTRACT_16BITS` (CVE-2017-13038), MPTCP `print-mptcp.c` (CVE-2017-13040), `icmp6_nodeinfo_print` (CVE-2017-13041); Monero `monerod` miniupnpc XML `parseelt` CDATA handling; I2P `GarlicDestination::HandleGarlicPayload` (DeliveryTypeTunnel).
- Payloads: crafted pcap files run as `./tcpdump -n -r test005` etc.; "specially crafted XML response with unterminated CDATA section" for Monero; for I2P, a garlic clove whose I2NP message length field is unchecked.
- Root cause: element/packet parsers that read fixed-size fields or loop on attacker-controlled lengths without remaining-length checks; Monero's `parseelt` memcmp's for CDATA without checking whether it reached the end of the XML buffer; I2P forwards a message onward using the unchecked length field.
- Impact: tcpdump heap over-reads (ASAN-confirmed; records for MPTCP/ICMPv6 claim potential code injection/process control); Monero client crashed within the local network (access violation); I2P leaked **up to ~16KB of heap — session keys, private keys, old messages — from victim routers, repeatably and without memory errors** (a semantic leak, not a memory-safety crash).
- Exemplars: id=268805/268806, id=964582, id=340012, id=295740.

### 7. Reused/pool-buffer over-copy (leaking *other users'* data)
- Endpoint shape: Squid proxy, `GET ftp://...` through the gateway; FTP server supplies a DOS-format listing.
- Payload that fired: malicious FTP server listing with tab-separated tokens, e.g. `04-05-70 09:33PM\tA*126 A*126`.
- Root cause: `Ftp::Gateway` misparsed tab-separated DOS-format listings and copied past the NUL byte from a reused pool buffer.
- Impact: leaked prior buffer contents — including **other users' requests/responses with headers, cookies, full bodies and post data** — into the returned HTML. The highest-severity pattern in the set: cross-tenant data exposure.
- Exemplar: id=824163.

### 8. Missing length checks in C utility/validation functions (fuzzing finds)
- Endpoint shapes: Cosmos `ledger-cosmos` `parser_validate`/`contains_whitespace`; Python `time.strftime`/`time_strftime` (bugs.python.org 24917); Python `audioop.lin2adpcm`/`adpcm2lin` (24457/24456); Linux kernel `drivers/block/floppy.c` `set_fdc`; Perl `S_pack_rec`/`Perl__byte_dump_string` via crafted regex/pack input (record describes a WRITE of size 4 with leak potential — included as reported).
- Payloads: fuzzing with a crafted buffer (Cosmos); payloads not stated for the Python/kernel/Perl items.
- Root cause: validation/scan helpers operating on buffers without a length parameter or check.
- Impact: ASAN heap-buffer-overread crashes (DoS); kernel: local DoS/crash or info exposure; Perl: remote heap-info leak to bypass ASLR depending on allocator.
- Exemplars: id=2806356, id=891846, id=480778.

## Bypass / chain notes
- **Padding/boundary tuning matters**: several bugs only fire on *exact* sizes — 256-byte IDN, exactly-10-byte dateTime string, 64-byte phar buffer. When fuzzing, sweep sizes around allocation boundaries (2^n ± 1).
- **Multi-condition triggers**: curl TFTP needed `CURLOPT_TFTP_NO_OPTIONS` + a malicious server for the blksize underflow; curl redirect_url needed the `GUESS_SCHEME`→`NO_GUESS_SCHEME` sequence; mod_isapi needed an attacker-supplied (or malicious) ISAPI DLL. Think "state machine step that makes an assumption false."
- **Leak amplification via echo**: the read only becomes an info-disclosure win when the over-read bytes are echoed back — WS echo (`wsread`/`wswrite`), WDDX/xmlrpc decode output, punycode-converted URL, Squid's HTML-ized FTP listing. Records repeatedly note "if the attacker has access to the decoded output this may leak memory contents" — demonstrate the echo, not just the crash.
- **Semantic leaks without memory errors** are stealthiest: I2P garlic (unchecked length forwarded onward) leaked keys "repeatably and without memory errors" — invisible to ASAN, hard to detect.
- **Crash-only is still bounty-worthy** in IBB-style programs: the entire tcpdump cluster was paid purely on ASAN-confirmed heap-buffer-overflow reports against crafted pcaps.
- No report in the set chained an over-read into RCE in the wild; records for `php_strip_tags_ex` and MPTCP/ICMPv6 tcpdump cite memory-corruption/RCE potential only.

## Gotchas / what NOT to do
- Don't stop at a debugger crash: these programs (IBB, curl, tcpdump, PHP, Python) expect an **ASAN report** — heap-buffer-overflow with read size, offset past region, and region size (e.g. "READ of size 4, 13 bytes past a 69-byte region"). Build with `-fsanitize=address` first.
- Don't report the same root cause twice across adjacent parsers without checking known-issue trackers — many records are single CVEs per parser function (`print-*.c` each got its own CVE, but Python audioop lin2adpcm/adpcm2lin were paired bugs 24457/24456).
- Don't assume remote reachability is required: the Linux floppy `set_fdc` bug was local; the Monero bug required only local-network access to a malicious UPnP XML response; the ISAPI bug required a malicious DLL.
- Don't overlook attacker-*server* scenarios: curl TFTP and Squid FTP show the client/proxy is the victim, with the malicious payload coming from the remote server you control.
- Payload truncation is real: the WDDX record's packet is cut off mid-tag (`</wddxP`) — the essential trigger is the malformed `<dateTime>I06.00am 0</dateTime>`, not the full document.
- Some records note impact only as "potential" (xmlrpc_decode leak, tcpdump code control). Prove what you can; ASAN crash evidence has historically sufficed for these programs.

## Real-world impact examples
- **Heartbleed (id=6626)**: 64KB of server/client memory per heartbeat request — the canonical mass-credential-leak.
- **Squid FTP gateway (id=824163)**: other users' full HTTP requests/responses — headers, cookies, bodies, POST data — leaked into an attacker-triggered HTML page via a tab-separated FTP listing.
- **I2P garlic (id=295740)**: ~16KB of heap from victim routers including session keys and private keys, repeatable, no memory errors.
- **Apache mod_lua WS (id=1595290)**: attacker-chosen 0x4000 bytes of httpd heap echoed back over the same WebSocket, repeatable and quiet.
- **curl TFTP (id=3508321)**: malicious TFTP server induced libcurl to transmit heap memory beyond the allocation.
- **tcpdump suite (ids 268803–268808, 802846–802896, 831353, 964582–964583)**: a dozen+ CVEs (CVE-2017-12985/12986/13008/13009/13010/13019/13033/13038/13040/13041/13050/13033/16808) each paid on an ASAN-confirmed over-read against a crafted pcap — the model for "crash = bounty" parser hunting.