---
name: hunter-l3-arbitrary-file-overwrite
description: "Use when hunting Arbitrary File Overwrite on a target. Loads the L3 technique sheet: Arbitrary File Overwrite is the class where an attacker controls *where* or *under what name* a program writes output — a generated file's filename, a download's output path, or a command response's destination."
domain: cybersecurity
subdomain: web
tags:
- web
- arbitrary-file-overwrite
- hunting
- l3
version: '1.0'
---

# Arbitrary File Overwrite — Technique Sheet

## Overview

Arbitrary File Overwrite is the class where an attacker controls *where* or *under what name* a program writes output — a generated file's filename, a download's output path, or a command response's destination. It pays because "overwrite" is strictly stronger than "write": overwriting `index.php` takes the whole site down, overwriting `.ssh/id_rsa` or `.bashrc` yields code execution on next use, and overwriting user documents destroys data. It shows up in three distinct settings: server-side file-generation modules, desktop CLI tools that derive output names from remote input, and local URL-handler/IPC endpoints that trust a path parameter.

## Distinct sub-patterns

### 1. Server-side file generation with attacker-controlled output filename

- **Endpoint shape:** A file-generation module reachable via `GET /{path}.php`, where the `filename` parameter (or the path itself) becomes the on-disk output name.
- **Payload that fired:** `filename=index.php` — the report demonstrated writing to `/██████_h1goedix.php` (a file created outside the intended location / at a chosen path) and then changing the filename to `index.php`.
- **Root cause:** The generator accepts an arbitrary output filename and joins it into the write path without normalization or allowlisting. Because the target can be `../`-traversed or pointed at existing entries, any PHP file — on the web root or outside it — can be replaced. No content sanitization matters once the name is attacker-controlled.
- **Impact proven:** Created a file at `/██████_h1goedix.php`; demonstrated the filename could be set to `index.php` to replace any PHP file with an empty page; overwrote all server files with empty pages (full-site outage / code destruction).
- **Exemplar:** 2733190 (MOD Supply Chain VDP).

### 2. CLI tool deriving output filename from remote path segments (curl `get_url_file_name()`)

- **Endpoint shape:** `curl --url @<url-list-file>` — i.e., curl is given a file of URLs (or any flow where the output name is auto-derived) and each URL's last path segment becomes the local write target.
- **Payload that fired (verbatim):**
  ```
  curl --url @urls.txt
  ```
  with attacker-controlled URL content such that the derived filename was `.bashrc_poc_test` and the file content was attacker-controlled (`# PWNED` / `export PWNED=1`).
- **Root cause:** `get_url_file_name()` derives the local output filename from the last segment of the URL path with no sanitization on non-Windows builds. Filenames beginning with `.` (dotfiles like `.bashrc`) are allowed, and path handling permits writing into the current working directory under names chosen by whoever controls the URL list.
- **Impact proven:** A local `.bashrc_poc_test` file was created in the working directory containing attacker-controlled content, demonstrating overwriting of sensitive files. (Named after `.bashrc` because a dotfile write of `export PWNED=1` in a shell startup file is a direct persistence/code-execution primitive.)
- **Exemplar:** 3766392 (curl).

### 3. Local URL handler / IPC endpoint writing a response to an arbitrary path

- **Endpoint shape:** A custom-scheme handler invoked from a web page or local trigger:
  ```
  steam://devkit-1/list-shortcuts?response={path}
  ```
  where the `response` parameter is a full filesystem path used as the write destination.
- **Payload that fired (verbatim):**
  ```
  steam://devkit-1/list-shortcuts?response=/home/ubuntu/.ssh/id_rsa
  ```
- **Root cause:** The steam:// URL handler writes the command's response body to a user-specified file path with no restriction on the location — no confinement to the app's own data directory, no blocklist of sensitive paths, no confirmation. Any page can trigger the scheme, so any website can drive the write.
- **Impact proven:** Created `/tmp/testfile` and overwrote/wiped existing files such as `/home/ubuntu/.ssh/id_rsa` and user documents, executing as the user running the Steam client. Wiping an SSH private key is both data destruction and a forced-regeneration vector; writing to `.ssh/`-adjacent paths is one step from key injection.
- **Exemplar:** 667242 (Valve).

## Bypass / chain notes

- **Traversal-out-of-web-root:** In pattern 1, the filename control is what removes the intended sandbox — the same write primitive covers files on the web root and files outside it. Test both: in-root overwrite (immediate site defacement/emptiness, easy to prove) and out-of-root write (higher-severity claim, prove with a temp file then demonstrate the target).
- **Dotfile prefix as the payload:** In pattern 2, the kill detail is not traversal but the *name shape*: a filename starting with `.` places the file where shells and tools look for config. A "harmless" download-to-cwd becomes code execution when the derived name is `.bashrc`-style. When auditing filename-derivation code, ask specifically "can the resulting name start with a dot / collide with a config file?"
- **Scheme-handler as cross-origin write:** In pattern 3, the bypass is implicit — no exploit chain against the app's internals is needed because the browser itself bridges web content to the local handler. Any page the victim visits can fire `steam://...?response=<path>`. The write runs with the *user's* privileges, which reaches `.ssh/`, documents, and startup files.
- **Empty-content overwrite as impact proof:** Where the write body is not attacker-controlled (patterns 1 and 3 write generated/empty content), impact is still proven by *destruction*: replacing `index.php` with an empty page, wiping `id_rsa`. Don't discount a write-only-empty primitive — "all server files replaced with empty pages" and "SSH key wiped" were the accepted severities in these records.
- **No chained escalations were present in these records** — all three stood alone. The natural next steps (persist via `.bashrc` injection in pattern 2, write an `authorized_keys`-adjacent file in pattern 3) were not demonstrated and should be treated as hypotheses, not verified techniques.

## Gotchas / what NOT to do

- **Do not actually overwrite `index.php` in production testing.** The curl and MOD reports prove impact by establishing control (a uniquely named file like `/██████_h1goedix.php`, `.bashrc_poc_test`, `/tmp/testfile`) and by *demonstrating* the overwrite on the real target only in a controlled/sandboxed context. A unique non-colliding name first; destructive overwrite only on your own test assets or with explicit permission.
- **Never overwrite a user's real `.ssh/id_rsa` or documents.** The Valve proof used the user's own test environment (ubuntu home, `/tmp/testfile`) to show the write path; wiping real credentials or user data is out-of-bounds destruction, not a stronger report.
- **Filename control ≠ file-content control.** In patterns 1 and 3 the content is fixed by the application. Report the primitive honestly as overwrite-with-application-generated-content; that was still accepted as high impact (total file destruction, site outage).
- **Check the platform qualifier.** The curl root cause is explicitly *non-Windows builds* — Windows builds sanitize differently. Scope your report and your repro to the affected platform.
- **Don't assume the write location is the web root.** Each sub-pattern's dangerous path differs: web root + beyond (server-side generator), current working directory (CLI), user home (desktop handler). Verify where the write actually lands before claiming impact.

## Real-world impact examples

- **Full-site file destruction (MOD Supply Chain VDP, 2733190):** Changing the generated file's `filename` to `index.php` replaced the site's PHP entry point with an empty page; the same primitive overwrote all server files with empty pages — total application outage and code loss from a single filename parameter.
- **Attacker-controlled dotfile write in user's shell environment (curl, 3766392):** `curl --url @urls.txt` created `.bashrc_poc_test` in the working directory containing `# PWNED` / `export PWNED=1` — demonstrating that a URL list controls both the local filename and its contents, i.e. silent overwrite of sensitive files with content of the attacker's choosing.
- **SSH key wipe + document destruction via a website-triggered URL (Valve, 667242):** A single `steam://devkit-1/list-shortcuts?response=/home/ubuntu/.ssh/id_rsa` invocation, firable from any web page, wiped the user's SSH private key and user documents as the Steam-client user — no local interaction required beyond visiting the attacker's page.