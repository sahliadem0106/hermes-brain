---
name: hunter-l3-email-spoofing
description: "Use when hunting Email Spoofing on a target. Loads the L3 technique sheet: Email spoofing is the class of bugs where an attacker can cause mail to be delivered that appears to originate from a domain they don't control — either by exploiting missing/misconfigured SPF, DKIM, "
domain: cybersecurity
subdomain: web
tags:
- web
- email-spoofing
- hunting
- l3
version: '1.0'
---

# Email Spoofing — Technique Sheet

## Overview
Email spoofing is the class of bugs where an attacker can cause mail to be delivered that appears to originate from a domain they don't control — either by exploiting missing/misconfigured SPF, DKIM, and DMARC records on the target domain, or by abusing application-level features (registration forms, invite flows, file-upload + PHP `mail()`, transactional relays) that reflect attacker-controlled content or forged From headers into outbound email. It pays because the impact is phishing with the target's trusted brand identity: spoofed mail from security@, support@, admin@, or hello@ addresses landing in victim inboxes (especially on Yahoo/Outlook, which were historically more permissive than Gmail). Bounty value comes from proving delivery to a real inbox, not just from showing a DNS misconfiguration.

## Distinct sub-patterns

### 1. Missing SPF + Missing DMARC (the classic full take-over)
- **Endpoint shape:** DNS lookup on the target apex: `dig example.com txt` (SPF) and `dig _dmarc.example.com txt` (DMARC). No HTTP endpoint involved.
- **Payload that fired:** None at the DNS layer — the proof is delivery of a forged message. Typical forged From values seen in records: `security@paragonie.com` (148763, 115232, 115452), `hello@legalrobot.com` (163475, 163501), `support@nextcloud.com` (200762), `admin@portswigger.net` (206359), `admin@badoo.com` (182467), `contact@khanacademy.org` (496360), `privacy@sifchain.finance` (1180668), `security@torproject.org` (423336), `mail@semrush.com` (276614), `support@gratipay.com` (240987), `admin@aspen.io` (288707).
- **Root cause:** The domain publishes no SPF record and/or no DMARC record, so recipient mail servers have no basis to reject a forged From. Several records confirm this explicitly via `dig`: torproject.org had no SPF and no DMARC (423336); sifchain.finance had no valid SPF and no DMARC (1194598); kubernetes.io had no valid SPF (918243); cordacon.com had no DMARC record at all, confirmed via mxtoolbox (1125143); Legal Robot lost its SPF records entirely during a DNS migration (66385).
- **Impact proven:** Spoofed mail delivered to a real inbox (Yahoo inbox at Gratipay — "trusted folder, not spam"; Outlook mailbox at Tor; Gmail spam at Badoo/Bumble, which still counts as delivered). Impact statements all frame it as phishing/enabling fake emails that can cause reputation loss or target customers and employees.
- **Exemplars:** 423336 (Tor), 182467 (Bumble/Badoo).

### 2. SPF softfail (`~all`) instead of hardfail (`-all`)
- **Endpoint shape:** DNS TXT SPF record on the apex, e.g. `dig example.com txt` and read the mechanism tail.
- **Payload that fired (verbatim):**
  - `v=spf1 include:_spf.google.com include:spf.autopilothq.com include:sendgrid.net ~all` (Sifchain, 1180668)
  - `v=spf1 include:_spf.google.com include:mailgun.org include:spf.sendinblue.com ~all` (WakaTime, 244432)
- **Root cause:** `~all` is softfail — receiving servers treat unauthorized senders as suspicious but do not reject. Without a DMARC policy at `p=reject`/`p=quarantine` on top, spoofed mail still lands in the inbox rather than being bounced.
- **Impact proven:** Sifchain — forged email appearing from `privacy@sifchain.finance` was delivered (PoC video + screenshot). WakaTime — confirmed ability to send spoofed email as `support@wakatime.com`.
- **Exemplars:** 1180668 (Sifchain), 244432 (WakaTime).

### 3. Third-party sender whitelisted without ownership verification (Mandrill/relay abuse)
- **Endpoint shape:** SPF record that `include`s a shared sending service (e.g. `spf.mandrillapp.com`) without the domain being registered/verified on that service. The attack is then launched from a free account on that service.
- **Payload that fired:** Forged email `From: mike.brooks@hackerone.com`, sent from a Mandrill account, delivered to `support@hackerone.com` (56742).
- **Root cause:** HackerOne's SPF whitelisted `spf.mandrillapp.com` without domain registration on Mandrill, so ANY Mandrill user could send mail appearing to originate from hackerone.com. This is a distinct pattern from plain missing SPF — the SPF record exists and looks correct, but delegates authority to a shared tenant anyone can sign up for.
- **Impact proven:** Forged mail delivered into the target's own support mailbox.
- **Exemplar:** 56742 (HackerOne).

Related variant — **recycled third-party service addresses**: hey.com's SPF delegated to `helpscoutemail.com`, and recycled trial email addresses could be re-registered, letting anyone with a Help Scout inbox act as that hey.com address and CC an address they own to capture replies (981824, Basecamp). Impact: spoof any recycled hey.com address, including high-profile individuals. Exemplar: 981824.

Related variant — **unused relay subdomain / bounceback abuse**: `mail-txn.identity.com` was an unused subdomain aliased to Mandrill's transactional relay, allowing fake bounceback / failed-delivery messages to be sent to an arbitrary recipient (280803, Inflection). Exemplar: 280803.

### 4. Third-party spoofing services (emkei.cz) against unprotected domains
- **Endpoint shape:** No target endpoint — the "endpoint" is emkei.cz (a public spoofing service), pointed at the target's mail domain. This was the dominant PoC tool in the records: Paragon Initiative (115232, 115452, 148763), Legal Robot (163475, 163501), Bumble (182467), Nextcloud (200762), PortSwigger (206359), Gratipay (240987), Skyliner (163526), Semrush (276614), Aspen (288707).
- **Payload that fired:** Set the From field to the target address (e.g. `security@paragonie.com`, `support@nextcloud.com`, `admin@portswigger.net`, `mail@semrush.com`) and send to a victim address you control.
- **Root cause:** Target domain lacks SPF/DKIM/DMARC enforcement (overlaps pattern 1); the spoofing service is just the delivery mechanism. Skyliner's root cause was stated as "mail server has no authentication/security filters, so any skyliner.io address can be forged via emkei.cz or PHP mail()."
- **Impact proven:** Delivered to inbox on Yahoo/Outlook; Gmail typically spam (Badoo) — note this inbox-vs-spam split when reporting.
- **Exemplars:** 115452 (Paragon — both `security@` and `scott@` forged), 206359 (PortSwigger).

### 5. Self-hosted PHP `mail()` from a compromised/hosting-adjacent position
- **Endpoint shape:** Any PHP-executable path on the target's web host (or an uploaded file on a host that permits it), calling `mail()`.
- **Payload that fired (verbatim, DoD 1878756):**
```php
<?php
$to = "█████";
$subject = "Email exploitation test";
$txt = "Email exploitation test";
$headers = "From: ███████";
mail($to,$subject,$txt,$headers);
?>
```
  And Skyliner (163526):
```php
<?php
$to = "gopss.sharma@gmail.com";
$subject = "Email Spoofing Test";
$txt = "This is Email Spoofing";
$headers = "From: dan@skyliner.io";
mail($to,$subject,$txt,$headers);
?>
```
- **Root cause:** DoD case: web host permitted uploading/executing PHP that can call `mail()`, so mail went out with the organization's own domain as sender (and the attacker also obtained an internal employee email list). Skyliner: no authentication/security filters on the mail server.
- **Impact proven:** Emails sent from the organization's own addresses/domain; combined with the employee list, enabled phishing, email bombing, and spoofing.
- **Exemplars:** 1878756 (U.S. Dept of Defense), 163526 (Skyliner).

### 6. Application feature reflects attacker content into outbound email (hyperlink/content injection)
- **Endpoint shape:** Feature that generates email containing user-supplied fields. In the records: OpenMage registration `POST /customer/account/createpost/` with params `firstname,lastname,email` (1091957), and Pushwoosh invites functionality (182008).
- **Payload that fired (verbatim):**
  - OpenMage (1091957): `hello your account has been deleted permanenty please visit here evil.com your account has been blocked permanenty ,please confrim your verification here evil.com` — placed in the oversized first/last name fields containing control characters and malicious links.
  - Pushwoosh (182008): `<a href="https://attacker.example.com">click here</a>` injected through the invites functionality.
- **Root cause:** OpenMage: name length limits and control characters not enforced, so attacker-controlled text is reflected verbatim into server notification emails sent to arbitrary victims. Pushwoosh: invites functionality permits hyperlink injection into emails, spoofing email content.
- **Impact proven:** OpenMage: registration returned 200 OK and notification emails carrying malware/phishing links could be sent to a victim's address — "email hijacking." Pushwoosh: spoofed email content via injected hyperlink.
- **Exemplars:** 1091957 (OpenMage), 182008 (Pushwoosh).

### 7. Form accepts a forged sender address (user-controlled From)
- **Endpoint shape:** Public web form with an email/sender input — media.gm.com email input form, `sender address` param (116432, General Motors).
- **Payload that fired:** Payload not stated; the forgery was via the sender address field.
- **Root cause:** The form accepted a forged sender address rather than hardcoding the sender.
- **Impact proven:** Email spoofing possible through forged sender address; remediated by removing user input for that field.
- **Exemplar:** 116432 (General Motors).

### 8. Legitimate transactional endpoint abused to spoof
- **Endpoint shape:** `POST /api/v1/users/reset_password` (WakaTime, 244555).
- **Payload that fired:** Payload not stated.
- **Root cause:** The reset_password endpoint could be abused to send emails spoofing the domain (program acknowledged the fix, confirming validity).
- **Impact proven:** Confirmed email spoofing via the reset flow; acknowledged and fixed.
- **Exemplar:** 244555 (WakaTime).

## Bypass / chain notes
- **Chain: DNS recon → forgery → inbox delivery** (Tor, 423336): (1) `dig torproject.org txt` to verify no SPF, (2) `dig _dmarc.torproject.org txt` to verify no DMARC, (3) send mail with forged From: to a victim mailbox and screenshot delivery.
- **Chain: application registration → reflected phishing email** (OpenMage, 1091957): register with oversized first/last name containing control characters and malicious links → server sends notification email to the victim address containing attacker content.
- **Chain: Help Scout inbox + recycled address + reply-hijack CC** (Basecamp, 981824): re-register a recycled hey.com trial address → send from Help Scout inbox acting as that address → CC an address you own to capture replies.
- **Chain: upload PHP → mail() → employee list → phishing/bombing** (DoD, 1878756): the email spoofing combined with an internal employee email list for targeted phishing and email bombing.
- **Inbox-vs-spam delivery nuance:** Badoo spoof landed in Gmail spam but direct inbox on Yahoo (182467); Gratipay spoof landed in Yahoo's trusted folder, not spam (240987); PortSwigger spoof landed in inbox "on services like Yahoo" (206359). Yahoo/Outlook were reliably more permissive — target them for PoC screenshots if Gmail quarantines the message.
- **SPF that "looks fine" can still be broken:** check what the `include:` mechanisms delegate to — shared tenants (`spf.mandrillapp.com`, `helpscoutemail.com`) without per-domain registration, or abandoned/unused subdomains aliased to relays (`mail-txn.identity.com`), are exploitable even with a valid SPF record present.
- **DMARC-check shortcut used in records:** mxtoolbox was used to confirm missing DMARC (1125143); `dig` for both SPF and `_dmarc` TXT records (423336).

## Gotchas / what NOT to do
- Don't report a mere DNS misconfiguration without a delivery PoC — the strongest records in this set all show the forged mail actually arriving (screenshots/video: 1180668). Records that only confirm missing records (1194598, 918243, 66385, 1125143) were duplicates or lower-value.
- Don't test only Gmail — Gmail often quarantines spoofed mail as spam even when the bug is real (Badoo/Bumble). Use Yahoo/Outlook for delivery proof, and report where it landed honestly.
- Don't forge From addresses of real named individuals carelessly — the high-impact variants targeted role addresses (security@, support@, admin@, hello@, contact@, privacy@, mail@), which is both more credible for phishing and less personally invasive.
- Don't rely on `-all` vs `~all` alone to conclude exploitability — softfail plus absent DMARC is the exploitable combination; hardfail alone also isn't proof of protection (DKIM/DMARC alignment matters).
- Don't send to arbitrary third parties — all records sent to addresses the researcher controlled (e.g. their own Gmail) or the program's own support address.
- Don't overlook application-level vectors when DNS looks configured: registration-name reflection, invites hyperlink injection, sender-input forms, reset-password endpoints, and uploadable PHP `mail()` all bypassed the "is SPF configured?" question entirely.
- Beware reporting SPF-migration fallout as novel — Legal Robot's missing SPF came from a DNS migration (66385), and Kubernetes' record was explicitly a duplicate of a known issue (918243).

## Real-world impact examples
- **DoD (1878756):** Uploaded a PHP `mail()` script on a public web host and sent emails from the organization's own addresses/domain, plus obtained an internal employee email list — enabling phishing, email bombing, and spoofing against DoD personnel.
- **OpenMage (1091957):** Attacker-controlled text with malware/phishing links delivered in server notification emails to arbitrary victims — "email hijacking" from a simple registration form.
- **Tor (423336):** Spoofed `security@torproject.org` delivered into an Outlook mailbox — direct phishing vector against Tor users and employees.
- **HackerOne (56742):** Forged `mike.brooks@hackerone.com` (a real H1 staff identity) delivered to `support@hackerone.com` itself, via any Mandrill account.
- **Basecamp/hey.com (981824):** Spoof any recycled hey.com address, including high-profile individuals, and silently capture reply traffic via CC.
- **WakaTime (244555):** Reset-password endpoint abused for spoofed mail — program acknowledged and fixed.
- **Badoo/Bumble (182467) / Gratipay (240987) / PortSwigger (206359):** Brand-identity phishing delivered into trusted inbox folders on Yahoo, making attacks far more convincing than ordinary spam.