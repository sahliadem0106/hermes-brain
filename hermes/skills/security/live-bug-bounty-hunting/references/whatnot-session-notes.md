# Worked example: Whatnot (HackerOne) — first live hunt, Sep 1 2026

Concrete request shapes and sequence that worked (and the dead ends to skip).

## Flow that worked
1. subfinder -d whatnot.com → 258 subs → httpx alive (browser UA + X-HackerOne-Research header) → 92 alive, 41 production (classify non-prod per program rules: stage/dev/qa/load likely declined — park, don't test).
2. Homepage 403 with curl defaults → 200 (1.7MB) with browser UA. Wall = UA-only.
3. Extract 78 JS bundle paths from HTML → download Next.js chunks (2.5MB) → grep for:
   - API surface: /services/api/supply/graphql, /services/api/v2/{login,oauth,register}
   - ID field names: orderId, livestreamId, listingId, entityId...
4. Supply GraphQL introspection OPEN (200 with __schema) → full schema dump in 2 requests (7 queries, 6 mutations, 47 types: invoice/quote CRUD with supplierId/sellerId, stripeInvoiceUrl, pdfUrl).
5. Contrast test: api.whatnot.com/graphql/ → "introspection is disabled" (config inconsistency between services).
6. Auth checks: viewer → null unauth; invoices → "Not authenticated". Data gates ON.
7. Role gate: authenticated buyer session → viewer OK but invoices/quotes/sellers all "Not authenticated" → supply API requires seller role. Correct behavior; path = operator upgrades to seller.
8. Main API (introspection off): error-oracle aliased batches mapped root fields. `me` leaks own id/email/username; global IDs are base64("UserNode:71397738") — sequential. node() returns null even for own ID (restricted). `paymentMethods` root field exists (credit-card surface — next-window target).

## Dead ends (do not repeat)
- Refresh-token replay server-side: Next.js middleware refresh is browser-only; guessing /oauth/token|/refresh paths = 404s. Ask for fresh paste instead.
- node() with typed inline fragments on UserNode — still null (interface restricted).
- gau/waybackurls from this IP — timed out/empty; JS extraction substitutes.
- Truncated DevTools cookie pastes ("eyJjIj...Mzh9") — silently fail auth; require Copy-as-cURL.

## Operator interaction notes
- Each cookie paste = 5-min window: pre-write the request script, fire on arrival.
- Session storage: /tmp/wn-session.env chmod 600; tokens never in git; rotate after testing.
- ~40 requests/day across full recon + probing (cap 10k/day) — budget never the constraint; the 5-min windows were.
