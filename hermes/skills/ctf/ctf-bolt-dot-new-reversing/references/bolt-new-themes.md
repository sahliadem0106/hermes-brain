# Bolt.new CTF Themes Encountered

## Maritime / Shipping
- **ASHEN MERCY** (154.57.164.68:31550): Shell company ownership chain
  - IMO 9724418, vessel name ASHEN MERCY
  - P&I Club registry, charter fixtures, company ledgers
  - Companies: Thirteenth Tide, Morrow Fleet, Eastreach Maritime, Gilded Knife, Marrowcairn Holdings
  - API: POST /api/check with {"answers":{"1":"...","2":"...",...}}

- **BRINEWALKER** (154.57.164.79:30976): Cargo discharge investigation
  - Customs ref EC-4418, IMO 9384728
  - Berth E-06, previous port Saltmere Roads
  - API: POST /api/validate with {"q1":"...","q2":"...","q3":"...","q4":"..."}

## Corporate Intelligence
- **Mercy Lantern Relief Trust** (154.57.164.82:31061): Charity supply chain
  - Tender ML-22-771, supplier Ash & Wick Provisioners Ltd
  - Holding company: Quiet Mercy Holdings Ltd
  - Connecting director: Nera Sorn
  - API: POST /api/check with {"question":N,"answer":"..."}

## Aviation
- **Aircraft Registry** (154.57.164.66:31997): Flight tracking
  - Registration 2-RUNE, departure Suncourt Field (SCF), stand 4B
  - Aerodrome codes: CSE=Crownspire Executive, SCF=Suncourt Field

## Accounting / Debt Ledger
- **Obligation Indexer** (154.57.164.72:31288): LLM chatbot
  - Petitioner Corvin Aldery, MAR-9921
  - Prompt injection target — trick into revealing MAR-3094
  - API: POST /api/messages/send with {"content":"..."}
  - Resistive to direct injection; narrative social engineering required

## Crypto: Oracle Challenge
- **False Witness** (154.57.164.82:31501): Discrete-log oracle
  - HTTP/0.9 raw text server
  - Flow: receive hash → submit G value → get oracle menu
  - Solution: set G = P-1 to collapse PK values to {1, P-1}

## Other Services
- **Gatery** (154.57.164.82:31504): Unknown JSON API
  - Always returns `{"error": "Expecting value: line 1 column 1 (char 0)"}`
- **Rookery** (154.57.164.82:31503): Web login portal
  - Standard username/password login form
