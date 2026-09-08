# Medical Dataset Reconnaissance — Research Workflow

When the user asks you to find medical imaging datasets for their research papers (e.g., MENA chest X-rays), follow this pattern.

## Search Strategy (in order)

1. **Search for the specific need**: "MENA chest X-ray dataset", "Tunisian radiology dataset", "Saudi chest X-ray AI"
2. **Search for curated lists**: GitHub repos like `aaekay/radiology-datasets`, `m-aryayi/Medical-Imaging-Datasets` — these aggregate everything
3. **Search for papers using the data**: Often papers mention datasets in their Methods section that aren't easily discoverable through dataset searches
4. **Search for Kaggle datasets**: Kaggle is the most accessible source for students with limited compute

## Approval Process Assessment

For every dataset found, determine:

| Factor | What to Check |
|--------|---------------|
| **Public portion available** | Is there a subset that needs NO approval? (e.g., 700/3500 TB images on Kaggle) |
| **Approval type** | Web form? Email request? Government portal? CITI course? |
| **Approval timeline** | NIH processes: 1-3 weeks. PhysioNet: 1-2 weeks. Direct email: days to weeks |
| **Individual eligibility** | Can a student without institutional IRB apply? PhysioNet requires CITI course (~2-3h, possible fee). NIAID requires Data Access Request. |
| **Institutional email requirement** | Many DUAs require `.edu` or institutional email |

## Friction Ranking (from easiest to hardest)

| Level | Example | Friction |
|-------|---------|---------|
| 🟢 **Zero** | Kaggle public dataset (Qatar TB public portion) | Download immediately |
| 🟡 **Low** | Web form + DUA (PadChest, BIMCV) | 2-3 day wait, straightforward |
| 🟡 **Medium** | CITI course + DUA (PhysioNet: VinDr-CXR, MIMIC) | 2-3h course + small fee if independent learner |
| 🔴 **Higher** | Government portal + review (NIAID TB Portal) | 1-3 week wait, uncertain for individuals |

## Key Insight: Always Check for a Public Portion

Many restricted datasets have a **public subset** that requires no approval:
- Qatar TB: 700/3500 images public on Kaggle (2,800 more require NIAID)
- The public portion is often enough to start working while waiting for the full set

## Data Use Agreements — Common Requirements

| Requirement | Applies To |
|-------------|------------|
| ORCID iD | PhysioNet (free, 5 min) |
| CITI "Data or Specimens" course | PhysioNet credentialed datasets ($0-30) |
| Institutional sign-off | Some NIH repositories |
| Email to data owner | PadChest, BIMCV |
| Online form + automated approval | Most mid-size datasets |
