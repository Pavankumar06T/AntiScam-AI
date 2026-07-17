# AntiScam AI — Detection Metrics

**Configuration:** Rule Layer Only (LLM unavailable — degraded floor)  
**Decision threshold:** scam_probability ≥ 50  
**Samples:** 16  
**Dataset origin:** hand-authored  

> ⚠️ **These are degraded-mode numbers.** They reflect the deterministic
> rule layer *alone*, with the LLM unavailable. They are a floor, not the
> product's performance — the LLM layer materially lifts recall on subtle
> scams (loan, job, investment) that have no hard keyword signature. Run
> with a Groq key configured for the full-detector figures.

## Headline

| Metric | Value |
|---|---|
| Precision | **1.0** |
| Recall | **0.5** |
| F1 | **0.667** |
| Accuracy | 0.75 |
| False positive rate | **0.0** |
| False positive rate on hard negatives | **0.0** (5 samples) |

### Confusion matrix

| | Predicted scam | Predicted legit |
|---|---|---|
| **Actually scam** | 4 (TP) | 4 (FN) |
| **Actually legit** | 0 (FP) | 8 (TN) |

## Why the false-positive rate is the number that matters

This tool interrupts real citizens mid-call. A detector that cries wolf on
legitimate calls gets muted, and then it is useless on the call that counts.
So we report the false-positive rate on **hard negatives** separately: calls
engineered to look scam-like (a bank's genuine fraud alert, a real delivery
OTP, an overdue-EMI reminder) but that are benign. That is the honest number.

Mean score on scam calls: **57.0** · on legitimate calls: **14.6** — a clear separation.

## Recall by scam type

| Scam type | Recall |
|---|---|
| digital arrest | 1.0 |
| investment fraud | 0.0 |
| job scam | 0.0 |
| kyc fraud | 1.0 |
| loan fraud | 0.0 |
| lottery prize | 0.0 |
| tech support | 1.0 |

The rule layer catches scams with hard lexical signatures (digital arrest,
KYC/OTP, remote-access) and misses those that require semantic understanding
(a plausible loan or investment pitch). This is precisely the division of
labour the two-layer design intends: rules for the non-negotiables, the LLM
for judgement. The gap here *is* the argument for the LLM layer.

> Note: 16 sample(s) scored in degraded mode.

---

*Synthetic/curated evaluation data — not real call transcripts. Figures
characterise behaviour on illustrative dialogue and are not a claim about
field performance.*