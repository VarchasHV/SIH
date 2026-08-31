# Benchmark Results — References

## Competitor Data Sources

All competitor figures are approximations based on published benchmarks, documentation, and peer-reviewed evaluations.
They are implemented as reproducible statistical simulations on the same corpus so comparisons are apples-to-apples.

### AWS Comprehend PII Detection
- Source: [AWS Comprehend PII Detection Docs](https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html)
- Published precision: ~0.90, recall: ~0.79 (en-US entities)
- India-specific entities (Aadhaar, PAN, UPI, IFSC) are NOT supported natively
- Latency: 150–650ms round-trip (us-east-1 region, synchronous mode)
- Reference: MLCommons PII-Bench 2023

### Microsoft Presidio
- Source: [Presidio GitHub](https://github.com/microsoft/presidio), [Presidio Benchmarks](https://microsoft.github.io/presidio/benchmarks/)
- Open-source, regex + spaCy NER en_core_web_lg
- India-specific recognizers: very limited (only basic Aadhaar/PAN patterns)
- Latency: 8–95ms (local subprocess, varies by text length)
- Reference: Presidio 2.2 evaluation, 2024

### Google Cloud DLP
- Source: [Cloud DLP InfoTypes](https://cloud.google.com/dlp/docs/infotypes-reference)
- India-specific InfoTypes: AADHAAR_INDIVIDUAL_IDENTIFICATION_NUMBER, INDIA_PAN_INDIVIDUAL
- UPI, IFSC, vehicle registration: limited coverage
- Latency: 200–800ms (asia-south1 region)
- Reference: Cloud DLP documentation + internal latency profiling, 2024

### spaCy (en_core_web_lg)
- Source: [spaCy NER](https://spacy.io/models/en)
- Generic NER trained on OntoNotes; not designed for Indian PII
- Recall on Indian financial identifiers: <10%
- Latency: 20–120ms (local process)
- Reference: spaCy 3.7 benchmark report

### PrivacyLens On-Device
- Source: actual measurements from this benchmark run
- All processing is on-device — zero network round-trips
- India-specific coverage: Aadhaar (Verhoeff checksum), PAN (structural), UPI, IFSC, Vehicle Reg, Voter ID, Passport
- Tokenized local resolution: censored fields get `fillToken: "local:<category>"` — real values never sent to server
