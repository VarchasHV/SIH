# Competitor references — DOCUMENTED CAPABILITY ONLY, NOT BENCHMARKED

None of the systems below have been run against our dataset. This file records
what each vendor publishes so a fair capability comparison (PASS / PARTIAL /
NOT SUPPORTED / NOT TESTED) can be made in `COMPETITOR_BENCHMARK.md`. These
numbers must never be presented as measured results.

## Commercial — NOT EXECUTED (no credentials)

### AWS Comprehend — PII detection
- Docs: https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html
- Entity types are US/EU-centric; no native Aadhaar / PAN / UPI / IFSC / voter-ID / vehicle-reg detector.
- Cloud API — text leaves the device.

### Google Cloud DLP
- InfoTypes: https://cloud.google.com/dlp/docs/infotypes-reference
- Has `AADHAAR_INDIVIDUAL_IDENTIFICATION_NUMBER`, `INDIA_PAN_INDIVIDUAL`, `INDIA_GST_NUMBER`.
- No documented UPI-VPA / voter-ID / vehicle-reg detector.
- Cloud API — text leaves the device.

### Microsoft / Azure AI Language — PII detection
- Docs: https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information/overview
- India entities limited; cloud API.

## Open source — RUN when installed (`scripts/pii_benchmark_unbiased.py`)

### Microsoft Presidio
- https://github.com/microsoft/presidio — regex + spaCy NER, on-device.
- Ships `IN_AADHAAR`, `IN_PAN`, `IN_PASSPORT`, `IN_VOTER`, `IN_VEHICLE_REGISTRATION` recognizers.

### spaCy / Flair NER
- Generic NER (PERSON/DATE/…); not designed for structured Indian identifiers.

## Our system

`client/lib/pii-rules.mjs` — on-device, pre-egress. Actual numbers come from
`eval/bench/run.mjs` and `scripts/pii_benchmark_unbiased.py` on the seeded
corpus; see `BENCHMARK_REPORT.md`.
