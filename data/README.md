# Telemetry Data & Schema Specification (`data/`)

This directory houses the synthetic network telemetry dataset (`sample_logs.csv`) and JSON Schema validation rules (`schema.json`).

## Dataset Composition (`data/sample_logs.csv`)

Generated deterministically via `python scripts/generate_sample_logs.py` (seed `42`):
- **Total Records:** `1,000` rows
- **Baseline Normal Traffic:** `950` rows (95.0%)
- **Injected Cyber-Attack Anomalies:** `50` rows (5.0%)

### Telemetry Columns

| Column | Type | Normal Baseline Range | Injected Anomaly Profile |
| :--- | :--- | :--- | :--- |
| `packet_size` | `int` | `64 – 1,480` bytes ($\mu = 520$) | `8,400 – 15,200` bytes (Jumbo flood frames) |
| `latency_ms` | `float` | `2.1 – 85.0` ms ($\mu = 24.5$) | `145.0 – 890.0` ms (Socket exhaustion) |
| `failed_logins` | `int` | `0 – 2` attempts | `19 – 127` attempts (SSH/RDP brute force) |
| `bytes_transferred` | `int` | `512 – 55,000` bytes | `920,000 – 8,000,000` bytes (Data exfiltration) |
| `port_number` | `int` | `80, 443, 8080, 8443, 53, 5432` | `22, 3389, 31337, 44444` (Brute force / C2 ports) |
