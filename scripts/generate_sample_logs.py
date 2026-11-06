"""
Generates a realistic 1,000-row network traffic telemetry dataset
(data/sample_logs.csv) containing 950 baseline rows and 50 injected
multi-vector cyber-attack anomalies.
"""

from pathlib import Path
from typing import Tuple
import numpy as np
import pandas as pd


def build_telemetry_dataset(
    total_rows: int = 1000,
    num_anomalies: int = 50,
    seed: int = 42,
) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Synthesizes network packet telemetry across 5 numerical features:
    packet_size, latency_ms, failed_logins, bytes_transferred, port_number.
    """
    if num_anomalies >= total_rows:
        raise ValueError("num_anomalies must be strictly less than total_rows.")

    rng = np.random.default_rng(seed=seed)
    n_normal = total_rows - num_anomalies

    normal_df = pd.DataFrame(
        {
            "packet_size": np.round(
                rng.normal(loc=520.0, scale=140.0, size=n_normal).clip(64.0, 1480.0), 0
            ).astype(int),
            "latency_ms": np.round(
                rng.normal(loc=24.5, scale=9.2, size=n_normal).clip(2.1, 85.0), 2
            ),
            "failed_logins": rng.choice([0, 1, 2], size=n_normal, p=[0.88, 0.09, 0.03]),
            "bytes_transferred": np.round(
                rng.normal(loc=18500.0, scale=6200.0, size=n_normal).clip(512.0, 55000.0), 0
            ).astype(int),
            "port_number": rng.choice(
                [80, 443, 443, 443, 8080, 8443, 53, 5432], size=n_normal
            ),
        }
    )

    ddos_count = 13
    brute_count = 13
    exfil_count = 12
    c2_count = num_anomalies - (ddos_count + brute_count + exfil_count)

    ddos_df = pd.DataFrame(
        {
            "packet_size": rng.integers(8400, 15200, size=ddos_count),
            "latency_ms": np.round(rng.uniform(390.0, 810.0, size=ddos_count), 2),
            "failed_logins": rng.integers(0, 3, size=ddos_count),
            "bytes_transferred": rng.integers(1_450_000, 2_400_000, size=ddos_count),
            "port_number": np.full(ddos_count, 443, dtype=int),
        }
    )

    brute_df = pd.DataFrame(
        {
            "packet_size": rng.integers(310, 500, size=brute_count),
            "latency_ms": np.round(rng.uniform(145.0, 255.0, size=brute_count), 2),
            "failed_logins": rng.integers(42, 127, size=brute_count),
            "bytes_transferred": rng.integers(64_000, 109_000, size=brute_count),
            "port_number": rng.choice([22, 3389], size=brute_count),
        }
    )

    exfil_df = pd.DataFrame(
        {
            "packet_size": rng.integers(4200, 7400, size=exfil_count),
            "latency_ms": np.round(rng.uniform(260.0, 450.0, size=exfil_count), 2),
            "failed_logins": rng.integers(4, 12, size=exfil_count),
            "bytes_transferred": rng.integers(3_800_000, 8_000_000, size=exfil_count),
            "port_number": rng.integers(44444, 44944, size=exfil_count),
        }
    )

    c2_df = pd.DataFrame(
        {
            "packet_size": rng.integers(6100, 9600, size=c2_count),
            "latency_ms": np.round(rng.uniform(510.0, 890.0, size=c2_count), 2),
            "failed_logins": rng.integers(19, 54, size=c2_count),
            "bytes_transferred": rng.integers(920_000, 1_670_000, size=c2_count),
            "port_number": rng.integers(31337, 33337, size=c2_count),
        }
    )

    combined = pd.concat([normal_df, ddos_df, brute_df, exfil_df, c2_df], ignore_index=True)
    labels = np.array([0] * n_normal + [1] * num_anomalies)

    permutation = rng.permutation(total_rows)
    shuffled_df = combined.iloc[permutation].reset_index(drop=True)
    shuffled_labels = labels[permutation]

    return shuffled_df, shuffled_labels


def main() -> None:
    """Entrypoint to write data/sample_logs.csv."""
    output_path = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df, labels = build_telemetry_dataset(total_rows=1000, num_anomalies=50, seed=42)
    df.to_csv(output_path, index=False)
    print(
        f"Generated {len(df)} telemetry rows ({int(labels.sum())} injected anomalies) -> {output_path}"
    )


if __name__ == "__main__":
    main()
