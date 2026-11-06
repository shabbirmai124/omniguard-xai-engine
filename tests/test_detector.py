"""
Unit test suite for the OmniGuard AnomalyDetectionPipeline.
Validates unsupervised Isolation Forest scoring and SHAP TreeExplainer
feature attribution on synthetic NumPy telemetry matrices.
"""

from typing import Dict, Any
import numpy as np
import pandas as pd
import pytest

from src.ml.detector import AnomalyDetectionPipeline


@pytest.fixture
def synthetic_telemetry_df() -> pd.DataFrame:
    """
    Generates a deterministic 500-row synthetic network telemetry DataFrame
    with 25 extreme injected cyber-attack outliers (5% contamination).
    """
    rng = np.random.default_rng(seed=42)
    n_normal = 475
    n_anomalies = 25

    normal_data = {
        "packet_size": rng.normal(loc=512.0, scale=110.0, size=n_normal).clip(64, 1500),
        "latency_ms": rng.normal(loc=24.0, scale=6.5, size=n_normal).clip(2.0, 90.0),
        "failed_logins": rng.poisson(lam=0.2, size=n_normal),
        "bytes_transferred": rng.normal(loc=18000.0, scale=4500.0, size=n_normal).clip(500, 60000),
        "port_number": rng.choice([80, 443, 8080, 8443], size=n_normal),
    }

    anomaly_data = {
        "packet_size": rng.uniform(low=9000.0, high=15000.0, size=n_anomalies),
        "latency_ms": rng.uniform(low=450.0, high=950.0, size=n_anomalies),
        "failed_logins": rng.integers(low=45, high=120, size=n_anomalies),
        "bytes_transferred": rng.uniform(low=2_500_000.0, high=6_000_000.0, size=n_anomalies),
        "port_number": rng.choice([22, 3389, 31337, 44444], size=n_anomalies),
    }

    df_normal = pd.DataFrame(normal_data)
    df_anomaly = pd.DataFrame(anomaly_data)
    combined = pd.concat([df_normal, df_anomaly], ignore_index=True)
    return combined


def test_pipeline_output_schema_and_counts(synthetic_telemetry_df: pd.DataFrame) -> None:
    """Verifies that fit_and_detect returns expected keys, record counts, and contamination rate."""
    contamination = 0.05
    pipeline = AnomalyDetectionPipeline(contamination=contamination)
    output: Dict[str, Any] = pipeline.fit_and_detect(synthetic_telemetry_df)

    assert "total_records" in output
    assert "anomalies_detected" in output
    assert "critical_incidents" in output

    assert output["total_records"] == 500
    expected_anomalies = int(500 * contamination)
    assert abs(output["anomalies_detected"] - expected_anomalies) <= 2
    assert len(output["critical_incidents"]) <= 10
    assert len(output["critical_incidents"]) > 0


def test_shap_root_cause_feature_attribution(synthetic_telemetry_df: pd.DataFrame) -> None:
    """Ensures each critical incident includes exactly 3 SHAP root-cause features with valid floats."""
    pipeline = AnomalyDetectionPipeline(contamination=0.05)
    output = pipeline.fit_and_detect(synthetic_telemetry_df)

    expected_features = {
        "packet_size",
        "latency_ms",
        "failed_logins",
        "bytes_transferred",
        "port_number",
    }

    for incident in output["critical_incidents"]:
        assert isinstance(incident["record_id"], int)
        assert isinstance(incident["anomaly_score"], float)
        assert incident["anomaly_score"] < 0.0

        root_causes = incident["root_cause_features"]
        assert len(root_causes) == 3

        for feature_name, metrics in root_causes.items():
            assert feature_name in expected_features
            assert isinstance(metrics["value"], float)
            assert isinstance(metrics["shap_impact"], float)


def test_injected_anomalies_are_captured(synthetic_telemetry_df: pd.DataFrame) -> None:
    """Verifies that the synthetic attack records at indices [475..499] are predominantly flagged."""
    pipeline = AnomalyDetectionPipeline(contamination=0.05)
    output = pipeline.fit_and_detect(synthetic_telemetry_df)

    flagged_ids = {inc["record_id"] for inc in output["critical_incidents"]}
    injected_overlap = [idx for idx in flagged_ids if idx >= 475]
    assert len(injected_overlap) >= int(0.8 * len(flagged_ids))


def test_pipeline_handles_non_numeric_and_missing_values(synthetic_telemetry_df: pd.DataFrame) -> None:
    """Confirms non-numeric metadata columns are ignored and NaN rows are safely dropped."""
    df_with_meta = synthetic_telemetry_df.copy()
    df_with_meta["source_ip"] = "10.24.1.10"
    df_with_meta.loc[0, "packet_size"] = np.nan

    pipeline = AnomalyDetectionPipeline(contamination=0.05)
    output = pipeline.fit_and_detect(df_with_meta)

    assert output["total_records"] == 500
    assert "source_ip" not in pipeline.feature_names
