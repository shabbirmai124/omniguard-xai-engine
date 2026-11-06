# Verification & Unit Testing Suite (`tests/`)

This directory contains the automated `pytest` test suite for verifying the mathematical integrity of `AnomalyDetectionPipeline`.

## Running Tests

```bash
pytest tests/test_detector.py -v
```

## Test Coverage

1. **`test_pipeline_output_schema_and_counts`**: Verifies that `fit_and_detect` processes a 500-row synthetic NumPy telemetry fixture (475 normal, 25 injected anomalies) and flags the expected 5% contamination quantile.
2. **`test_shap_root_cause_feature_attribution`**: Asserts that every flagged incident in `critical_incidents` contains a negative `anomaly_score` and exactly 3 root-cause features with float `value` and `shap_impact` keys.
3. **`test_injected_anomalies_are_captured`**: Confirms that $\ge 80\%$ of top critical incidents correspond to the ground-truth injected cyber-attack rows.
4. **`test_pipeline_handles_non_numeric_and_missing_values`**: Ensures string metadata columns (`source_ip`) and rows containing `NaN` values are safely filtered without raising runtime exceptions.
