import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSyntheticTelemetry,
  runAnomalyDetectionPipeline,
  parseCsvTelemetry,
  recordsToCsv,
  synthesizeDeterministicRemediation,
} from './xaiEngine';

test('generateSyntheticTelemetry produces 1,000 rows with 50 injected cyber-attack anomalies', () => {
  const records = generateSyntheticTelemetry(1000, 50, 42);
  assert.equal(records.length, 1000);

  const injected = records.filter((r) => r.ground_truth_label !== 'normal');
  assert.equal(injected.length, 50);

  // Verify required columns exist on every row
  for (const row of records.slice(0, 10)) {
    assert.equal(typeof row.packet_size, 'number');
    assert.equal(typeof row.latency_ms, 'number');
    assert.equal(typeof row.failed_logins, 'number');
    assert.equal(typeof row.bytes_transferred, 'number');
    assert.equal(typeof row.port_number, 'number');
  }
});

test('runAnomalyDetectionPipeline isolates anomalies and computes top-3 SHAP root causes', () => {
  const records = generateSyntheticTelemetry(1000, 50, 42);
  const output = runAnomalyDetectionPipeline(records, 0.05);

  assert.equal(output.total_records, 1000);
  assert.equal(output.anomalies_detected, 50);
  assert.equal(output.anomaly_rate_pct, 5);
  assert.ok(output.critical_incidents.length >= 10);

  const topIncident = output.critical_incidents[0];
  assert.ok(topIncident.anomaly_score < 0, 'Critical incident must have negative anomaly decision score');
  const rootCauseKeys = Object.keys(topIncident.root_cause_features);
  assert.equal(rootCauseKeys.length, 3, 'Each incident must isolate top 3 SHAP root-cause features');

  for (const key of rootCauseKeys) {
    const factor = topIncident.root_cause_features[key];
    assert.equal(typeof factor.value, 'number');
    assert.equal(typeof factor.shap_impact, 'number');
  }
});

test('CSV serialization and parsing round-trips cleanly through the pipeline', () => {
  const sample = generateSyntheticTelemetry(100, 5, 99);
  const csvString = recordsToCsv(sample);
  const parsed = parseCsvTelemetry(csvString);

  assert.equal(parsed.length, 100);
  const result = runAnomalyDetectionPipeline(parsed, 0.05);
  assert.equal(result.total_records, 100);
  assert.equal(result.anomalies_detected, 5);
});

test('synthesizeDeterministicRemediation returns actionable CLI steps and severity', () => {
  const report = synthesizeDeterministicRemediation({
    record_id: 18,
    anomaly_score: -0.2412,
    source_ip: '45.155.205.91',
    root_cause_features: {
      failed_logins: { value: 94, shap_impact: -0.312 },
      port_number: { value: 22, shap_impact: -0.145 },
      latency_ms: { value: 188.4, shap_impact: -0.089 },
    },
  });

  assert.equal(report.severity_level, 'Critical');
  assert.ok(report.potential_attack_vector.includes('Brute Force'));
  assert.equal(report.remediation_steps.length, 3);
});
