# OmniGuard Core Engine (`src/`)

This directory contains the decoupled Python backend modules powering **OmniGuard**.

## Module Breakdown

### 1. `src/ml/detector.py` — Unsupervised Anomaly Detection & SHAP Core
- **`AnomalyDetectionPipeline`**: Wraps `sklearn.ensemble.IsolationForest` (`n_estimators=150`, `random_state=42`, `n_jobs=-1`) and `shap.TreeExplainer`.
- **`fit_and_detect(df: pd.DataFrame)`**:
  1. Filters incoming DataFrames to numeric columns and drops malformed `NaN` rows.
  2. Computes `fit_predict` (`-1` for outlier, `1` for inlier) and continuous `decision_function` scores.
  3. Runs `shap.TreeExplainer` to compute exact additive feature attributions for every record.
  4. Extracts the top 3 negative SHAP contributors (`np.argsort(row_shap)[:3]`) for each critical outlier.

### 2. `src/engine/reasoning.py` — Cognitive Remediation Wrapper
- **`AutomatedThreatAnalyst`**: Decoupled inference client that reads `CORE_ENGINE_API_KEY` from the environment and translates mathematical SHAP attributions into a strict JSON remediation schema (`severity_level`, `executive_summary`, `potential_attack_vector`, `remediation_steps`).

### 3. `src/api/main.py` — FastAPI REST Service
- **`GET /api/v1/health`**: Container liveness and readiness probe.
- **`POST /api/v1/analyze`**: Accepts multipart CSV uploads (`UploadFile`), validates numerical schema rules, runs `AnomalyDetectionPipeline`, and returns Pydantic-validated JSON.
