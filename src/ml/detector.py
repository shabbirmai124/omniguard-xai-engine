"""
Unsupervised anomaly detection and game-theoretic SHAP feature attribution core.
"""

from typing import Any, Dict, List
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import IsolationForest


class AnomalyDetectionPipeline:
    """
    Unsupervised anomaly detection pipeline with SHAP-based feature attribution.
    """

    def __init__(self, contamination: float = 0.05) -> None:
        self.model = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.explainer: Any = None
        self.feature_names: List[str] = []

    def fit_and_detect(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Fits the Isolation Forest on numerical telemetry features, computes
        SHAP values via TreeExplainer, and extracts the top critical anomalies.
        """
        numeric_df = df.select_dtypes(include=[np.number]).dropna()
        if numeric_df.empty:
            raise ValueError("Input DataFrame contains no valid numeric rows.")

        self.feature_names = numeric_df.columns.tolist()

        predictions = self.model.fit_predict(numeric_df)
        scores = self.model.decision_function(numeric_df)

        self.explainer = shap.TreeExplainer(self.model)
        shap_values = self.explainer.shap_values(numeric_df)

        results = numeric_df.copy()
        results["is_anomaly"] = np.where(predictions == -1, True, False)
        results["anomaly_score"] = np.round(scores, 4)

        anomaly_positions = np.where(predictions == -1)[0]
        sorted_positions = anomaly_positions[np.argsort(scores[anomaly_positions])]

        anomalies: List[Dict[str, Any]] = []
        for pos in sorted_positions[:10]:
            row_shap = shap_values[pos]
            top_feature_indices = np.argsort(row_shap)[:3]
            contributing_factors = {
                self.feature_names[i]: {
                    "value": float(numeric_df.iloc[pos, i]),
                    "shap_impact": float(np.round(row_shap[i], 4)),
                }
                for i in top_feature_indices
            }
            anomalies.append(
                {
                    "record_id": int(numeric_df.index[pos]),
                    "anomaly_score": float(results["anomaly_score"].iloc[pos]),
                    "root_cause_features": contributing_factors,
                }
            )

        return {
            "total_records": int(len(df)),
            "anomalies_detected": int(len(anomaly_positions)),
            "critical_incidents": anomalies,
        }
