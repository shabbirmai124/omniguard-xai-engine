"""
FastAPI REST microservice for the OmniGuard Explainable AI (XAI) Engine.
Exposes endpoints for CSV telemetry ingestion, SHAP root-cause attribution,
and automated threat remediation synthesis.
"""

import io
import logging
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.engine.reasoning import AutomatedThreatAnalyst
from src.ml.detector import AnomalyDetectionPipeline

logger = logging.getLogger("omniguard.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

REQUIRED_COLUMNS: List[str] = [
    "packet_size",
    "latency_ms",
    "failed_logins",
    "bytes_transferred",
    "port_number",
]


class FeatureImpact(BaseModel):
    """Game-theoretic SHAP impact for a single telemetry feature."""

    value: float = Field(..., description="Observed raw numeric value of the feature.")
    shap_impact: float = Field(..., description="Additive SHAP value driving the anomaly decision.")


class IncidentRecord(BaseModel):
    """Structured representation of a flagged anomalous telemetry record."""

    record_id: int = Field(..., description="Zero-based row index in the analyzed dataset.")
    anomaly_score: float = Field(..., description="Isolation Forest decision score (negative indicates outlier).")
    root_cause_features: Dict[str, FeatureImpact] = Field(
        ..., description="Top 3 features pushing the record toward an anomaly classification."
    )
    remediation_report: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional cognitive remediation runbook for critical incidents."
    )


class AnalyzeResponse(BaseModel):
    """Response payload returned by POST /api/v1/analyze."""

    total_records: int = Field(..., ge=1, description="Total number of telemetry records evaluated.")
    anomalies_detected: int = Field(..., ge=0, description="Total number of records flagged as anomalous.")
    contamination_rate: float = Field(..., description="Configured contamination hyperparameter.")
    critical_incidents: List[IncidentRecord] = Field(
        ..., description="Top critical anomalies ordered by anomaly severity with SHAP attributions."
    )


app = FastAPI(
    title="OmniGuard XAI Anomaly & Threat Intelligence API",
    description="Enterprise unsupervised anomaly detection and SHAP root-cause attribution service.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, str]:
    """Liveness and readiness probe for container orchestration."""
    return {"status": "healthy", "service": "omniguard-xai-engine"}


@app.post(
    "/api/v1/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest CSV telemetry and compute Isolation Forest + SHAP anomaly attributions",
)
async def analyze_telemetry_csv(
    file: UploadFile = File(..., description="CSV file containing network or transaction telemetry."),
    contamination: float = Query(
        default=0.05,
        ge=0.005,
        le=0.40,
        description="Expected proportion of outliers in the dataset.",
    ),
    enrich_remediation: bool = Query(
        default=False,
        description="If true, runs AutomatedThreatAnalyst on the top 3 critical incidents.",
    ),
) -> AnalyzeResponse:
    """
    Accepts a CSV telemetry upload, validates numerical columns, runs the
    Isolation Forest + TreeExplainer SHAP pipeline, and returns structured JSON.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a .csv extension.",
        )

    try:
        raw_bytes = await file.read()
        df = pd.read_csv(io.BytesIO(raw_bytes))
    except Exception as exc:
        logger.error("Failed to parse uploaded CSV file: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unable to parse CSV payload: {str(exc)}",
        ) from exc

    if df.empty:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded CSV dataset contains zero rows.",
        )

    numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
    if not numeric_cols:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"CSV must contain numeric telemetry columns (expected: {REQUIRED_COLUMNS}).",
        )

    try:
        pipeline = AnomalyDetectionPipeline(contamination=contamination)
        result = pipeline.fit_and_detect(df)
    except Exception as exc:
        logger.exception("Pipeline execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly detection pipeline error: {str(exc)}",
        ) from exc

    incidents: List[Dict[str, Any]] = result["critical_incidents"]

    if enrich_remediation and incidents:
        try:
            analyst = AutomatedThreatAnalyst()
            for incident in incidents[:3]:
                incident["remediation_report"] = analyst.generate_incident_report(incident)
        except Exception as exc:
            logger.warning("Cognitive remediation enrichment skipped: %s", exc)

    return AnalyzeResponse(
        total_records=result["total_records"],
        anomalies_detected=result["anomalies_detected"],
        contamination_rate=contamination,
        critical_incidents=incidents,
    )
