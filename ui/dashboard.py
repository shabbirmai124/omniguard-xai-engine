"""
Interactive Streamlit frontend for the OmniGuard XAI Threat Engine.
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.engine.reasoning import AutomatedThreatAnalyst
from src.ml.detector import AnomalyDetectionPipeline

st.set_page_config(page_title="OmniGuard XAI Engine", layout="wide")

st.title("OmniGuard: Autonomous Anomaly & XAI Threat Engine")
st.markdown(
    "Real-time unsupervised telemetry analysis powered by **Isolation Forests**, "
    "**SHAP**, and **Automated Incident Reasoning**."
)

uploaded_file = st.file_uploader("Upload Telemetry / Transaction Dataset (CSV)", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.subheader("1. Raw Telemetry Preview")
    st.dataframe(df.head(5), use_container_width=True)

    if st.button("Run XAI Anomaly Pipeline"):
        with st.spinner("Executing Isolation Forest & calculating SHAP attributions..."):
            pipeline = AnomalyDetectionPipeline(contamination=0.05)
            output = pipeline.fit_and_detect(df)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records Scanned", output["total_records"])
        col2.metric("Anomalies Flagged", output["anomalies_detected"])
        col3.metric(
            "Anomaly Rate",
            f"{(output['anomalies_detected'] / output['total_records']) * 100:.2f}%",
        )

        st.subheader("2. Explainable AI (SHAP) Root-Cause Analysis & Remediation")
        analyst = AutomatedThreatAnalyst()

        for incident in output["critical_incidents"][:3]:
            with st.expander(
                f"Incident Record #{incident['record_id']} (Score: {incident['anomaly_score']})",
                expanded=True,
            ):
                c1, c2 = st.columns([1, 2])
                with c1:
                    st.markdown("**Top Contributing Features (SHAP):**")
                    st.json(incident["root_cause_features"])
                with c2:
                    st.markdown("**Automated Architect Assessment:**")
                    report = analyst.generate_incident_report(incident)
                    st.error(
                        f"**Severity:** {report.get('severity_level')} | "
                        f"**Vector:** {report.get('potential_attack_vector')}"
                    )
                    st.write(report.get("executive_summary"))
                    st.markdown("**Recommended Remediation:**")
                    for step in report.get("remediation_steps", []):
                        st.code(step, language="bash")
