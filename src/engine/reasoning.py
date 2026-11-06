"""
Cognitive reasoning engine translating mathematical SHAP attributions into
executive incident summaries and actionable terminal remediation commands.
"""

import json
import os
from typing import Any, Dict
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()


class AutomatedThreatAnalyst:
    """
    Cognitive reasoning engine that translates SHAP mathematical attributions
    into actionable engineering remediation plans.
    """

    def __init__(self) -> None:
        api_key = os.getenv("CORE_ENGINE_API_KEY")
        if not api_key:
            raise ValueError("CORE_ENGINE_API_KEY environment variable not set.")
        self._client = genai.Client(api_key=api_key)

    def generate_incident_report(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes a structured remediation report for an anomalous telemetry record.
        """
        system_instruction = (
            "You are an elite Principal Data Scientist and Cybersecurity Architect. "
            "Analyze the provided anomaly detection telemetry and SHAP feature attributions. "
            "Output a strict JSON object containing keys: 'severity_level' (Critical/High/Medium), "
            "'executive_summary' (2 sentences explaining why the math flagged this), "
            "'potential_attack_vector' (e.g., DDoS, SQLi, Data Exfiltration, Fraud), and "
            "'remediation_steps' (list of 3 concrete technical actions or CLI commands)."
        )

        prompt = f"Analyze this anomalous telemetry record:\n{json.dumps(incident_data, indent=2)}"

        response = self._client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )
        return json.loads(response.text)
