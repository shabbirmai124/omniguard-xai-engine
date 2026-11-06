import React, { useState } from 'react';
import { Check, Copy, RefreshCw, ShieldAlert, Terminal } from 'lucide-react';
import type { CriticalIncident, RemediationReport } from '../ml/xaiEngine';

interface ShapWaterfallPanelProps {
  incidents: CriticalIncident[];
  selectedIncidentId: number;
  onSelectIncident: (recordId: number) => void;
  globalFeatureImportance: Array<{ feature: string; mean_abs_shap: number }>;
  onUpdateIncidentReport: (recordId: number, report: RemediationReport) => void;
}

export const ShapWaterfallPanel: React.FC<ShapWaterfallPanelProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  globalFeatureImportance,
  onUpdateIncidentReport,
}) => {
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [lastSynthesizedRecordId, setLastSynthesizedRecordId] = useState<number | null>(null);
  const [copiedCommandIdx, setCopiedCommandIdx] = useState<number | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const activeIncident =
    incidents.find((inc) => inc.record_id === selectedIncidentId) ?? incidents[0];

  if (!activeIncident) {
    return (
      <section className="border border-neutral-300 bg-neutral-50 p-8 text-center">
        <p className="text-sm text-neutral-600">
          No anomalies flagged at the current contamination threshold. Run the XAI pipeline or
          increase contamination sensitivity to inspect SHAP feature attributions.
        </p>
      </section>
    );
  }

  const handleSynthesizeReport = async () => {
    setIsGeneratingReport(true);
    setErrorMessage(null);
    try {
      const response = await fetch('/api/v1/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident: activeIncident }),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: Failed to generate remediation assessment.`);
      }
      const data = await response.json();
      if (data.report) {
        onUpdateIncidentReport(activeIncident.record_id, data.report);
        setLastSynthesizedRecordId(activeIncident.record_id);
      }
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : 'Unable to reach cognitive remediation service.'
      );
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const handleCopyCommand = (cmd: string, index: number) => {
    navigator.clipboard?.writeText(cmd);
    setCopiedCommandIdx(index);
    setTimeout(() => setCopiedCommandIdx(null), 1800);
  };

  const handleCopyShapJson = () => {
    const payload = {
      record_id: activeIncident.record_id,
      anomaly_score: activeIncident.anomaly_score,
      root_cause_features: activeIncident.root_cause_features,
    };
    navigator.clipboard?.writeText(JSON.stringify(payload, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1800);
  };

  const allFeaturesList = Object.entries(activeIncident.all_shap_values).sort(
    (a, b) => a[1].shap_impact - b[1].shap_impact
  );
  const maxAbsShap = Math.max(
    0.05,
    ...allFeaturesList.map(([, attr]) => Math.abs(attr.shap_impact))
  );

  const report = activeIncident.remediation_report;
  const severityStyle =
    report?.severity_level === 'Critical'
      ? 'text-red-700 font-bold'
      : report?.severity_level === 'High'
      ? 'text-amber-700 font-bold'
      : 'text-neutral-900 font-semibold';

  const maxGlobalShap = Math.max(
    0.01,
    ...globalFeatureImportance.map((item) => item.mean_abs_shap)
  );

  return (
    <div className="space-y-6">
      {/* Incident Selector Strip */}
      <div className="border border-neutral-300 bg-white p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-4 border-b border-neutral-200">
          <div>
            <h2 className="text-lg font-bold text-neutral-950 tracking-tight">
              01. Explainable AI (SHAP) Root-Cause Attribution & Remediation
            </h2>
            <p className="text-sm text-neutral-600 mt-0.5">
              Select a flagged anomaly record below to inspect its exact TreeExplainer SHAP vector
              and engineering remediation runbook.
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs text-neutral-600 font-mono tabular-nums">
            <span>Top Critical Outliers ({incidents.length})</span>
            <span aria-hidden="true">·</span>
            <span>Negative SHAP = Pushes Toward Anomaly (-1)</span>
          </div>
        </div>

        {/* Interactive Incident Selector Buttons (Crisp Black & White Toggle State) */}
        <div
          className="mt-4 flex items-center gap-2 overflow-x-auto pb-1"
          role="tablist"
          aria-label="Critical Anomaly Incidents"
        >
          {incidents.slice(0, 10).map((incident) => {
            const isSelected = incident.record_id === activeIncident.record_id;
            const topFeature = Object.keys(incident.root_cause_features)[0] ?? 'packet_size';
            return (
              <button
                key={incident.record_id}
                role="tab"
                aria-selected={isSelected}
                onClick={() => onSelectIncident(incident.record_id)}
                className={`px-3.5 py-2.5 text-left transition-colors shrink-0 border cursor-pointer ${
                  isSelected
                    ? 'bg-neutral-950 border-neutral-950 text-white'
                    : 'bg-neutral-50 border-neutral-300 text-neutral-800 hover:bg-neutral-100 hover:border-neutral-400'
                }`}
              >
                <div className="text-xs font-mono font-semibold tabular-nums whitespace-nowrap">
                  Record #{incident.record_id} · Score {incident.anomaly_score.toFixed(4)}
                </div>
                <div
                  className={`text-[11px] mt-0.5 whitespace-nowrap font-mono ${
                    isSelected ? 'text-neutral-300' : 'text-neutral-600'
                  }`}
                >
                  Driver: {topFeature}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Split: Left = Mathematical SHAP Attribution, Right = Automated Threat Analyst */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left Column: SHAP Feature Attribution Breakdown (5 cols) */}
        <div className="lg:col-span-5 border border-neutral-300 bg-white p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-neutral-200">
              <div>
                <h3 className="text-base font-bold text-neutral-950">
                  Local TreeExplainer SHAP Attribution
                </h3>
                <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-600 font-mono tabular-nums mt-1">
                  <span>Record #{activeIncident.record_id}</span>
                  <span aria-hidden="true">·</span>
                  <span>IP {activeIncident.source_ip || '10.24.12.88'}</span>
                  <span aria-hidden="true">·</span>
                  <span>Tree Depth {activeIncident.isolation_depth}</span>
                </div>
              </div>
              <button
                type="button"
                onClick={handleCopyShapJson}
                className="px-3 py-1.5 text-xs font-medium text-neutral-900 bg-neutral-100 hover:bg-neutral-200 border border-neutral-300 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {copiedJson ? (
                  <Check className="w-3.5 h-3.5 text-emerald-700" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>{copiedJson ? 'Copied JSON' : 'Copy SHAP JSON'}</span>
              </button>
            </div>

            {/* Per-Feature Horizontal Waterfall Bars */}
            <div className="mt-5 space-y-4">
              {allFeaturesList.map(([featureName, attr], idx) => {
                const isAnomalyDriver = attr.shap_impact < 0;
                const widthPct = Math.min(
                  100,
                  Math.max(6, (Math.abs(attr.shap_impact) / maxAbsShap) * 100)
                );
                const isTop3 = idx < 3;

                return (
                  <div key={featureName} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs font-mono tabular-nums">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-neutral-950">{featureName}</span>
                        {isTop3 && (
                          <span className="text-[11px] text-red-700 font-medium">
                            · Root Cause #{idx + 1}
                          </span>
                        )}
                      </div>
                      <div className="text-right">
                        <span className="text-neutral-500 mr-2">
                          val={attr.value.toLocaleString()} (μ={attr.baseline_mean})
                        </span>
                        <span
                          className={
                            isAnomalyDriver
                              ? 'text-red-700 font-bold'
                              : 'text-emerald-700 font-medium'
                          }
                        >
                          {attr.shap_impact > 0
                            ? `+${attr.shap_impact.toFixed(4)}`
                            : attr.shap_impact.toFixed(4)}
                        </span>
                      </div>
                    </div>

                    <div className="h-2.5 w-full bg-neutral-100 border border-neutral-200 overflow-hidden flex items-center">
                      <div
                        className={`h-full transition-all duration-150 ${
                          isAnomalyDriver ? 'bg-neutral-950' : 'bg-neutral-400'
                        }`}
                        style={{ width: `${widthPct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Exact Top-3 JSON Payload Preview (High-Contrast Black Terminal Box) */}
          <div className="mt-6 pt-4 border-t border-neutral-200">
            <div className="flex items-center justify-between text-xs text-neutral-600 mb-2">
              <span className="font-medium text-neutral-900">
                Top-3 Root Cause Attribution Vector (SHAP JSON)
              </span>
              <span className="font-mono tabular-nums">
                Score: {activeIncident.anomaly_score.toFixed(4)}
              </span>
            </div>
            <pre className="bg-neutral-950 text-neutral-100 p-3.5 text-xs font-mono overflow-x-auto leading-relaxed tabular-nums">
              {JSON.stringify(activeIncident.root_cause_features, null, 2)}
            </pre>
          </div>
        </div>

        {/* Right Column: Cognitive Remediation Agent (7 cols) */}
        <div className="lg:col-span-7 border border-neutral-300 bg-white p-6 flex flex-col justify-between">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-200">
              <div>
                <h3 className="text-base font-bold text-neutral-950">
                  Automated Architect Assessment & Remediation Runbook
                </h3>
                <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-600 mt-1">
                  <span>Engine: AutomatedThreatAnalyst</span>
                  <span aria-hidden="true">·</span>
                  <span>Input: Isolation Forest + TreeSHAP Vector</span>
                  {lastSynthesizedRecordId === activeIncident.record_id && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span className="text-emerald-700 font-semibold">
                        Runbook Verified (#{activeIncident.record_id})
                      </span>
                    </>
                  )}
                </div>
              </div>

              <button
                type="button"
                onClick={handleSynthesizeReport}
                disabled={isGeneratingReport}
                className="px-4 py-2 text-xs font-medium text-white bg-neutral-950 hover:bg-neutral-800 disabled:opacity-60 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 ${isGeneratingReport ? 'animate-spin' : ''}`}
                />
                <span>
                  {isGeneratingReport
                    ? 'Synthesizing Runbook...'
                    : 'Run Cognitive Threat Analyst'}
                </span>
              </button>
            </div>

            {errorMessage && (
              <div className="mt-4 p-3 bg-red-50 border border-red-300 text-xs text-red-800">
                {errorMessage}
              </div>
            )}

            {report && (
              <div className="mt-5 space-y-5">
                {/* Threat Classification Metadata Row */}
                <div className="p-4 bg-neutral-50 border border-neutral-300">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-mono tabular-nums">
                    <span className="flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 text-red-700" />
                      <span className={severityStyle}>
                        Severity: {report.severity_level}
                      </span>
                    </span>
                    <span className="text-neutral-400" aria-hidden="true">
                      /
                    </span>
                    <span className="text-neutral-950 font-semibold">
                      Vector: {report.potential_attack_vector}
                    </span>
                    <span className="text-neutral-400" aria-hidden="true">
                      /
                    </span>
                    <span className="text-neutral-600">
                      Target Record #{activeIncident.record_id}
                    </span>
                  </div>

                  <p className="mt-3 text-sm text-neutral-800 leading-relaxed">
                    {report.executive_summary}
                  </p>
                </div>

                {/* Actionable CLI Remediation Commands (Stark Black Terminal Strips) */}
                <div>
                  <div className="flex items-center justify-between text-xs text-neutral-600 mb-2.5">
                    <span className="font-semibold text-neutral-950">
                      Recommended Terminal Remediation Commands (CLI / Firewall Rules)
                    </span>
                    <span className="font-mono">bash · netfilter · waf</span>
                  </div>

                  <div className="space-y-2.5">
                    {report.remediation_steps.map((step, index) => (
                      <div
                        key={index}
                        className="bg-neutral-950 text-neutral-100 p-3 flex items-start justify-between gap-3"
                      >
                        <div className="flex items-start gap-2.5 min-w-0">
                          <Terminal className="w-4 h-4 text-neutral-400 shrink-0 mt-0.5" />
                          <code className="text-xs font-mono text-neutral-100 break-all leading-relaxed">
                            {step}
                          </code>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleCopyCommand(step, index)}
                          aria-label={`Copy remediation command ${index + 1}`}
                          className="px-2.5 py-1 text-xs font-medium text-neutral-950 bg-white hover:bg-neutral-200 transition-colors flex items-center gap-1 shrink-0 cursor-pointer"
                        >
                          {copiedCommandIdx === index ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-700" />
                              <span className="text-emerald-800">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Global Dataset Feature Importance Strip at Bottom of Right Column */}
          <div className="mt-6 pt-4 border-t border-neutral-200">
            <div className="flex items-center justify-between text-xs text-neutral-600 mb-3">
              <span className="font-medium text-neutral-900">
                Global Dataset SHAP Importance (Mean |SHAP| Across All Records)
              </span>
              <span className="font-mono tabular-nums">5 Telemetry Dimensions</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {globalFeatureImportance.map((item) => {
                const pct = Math.round((item.mean_abs_shap / maxGlobalShap) * 100);
                return (
                  <div
                    key={item.feature}
                    className="bg-neutral-50 border border-neutral-300 p-2.5"
                  >
                    <div className="text-[11px] font-mono text-neutral-700 truncate">
                      {item.feature}
                    </div>
                    <div className="text-sm font-mono font-bold text-neutral-950 tabular-nums mt-0.5">
                      {item.mean_abs_shap.toFixed(4)}
                    </div>
                    <div className="mt-1.5 h-1.5 w-full bg-neutral-200 overflow-hidden">
                      <div
                        className="h-full bg-neutral-950"
                        style={{ width: `${Math.max(10, pct)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
