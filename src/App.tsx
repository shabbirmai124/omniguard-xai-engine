import { useCallback, useMemo, useState } from 'react';
import { Download, Play } from 'lucide-react';
import {
  generateSyntheticTelemetry,
  parseCsvTelemetry,
  runAnomalyDetectionPipeline,
  type AnomalyPipelineOutput,
  type RemediationReport,
  type TelemetryRecord,
} from './ml/xaiEngine';
import { ShapWaterfallPanel } from './components/ShapWaterfallPanel';
import { TelemetryTable } from './components/TelemetryTable';

type ActiveSection = 'console' | 'shap' | 'telemetry' | 'architecture';

export default function App() {
  const initialRecords = useMemo(() => generateSyntheticTelemetry(1000, 50, 42), []);
  const [records, setRecords] = useState<TelemetryRecord[]>(initialRecords);
  const [datasetName, setDatasetName] = useState<string>('data/sample_logs.csv');
  const [contamination, setContamination] = useState<number>(0.05);
  const [pipelineOutput, setPipelineOutput] = useState<AnomalyPipelineOutput>(() =>
    runAnomalyDetectionPipeline(initialRecords, 0.05)
  );
  const [selectedIncidentId, setSelectedIncidentId] = useState<number>(
    () => pipelineOutput.critical_incidents[0]?.record_id ?? 4
  );
  const [activeSection, setActiveSection] = useState<ActiveSection>('console');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [apiTestResult, setApiTestResult] = useState<string | null>(null);
  const [isTestingApi, setIsTestingApi] = useState<boolean>(false);

  const handleRunPipeline = useCallback(
    async (customRecords?: TelemetryRecord[], customContamination?: number) => {
      setIsRunning(true);
      setUploadError(null);
      const targetRecords = customRecords ?? records;
      const targetContam = customContamination ?? contamination;

      try {
        const response = await fetch('/api/v1/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            records: targetRecords,
            contamination: targetContam,
          }),
        });
        if (response.ok) {
          const result: AnomalyPipelineOutput = await response.json();
          setPipelineOutput(result);
          if (result.critical_incidents.length > 0) {
            setSelectedIncidentId(result.critical_incidents[0].record_id);
          }
          setIsRunning(false);
          return;
        }
      } catch (_err) {
        // Fallback to local deterministic execution if offline
      }

      const localResult = runAnomalyDetectionPipeline(targetRecords, targetContam);
      setPipelineOutput(localResult);
      if (localResult.critical_incidents.length > 0) {
        setSelectedIncidentId(localResult.critical_incidents[0].record_id);
      }
      setIsRunning(false);
    },
    [records, contamination]
  );

  const handleContaminationChange = (newVal: number) => {
    setContamination(newVal);
    const updated = runAnomalyDetectionPipeline(records, newVal);
    setPipelineOutput(updated);
    if (
      updated.critical_incidents.length > 0 &&
      !updated.critical_incidents.some((i) => i.record_id === selectedIncidentId)
    ) {
      setSelectedIncidentId(updated.critical_incidents[0].record_id);
    }
  };

  const handleUploadCsv = (csvText: string, fileName: string) => {
    try {
      setUploadError(null);
      const parsed = parseCsvTelemetry(csvText);
      setRecords(parsed);
      setDatasetName(fileName);
      const output = runAnomalyDetectionPipeline(parsed, contamination);
      setPipelineOutput(output);
      if (output.critical_incidents.length > 0) {
        setSelectedIncidentId(output.critical_incidents[0].record_id);
      }
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Invalid CSV telemetry file.');
    }
  };

  const handleResetDefaultDataset = () => {
    setUploadError(null);
    setRecords(initialRecords);
    setDatasetName('data/sample_logs.csv');
    const output = runAnomalyDetectionPipeline(initialRecords, contamination);
    setPipelineOutput(output);
    if (output.critical_incidents.length > 0) {
      setSelectedIncidentId(output.critical_incidents[0].record_id);
    }
  };

  const handleUpdateIncidentReport = (recordId: number, report: RemediationReport) => {
    setPipelineOutput((prev) => ({
      ...prev,
      critical_incidents: prev.critical_incidents.map((inc) =>
        inc.record_id === recordId ? { ...inc, remediation_report: report } : inc
      ),
    }));
  };

  const handleSwitchSection = (section: ActiveSection) => {
    setActiveSection(section);
    window.scrollTo({ top: 0, behavior: 'instant' });
  };

  const handleTestAnalyzeEndpoint = async () => {
    setIsTestingApi(true);
    try {
      const sampleCsv = [
        'packet_size,latency_ms,failed_logins,bytes_transferred,port_number',
        '510,22.4,0,18200,443',
        '490,25.1,0,16400,443',
        '530,21.8,1,19100,80',
        '14200,780.5,95,4850000,31337',
        '480,23.0,0,17500,443',
      ].join('\n');

      const response = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csv: sampleCsv, contamination: 0.2 }),
      });
      const json = await response.json();
      setApiTestResult(
        JSON.stringify(
          {
            endpoint: 'POST /api/v1/analyze',
            status_code: response.status,
            total_records: json.total_records,
            anomalies_detected: json.anomalies_detected,
            critical_incidents: json.critical_incidents?.map(
              (inc: {
                record_id: number;
                anomaly_score: number;
                root_cause_features: unknown;
              }) => ({
                record_id: inc.record_id,
                anomaly_score: inc.anomaly_score,
                root_cause_features: inc.root_cause_features,
              })
            ),
          },
          null,
          2
        )
      );
    } catch (err) {
      setApiTestResult(
        JSON.stringify(
          { error: err instanceof Error ? err.message : 'Endpoint test failed' },
          null,
          2
        )
      );
    } finally {
      setIsTestingApi(false);
    }
  };

  const topIncident = pipelineOutput.critical_incidents[0];

  return (
    <div className="min-h-screen bg-white text-neutral-950 flex flex-col">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-neutral-950 bg-white sticky top-0 z-30">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            handleSwitchSection('console');
          }}
          className="text-lg font-bold tracking-tight text-neutral-950 font-display whitespace-nowrap shrink-0"
        >
          OmniGuard
        </a>

        {/* Zone 2: 4 concise single-line product navigation links */}
        <nav
          className="hidden md:flex items-center gap-6 text-sm font-medium text-neutral-600"
          aria-label="Primary Workspace Navigation"
        >
          <button
            type="button"
            onClick={() => handleSwitchSection('console')}
            className={`hover:text-neutral-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'console'
                ? 'text-neutral-950 font-semibold border-b-2 border-neutral-950'
                : ''
            }`}
          >
            Threat Console
          </button>
          <button
            type="button"
            onClick={() => handleSwitchSection('shap')}
            className={`hover:text-neutral-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'shap'
                ? 'text-neutral-950 font-semibold border-b-2 border-neutral-950'
                : ''
            }`}
          >
            SHAP Attribution
          </button>
          <button
            type="button"
            onClick={() => handleSwitchSection('telemetry')}
            className={`hover:text-neutral-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'telemetry'
                ? 'text-neutral-950 font-semibold border-b-2 border-neutral-950'
                : ''
            }`}
          >
            Telemetry Stream
          </button>
          <button
            type="button"
            onClick={() => handleSwitchSection('architecture')}
            className={`hover:text-neutral-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeSection === 'architecture'
                ? 'text-neutral-950 font-semibold border-b-2 border-neutral-950'
                : ''
            }`}
          >
            Pipeline Specs
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => handleRunPipeline()}
            disabled={isRunning}
            className="px-4 py-2 text-xs font-medium text-white bg-neutral-950 hover:bg-neutral-800 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {isRunning ? 'Executing Pipeline...' : 'Run XAI Pipeline'}
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-6 py-8 space-y-8">
        {/* Executive Header & 4-Column Telemetry KPI Strip */}
        <section className="space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-neutral-200">
            <div className="max-w-3xl">
              <div className="text-xs text-neutral-600 font-mono">
                Unsupervised Isolation Forest · TreeExplainer SHAP · Automated Incident Remediation
              </div>
              <h1
                className="text-2xl sm:text-3xl font-bold text-neutral-950 tracking-tight mt-1"
                style={{ textWrap: 'balance' }}
              >
                Explainable AI (XAI) Anomaly & Threat Intelligence Engine
              </h1>
              <p className="text-sm text-neutral-600 mt-2 leading-relaxed">
                Ingests real-time network and transaction telemetry, isolates zero-day outliers
                using multi-tree Isolation Forests, computes exact game-theoretic SHAP feature
                attributions, and synthesizes terminal remediation runbooks.
              </p>
            </div>

            {/* Mobile/Compact Section Switcher */}
            <div className="flex md:hidden items-center gap-1 p-1 bg-neutral-100 border border-neutral-300 overflow-x-auto">
              <button
                type="button"
                onClick={() => handleSwitchSection('console')}
                className={`px-3 py-1.5 text-xs font-medium whitespace-nowrap ${
                  activeSection === 'console' ? 'bg-neutral-950 text-white' : 'text-neutral-700'
                }`}
              >
                Console
              </button>
              <button
                type="button"
                onClick={() => handleSwitchSection('shap')}
                className={`px-3 py-1.5 text-xs font-medium whitespace-nowrap ${
                  activeSection === 'shap' ? 'bg-neutral-950 text-white' : 'text-neutral-700'
                }`}
              >
                SHAP Attribution
              </button>
              <button
                type="button"
                onClick={() => handleSwitchSection('telemetry')}
                className={`px-3 py-1.5 text-xs font-medium whitespace-nowrap ${
                  activeSection === 'telemetry' ? 'bg-neutral-950 text-white' : 'text-neutral-700'
                }`}
              >
                Telemetry Stream
              </button>
              <button
                type="button"
                onClick={() => handleSwitchSection('architecture')}
                className={`px-3 py-1.5 text-xs font-medium whitespace-nowrap ${
                  activeSection === 'architecture' ? 'bg-neutral-950 text-white' : 'text-neutral-700'
                }`}
              >
                Pipeline Specs
              </button>
            </div>
          </div>

          {/* 4-Column Quantitative KPI Strip (Crisp Monochrome Grid) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="border border-neutral-300 bg-white p-5">
              <div className="text-xs text-neutral-600 font-medium">Total Records Scanned</div>
              <div
                data-testid="kpi-total-records"
                className="text-2xl font-bold text-neutral-950 font-mono tabular-nums mt-1"
              >
                {pipelineOutput.total_records.toLocaleString()}
              </div>
              <div className="text-xs text-neutral-500 font-mono tabular-nums mt-2">
                Source: {datasetName} · {pipelineOutput.execution_time_ms} ms
              </div>
            </div>

            <div className="border border-neutral-950 bg-neutral-950 text-white p-5">
              <div className="text-xs text-neutral-300 font-medium">Anomalies Flagged</div>
              <div
                data-testid="kpi-anomalies-flagged"
                className="text-2xl font-bold text-white font-mono tabular-nums mt-1"
              >
                {pipelineOutput.anomalies_detected.toLocaleString()}
              </div>
              <div className="text-xs text-neutral-400 font-mono tabular-nums mt-2">
                Contamination Target: {(contamination * 100).toFixed(1)}%
              </div>
            </div>

            <div className="border border-neutral-300 bg-white p-5">
              <div className="text-xs text-neutral-600 font-medium">Observed Anomaly Rate</div>
              <div
                data-testid="kpi-anomaly-rate"
                className="text-2xl font-bold text-neutral-950 font-mono tabular-nums mt-1"
              >
                {pipelineOutput.anomaly_rate_pct.toFixed(2)}%
              </div>
              <div className="text-xs text-neutral-500 font-mono tabular-nums mt-2">
                Ensemble: 75 Isolation Trees + Boosted Margin
              </div>
            </div>

            <div className="border border-neutral-300 bg-white p-5">
              <div className="text-xs text-neutral-600 font-medium">Primary Root-Cause Feature</div>
              <div className="text-2xl font-bold text-neutral-950 font-mono tabular-nums mt-1 truncate">
                {pipelineOutput.global_feature_importance[0]?.feature ?? 'packet_size'}
              </div>
              <div className="text-xs text-neutral-500 font-mono tabular-nums mt-2">
                Peak Outlier: Record #{topIncident?.record_id ?? 0} (
                {topIncident?.anomaly_score.toFixed(4) ?? '-0.2500'})
              </div>
            </div>
          </div>
        </section>

        {/* Active Workspace View */}
        {activeSection === 'console' && (
          <div className="space-y-8">
            <ShapWaterfallPanel
              incidents={pipelineOutput.critical_incidents}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              globalFeatureImportance={pipelineOutput.global_feature_importance}
              onUpdateIncidentReport={handleUpdateIncidentReport}
            />

            <TelemetryTable
              pipelineOutput={pipelineOutput}
              contamination={contamination}
              onContaminationChange={handleContaminationChange}
              onRunPipeline={() => handleRunPipeline()}
              onUploadCsv={handleUploadCsv}
              onResetDefaultDataset={handleResetDefaultDataset}
              onSelectIncident={(recordId) => {
                setSelectedIncidentId(recordId);
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }}
              selectedIncidentId={selectedIncidentId}
              datasetName={datasetName}
              isRunning={isRunning}
              uploadError={uploadError}
            />
          </div>
        )}

        {activeSection === 'shap' && (
          <ShapWaterfallPanel
            incidents={pipelineOutput.critical_incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={setSelectedIncidentId}
            globalFeatureImportance={pipelineOutput.global_feature_importance}
            onUpdateIncidentReport={handleUpdateIncidentReport}
          />
        )}

        {activeSection === 'telemetry' && (
          <TelemetryTable
            pipelineOutput={pipelineOutput}
            contamination={contamination}
            onContaminationChange={handleContaminationChange}
            onRunPipeline={() => handleRunPipeline()}
            onUploadCsv={handleUploadCsv}
            onResetDefaultDataset={handleResetDefaultDataset}
            onSelectIncident={(recordId) => {
              setSelectedIncidentId(recordId);
              handleSwitchSection('shap');
            }}
            selectedIncidentId={selectedIncidentId}
            datasetName={datasetName}
            isRunning={isRunning}
            uploadError={uploadError}
          />
        )}

        {activeSection === 'architecture' && (
          <section className="space-y-6">
            <div className="border border-neutral-300 bg-white p-6">
              <h2 className="text-lg font-bold text-neutral-950 tracking-tight">
                01. Three-Stage Decoupled XAI Pipeline Specification
              </h2>
              <p className="text-sm text-neutral-600 mt-1">
                High-throughput enterprise telemetry triage with mathematical root-cause proof and
                automated incident response.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
                <div className="border border-neutral-300 bg-neutral-50 p-5 space-y-2">
                  <div className="text-xs font-mono font-semibold text-neutral-600">
                    Stage 01 · Statistical ML Core
                  </div>
                  <h3 className="text-base font-bold text-neutral-950">
                    Unsupervised Isolation Forest & Boosted Margin
                  </h3>
                  <p className="text-xs text-neutral-700 leading-relaxed">
                    Ingests high-dimensional tabular streams (`packet_size`, `latency_ms`,
                    `failed_logins`, `bytes_transferred`, `port_number`) and partitions outliers via
                    recursive random tree splits without requiring historical attack labels.
                  </p>
                </div>

                <div className="border border-neutral-300 bg-neutral-50 p-5 space-y-2">
                  <div className="text-xs font-mono font-semibold text-neutral-600">
                    Stage 02 · Explainable AI Layer
                  </div>
                  <h3 className="text-base font-bold text-neutral-950">
                    Game-Theoretic SHAP Feature Attribution
                  </h3>
                  <p className="text-xs text-neutral-700 leading-relaxed">
                    Executes `shap.TreeExplainer` across the Isolation Forest ensemble to compute
                    exact additive feature impacts, isolating the top 3 numerical drivers pushing a
                    record toward an anomaly classification.
                  </p>
                </div>

                <div className="border border-neutral-300 bg-neutral-50 p-5 space-y-2">
                  <div className="text-xs font-mono font-semibold text-neutral-600">
                    Stage 03 · Cognitive Remediation Agent
                  </div>
                  <h3 className="text-base font-bold text-neutral-950">
                    Automated Threat Analyst
                  </h3>
                  <p className="text-xs text-neutral-700 leading-relaxed">
                    Translates mathematical SHAP attribution vectors into structured incident reports
                    containing severity classifications, attack vector identification, and concrete
                    Linux firewall / Kubernetes remediation commands.
                  </p>
                </div>
              </div>
            </div>

            {/* Live REST Endpoint Verification */}
            <div className="border border-neutral-300 bg-white p-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-200">
                <div>
                  <h2 className="text-lg font-bold text-neutral-950 tracking-tight">
                    02. REST API Endpoint Verification (POST /api/v1/analyze)
                  </h2>
                  <p className="text-xs text-neutral-600 mt-0.5">
                    Execute a live HTTP POST request against the ingestion endpoint using a 5-row
                    CSV batch containing an injected Port 31337 C2 anomaly.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleTestAnalyzeEndpoint}
                  disabled={isTestingApi}
                  className="px-4 py-2 text-xs font-medium text-white bg-neutral-950 hover:bg-neutral-800 disabled:opacity-50 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{isTestingApi ? 'Sending Request...' : 'Test POST /api/v1/analyze'}</span>
                </button>
              </div>

              {apiTestResult ? (
                <pre className="mt-4 p-4 bg-neutral-950 text-neutral-100 text-xs font-mono overflow-x-auto leading-relaxed tabular-nums">
                  {apiTestResult}
                </pre>
              ) : (
                <div className="mt-4 p-4 bg-neutral-50 border border-neutral-300 text-xs text-neutral-700 font-mono">
                  Click &quot;Test POST /api/v1/analyze&quot; to inspect the live JSON response
                  payload.
                </div>
              )}
            </div>
          </section>
        )}
      </main>

      {/* Quiet Product Footer */}
      <footer className="border-t border-neutral-200 bg-neutral-50 py-5 px-6 text-xs text-neutral-600">
        <div className="max-w-[1440px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <span>OmniGuard XAI Engine — Unsupervised Anomaly Detection & SHAP Attribution Platform</span>
          <div className="flex items-center gap-4">
            <a
              href="/api/v1/sample-logs?format=csv"
              className="hover:text-neutral-950 font-medium transition-colors flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export sample_logs.csv</span>
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
