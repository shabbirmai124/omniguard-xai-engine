import React, { useMemo, useRef, useState } from 'react';
import { Download, Search, Upload, Play, RotateCcw } from 'lucide-react';
import type { AnomalyPipelineOutput } from '../ml/xaiEngine';

interface TelemetryTableProps {
  pipelineOutput: AnomalyPipelineOutput;
  contamination: number;
  onContaminationChange: (val: number) => void;
  onRunPipeline: () => void;
  onUploadCsv: (csvText: string, fileName: string) => void;
  onResetDefaultDataset: () => void;
  onSelectIncident: (recordId: number) => void;
  selectedIncidentId: number;
  datasetName: string;
  isRunning: boolean;
  uploadError: string | null;
}

export const TelemetryTable: React.FC<TelemetryTableProps> = ({
  pipelineOutput,
  contamination,
  onContaminationChange,
  onRunPipeline,
  onUploadCsv,
  onResetDefaultDataset,
  onSelectIncident,
  selectedIncidentId,
  datasetName,
  isRunning,
  uploadError,
}) => {
  const [statusFilter, setStatusFilter] = useState<'all' | 'anomalies' | 'normal'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(0);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const pageSize = 15;

  const filteredRecords = useMemo(() => {
    return pipelineOutput.annotated_records.filter((row) => {
      if (statusFilter === 'anomalies' && !row.is_anomaly) return false;
      if (statusFilter === 'normal' && row.is_anomaly) return false;

      if (searchQuery.trim().length > 0) {
        const q = searchQuery.trim().toLowerCase();
        const matchId = String(row.record_id).includes(q);
        const matchIp = String(row.source_ip || '').toLowerCase().includes(q);
        const matchPort = String(row.port_number).includes(q);
        const matchDriver = String(row.top_driver || '').toLowerCase().includes(q);
        return matchId || matchIp || matchPort || matchDriver;
      }
      return true;
    });
  }, [pipelineOutput.annotated_records, statusFilter, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / pageSize));
  const currentPage = Math.min(page, totalPages - 1);
  const pageRecords = filteredRecords.slice(
    currentPage * pageSize,
    currentPage * pageSize + pageSize
  );

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        onUploadCsv(reader.result, file.name);
        setPage(0);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleDownloadSampleCsv = () => {
    window.location.href = '/api/v1/sample-logs?format=csv';
  };

  return (
    <section className="border border-neutral-300 bg-white p-6 space-y-5">
      {/* Header & Ingestion Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-neutral-200">
        <div>
          <h2 className="text-lg font-bold text-neutral-950 tracking-tight">
            02. Telemetry Ingestion Stream & Unsupervised Outlier Matrix
          </h2>
          <div className="flex flex-wrap items-center gap-2 text-xs text-neutral-600 font-mono tabular-nums mt-1">
            <span>Dataset: {datasetName}</span>
            <span aria-hidden="true">·</span>
            <span>{pipelineOutput.total_records.toLocaleString()} rows</span>
            <span aria-hidden="true">·</span>
            <span>Execution: {pipelineOutput.execution_time_ms} ms</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv"
            onChange={handleFileChange}
            className="hidden"
            aria-label="Upload Telemetry CSV File"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="px-3.5 py-2 text-xs font-medium text-neutral-900 bg-neutral-100 hover:bg-neutral-200 border border-neutral-300 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload CSV</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadSampleCsv}
            className="px-3.5 py-2 text-xs font-medium text-neutral-900 bg-neutral-100 hover:bg-neutral-200 border border-neutral-300 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download sample_logs.csv (1,000 rows)</span>
          </button>

          {datasetName !== 'data/sample_logs.csv' && (
            <button
              type="button"
              onClick={() => {
                onResetDefaultDataset();
                setPage(0);
              }}
              className="px-3 py-2 text-xs font-medium text-neutral-800 bg-white hover:bg-neutral-100 border border-neutral-300 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Default Logs</span>
            </button>
          )}
        </div>
      </div>

      {uploadError && (
        <div
          role="alert"
          className="p-3 bg-red-50 border border-red-300 text-xs text-red-800"
        >
          {uploadError}
        </div>
      )}

      {/* Filter Bar, Search & Contamination Control */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Interactive Segmented Filter Controls */}
          <div
            className="flex items-center gap-1 p-1 bg-neutral-100 border border-neutral-300"
            role="group"
            aria-label="Filter telemetry records by anomaly status"
          >
            <button
              type="button"
              onClick={() => {
                setStatusFilter('all');
                setPage(0);
              }}
              className={`px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                statusFilter === 'all'
                  ? 'bg-neutral-950 text-white'
                  : 'text-neutral-700 hover:text-neutral-950'
              }`}
            >
              All Records ({pipelineOutput.total_records})
            </button>
            <button
              type="button"
              onClick={() => {
                setStatusFilter('anomalies');
                setPage(0);
              }}
              className={`px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                statusFilter === 'anomalies'
                  ? 'bg-neutral-950 text-white'
                  : 'text-neutral-700 hover:text-neutral-950'
              }`}
            >
              Anomalies Flagged ({pipelineOutput.anomalies_detected})
            </button>
            <button
              type="button"
              onClick={() => {
                setStatusFilter('normal');
                setPage(0);
              }}
              className={`px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                statusFilter === 'normal'
                  ? 'bg-neutral-950 text-white'
                  : 'text-neutral-700 hover:text-neutral-950'
              }`}
            >
              Baseline Normal ({pipelineOutput.total_records - pipelineOutput.anomalies_detected})
            </button>
          </div>

          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-neutral-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(0);
              }}
              placeholder="Search Record ID, IP, port, feature..."
              aria-label="Search telemetry records"
              className="pl-8 pr-3 py-1.5 text-xs bg-white border border-neutral-300 text-neutral-950 placeholder:text-neutral-500 focus:outline-none focus:border-neutral-950 w-64"
            />
          </div>
        </div>

        {/* Contamination Parameter & Execute Pipeline Button */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2.5 text-xs">
            <label htmlFor="contamination-slider" className="text-neutral-700 whitespace-nowrap font-medium">
              Contamination Threshold:
            </label>
            <input
              id="contamination-slider"
              type="range"
              min="0.01"
              max="0.15"
              step="0.01"
              value={contamination}
              onChange={(e) => onContaminationChange(Number(e.target.value))}
              className="w-28 accent-neutral-950 cursor-pointer"
            />
            <span className="font-mono font-bold text-neutral-950 tabular-nums w-12">
              {Math.round(contamination * 100)}%
            </span>
          </div>

          <button
            type="button"
            onClick={onRunPipeline}
            disabled={isRunning}
            className="px-4 py-2 text-xs font-medium text-white bg-neutral-950 hover:bg-neutral-800 disabled:opacity-50 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{isRunning ? 'Executing Pipeline...' : 'Run XAI Anomaly Pipeline'}</span>
          </button>
        </div>
      </div>

      {/* High-Density Data Grid */}
      <div className="overflow-x-auto border border-neutral-300">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-neutral-100 border-b border-neutral-300 text-[11px] font-semibold text-neutral-700">
              <th className="py-2.5 px-3">Record ID</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3 text-right">packet_size</th>
              <th className="py-2.5 px-3 text-right">latency_ms</th>
              <th className="py-2.5 px-3 text-right">failed_logins</th>
              <th className="py-2.5 px-3 text-right">bytes_transferred</th>
              <th className="py-2.5 px-3 text-right">port_number</th>
              <th className="py-2.5 px-3 text-right">Decision Score</th>
              <th className="py-2.5 px-3">Top SHAP Driver</th>
              <th className="py-2.5 px-3">Classification</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-200 text-xs font-mono tabular-nums">
            {pageRecords.length === 0 ? (
              <tr>
                <td colSpan={11} className="py-8 text-center text-neutral-600 font-sans">
                  No telemetry records match the active filter criteria.
                </td>
              </tr>
            ) : (
              pageRecords.map((row) => {
                const isSelected = row.record_id === selectedIncidentId;
                return (
                  <tr
                    key={row.record_id}
                    className={`transition-colors ${
                      isSelected
                        ? 'bg-neutral-200/80'
                        : row.is_anomaly
                        ? 'bg-red-50/60 hover:bg-red-100/60'
                        : 'bg-white hover:bg-neutral-50'
                    }`}
                  >
                    <td className="py-2 px-3 font-bold text-neutral-950">
                      #{row.record_id}
                    </td>
                    <td className="py-2 px-3 text-neutral-800">
                      {row.source_ip || '10.24.10.45'}
                    </td>
                    <td className="py-2 px-3 text-right text-neutral-900">
                      {Number(row.packet_size).toLocaleString()}
                    </td>
                    <td className="py-2 px-3 text-right text-neutral-900">
                      {Number(row.latency_ms).toFixed(2)}
                    </td>
                    <td className="py-2 px-3 text-right text-neutral-900">
                      {row.failed_logins}
                    </td>
                    <td className="py-2 px-3 text-right text-neutral-900">
                      {Number(row.bytes_transferred).toLocaleString()}
                    </td>
                    <td className="py-2 px-3 text-right text-neutral-800">
                      {row.port_number}
                    </td>
                    <td
                      className={`py-2 px-3 text-right font-bold ${
                        row.is_anomaly ? 'text-red-700' : 'text-emerald-700'
                      }`}
                    >
                      {row.anomaly_score > 0
                        ? `+${row.anomaly_score.toFixed(4)}`
                        : row.anomaly_score.toFixed(4)}
                    </td>
                    <td className="py-2 px-3 text-neutral-900">
                      {row.top_driver}{' '}
                      <span className="text-neutral-500">
                        ({row.top_shap_impact > 0 ? '+' : ''}
                        {row.top_shap_impact.toFixed(3)})
                      </span>
                    </td>
                    <td className="py-2 px-3 font-sans">
                      {row.is_anomaly ? (
                        <span className="text-red-700 font-semibold">
                          Anomaly · Outlier
                        </span>
                      ) : (
                        <span className="text-neutral-700">Nominal · Baseline</span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right font-sans">
                      {row.is_anomaly ? (
                        <button
                          type="button"
                          onClick={() => onSelectIncident(row.record_id)}
                          className="text-xs font-semibold text-neutral-950 underline underline-offset-2 hover:text-neutral-600 whitespace-nowrap cursor-pointer"
                        >
                          Inspect SHAP
                        </button>
                      ) : (
                        <span className="text-neutral-400">—</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-neutral-600 font-mono tabular-nums">
        <div>
          Showing {filteredRecords.length === 0 ? 0 : currentPage * pageSize + 1}–
          {Math.min(filteredRecords.length, (currentPage + 1) * pageSize)} of{' '}
          {filteredRecords.length.toLocaleString()} filtered records
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={currentPage === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="px-3 py-1.5 bg-white border border-neutral-300 text-neutral-900 hover:bg-neutral-100 disabled:opacity-40 cursor-pointer"
          >
            Previous
          </button>
          <span className="px-2 text-neutral-900 font-medium">
            Page {currentPage + 1} / {totalPages}
          </span>
          <button
            type="button"
            disabled={currentPage >= totalPages - 1}
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            className="px-3 py-1.5 bg-white border border-neutral-300 text-neutral-900 hover:bg-neutral-100 disabled:opacity-40 cursor-pointer"
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
};
