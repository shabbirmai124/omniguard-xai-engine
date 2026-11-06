import dotenv from 'dotenv';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';
import {
  generateSyntheticTelemetry,
  parseCsvTelemetry,
  recordsToCsv,
  runAnomalyDetectionPipeline,
  synthesizeDeterministicRemediation,
  type CriticalIncident,
  type TelemetryRecord,
} from './src/ml/xaiEngine.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '15mb' }));

function getInferenceClient(): GoogleGenAI | null {
  const apiKey = process.env.CORE_ENGINE_API_KEY || process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// Health check endpoint matching FastAPI specification
app.get('/api/v1/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'omniguard-xai-engine',
  });
});

// Endpoint to retrieve or download the 1,000-row network telemetry dataset with 50 injected attacks
app.get('/api/v1/sample-logs', (req, res) => {
  const records = generateSyntheticTelemetry(1000, 50, 42);
  if (req.query.format === 'csv') {
    const csv = recordsToCsv(records);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="sample_logs.csv"');
    res.send(csv);
    return;
  }
  res.json({
    total_records: records.length,
    injected_anomalies: 50,
    records,
  });
});

// FastAPI-compatible /api/v1/analyze endpoint accepting CSV text or JSON records
app.post('/api/v1/analyze', (req, res) => {
  try {
    const { csv, records, contamination = 0.05 } = req.body as {
      csv?: string;
      records?: TelemetryRecord[];
      contamination?: number;
    };

    let dataset: TelemetryRecord[];
    if (typeof csv === 'string' && csv.trim().length > 0) {
      dataset = parseCsvTelemetry(csv);
    } else if (Array.isArray(records) && records.length > 0) {
      dataset = records;
    } else {
      dataset = generateSyntheticTelemetry(1000, 50, 42);
    }

    const result = runAnomalyDetectionPipeline(dataset, Number(contamination) || 0.05);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Telemetry analysis failed.';
    res.status(422).json({ error: message });
  }
});

// Cognitive Remediation Agent endpoint (AutomatedThreatAnalyst)
app.post('/api/v1/remediate', async (req, res) => {
  const { incident } = req.body as { incident?: CriticalIncident };
  if (!incident || typeof incident.record_id !== 'number') {
    res.status(400).json({ error: 'Valid incident telemetry payload is required.' });
    return;
  }

  const fallbackReport = synthesizeDeterministicRemediation(incident);
  const client = getInferenceClient();

  if (!client) {
    res.json({
      report: fallbackReport,
      engine_mode: 'deterministic_xai_synthesizer',
    });
    return;
  }

  try {
    const systemInstruction =
      'You are an elite Principal Data Scientist and Cybersecurity Architect. ' +
      'Analyze the provided anomaly detection telemetry and SHAP feature attributions. ' +
      "Output a strict JSON object containing keys: 'severity_level' (Critical/High/Medium), " +
      "'executive_summary' (2 sentences explaining why the math flagged this), " +
      "'potential_attack_vector' (e.g., DDoS, SQLi, Data Exfiltration, Fraud), and " +
      "'remediation_steps' (list of 3 concrete technical actions or CLI commands).";

    const payloadForPrompt = {
      record_id: incident.record_id,
      source_ip: incident.source_ip,
      anomaly_score: incident.anomaly_score,
      root_cause_features: incident.root_cause_features,
    };

    const response = await client.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: `Analyze this anomalous telemetry record:\n${JSON.stringify(payloadForPrompt, null, 2)}`,
      config: {
        systemInstruction,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            severity_level: {
              type: Type.STRING,
              description: 'Critical, High, or Medium severity level.',
            },
            executive_summary: {
              type: Type.STRING,
              description: 'Two concise sentences explaining why the SHAP math flagged this record.',
            },
            potential_attack_vector: {
              type: Type.STRING,
              description: 'Identified threat vector such as DDoS, Brute Force, or Data Exfiltration.',
            },
            remediation_steps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'List of 3 concrete CLI commands or firewall remediation rules.',
            },
          },
          required: [
            'severity_level',
            'executive_summary',
            'potential_attack_vector',
            'remediation_steps',
          ],
        },
      },
    });

    const rawText = (response.text ?? '').trim();
    if (!rawText) {
      res.json({ report: fallbackReport, engine_mode: 'deterministic_xai_synthesizer' });
      return;
    }

    const parsed = JSON.parse(rawText);
    res.json({
      report: {
        severity_level:
          parsed.severity_level === 'Critical' ||
          parsed.severity_level === 'High' ||
          parsed.severity_level === 'Medium'
            ? parsed.severity_level
            : fallbackReport.severity_level,
        executive_summary: parsed.executive_summary || fallbackReport.executive_summary,
        potential_attack_vector:
          parsed.potential_attack_vector || fallbackReport.potential_attack_vector,
        remediation_steps:
          Array.isArray(parsed.remediation_steps) && parsed.remediation_steps.length > 0
            ? parsed.remediation_steps.slice(0, 3)
            : fallbackReport.remediation_steps,
      },
      engine_mode: 'cognitive_inference_engine',
    });
  } catch (_err) {
    res.json({
      report: fallbackReport,
      engine_mode: 'deterministic_xai_synthesizer',
    });
  }
});

async function startServer() {
  const PORT = Number(process.env.PORT) || 3000;

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`OmniGuard XAI Engine running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
