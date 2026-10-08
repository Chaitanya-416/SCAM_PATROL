import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { randomUUID } from "node:crypto";
import type {
  IncidentStatus,
  ReputationRecord,
  RiskSignal,
  ScanInput,
  ScanKind,
  ScanResult,
} from "@workspace/api-zod";

const configuredPath = process.env.SCAMPATROL_DB_PATH;
const databasePath = resolve(
  process.cwd(),
  configuredPath ?? "data/scampatrol.sqlite",
);

mkdirSync(dirname(databasePath), { recursive: true });

const database = new DatabaseSync(databasePath);
database.exec("PRAGMA foreign_keys = ON");
database.exec(`
  CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    original_input TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    category TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    decision TEXT NOT NULL,
    status TEXT NOT NULL,
    is_blocked INTEGER NOT NULL DEFAULT 0,
    signals_json TEXT NOT NULL,
    report_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS incidents_created_at_idx ON incidents(created_at DESC);
  CREATE INDEX IF NOT EXISTS incidents_kind_idx ON incidents(kind);
  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    identifier TEXT NOT NULL,
    kind TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS reports_identifier_idx ON reports(kind, identifier);
  CREATE TABLE IF NOT EXISTS reputation (
    identifier TEXT NOT NULL,
    kind TEXT NOT NULL,
    report_count INTEGER NOT NULL DEFAULT 0,
    risk_boost INTEGER NOT NULL DEFAULT 0,
    last_reported_at TEXT NOT NULL,
    PRIMARY KEY (kind, identifier)
  );
`);

interface IncidentRow {
  id: string;
  kind: ScanKind;
  target: string;
  original_input: string;
  risk_score: number;
  category: string;
  recommendation: string;
  decision: ScanResult["decision"];
  status: IncidentStatus;
  is_blocked: number;
  signals_json: string;
  report_count: number;
  created_at: string;
}

interface ReputationRow {
  identifier: string;
  kind: string;
  report_count: number;
  risk_boost: number;
  last_reported_at: string;
}

export interface ReputationSignal {
  reportCount: number;
  riskBoost: number;
}

function incidentFromRow(row: IncidentRow): ScanResult {
  return {
    id: row.id,
    kind: row.kind,
    target: row.target,
    originalInput: row.original_input,
    riskScore: row.risk_score,
    category: row.category,
    recommendation: row.recommendation,
    decision: row.decision,
    status: row.status,
    isBlocked: row.is_blocked === 1,
    signals: JSON.parse(row.signals_json) as RiskSignal[],
    reportCount: row.report_count,
    createdAt: new Date(row.created_at),
  };
}

function reputationFromRow(row: ReputationRow): ReputationRecord {
  return {
    identifier: row.identifier,
    kind: row.kind,
    reportCount: row.report_count,
    riskBoost: row.risk_boost,
    lastReportedAt: new Date(row.last_reported_at),
    isReported: row.report_count > 0,
  };
}

export function getReputationSignal(
  kind: ScanKind,
  identifier: string,
): ReputationSignal {
  const row = database
    .prepare(
      "SELECT report_count, risk_boost FROM reputation WHERE kind = ? AND identifier = ?",
    )
    .get(kind, identifier) as
    | Pick<ReputationRow, "report_count" | "risk_boost">
    | undefined;
  return row
    ? { reportCount: row.report_count, riskBoost: row.risk_boost }
    : { reportCount: 0, riskBoost: 0 };
}

export function insertIncident(
  input: ScanInput,
  result: Omit<
    ScanResult,
    "id" | "createdAt" | "reportCount" | "originalInput" | "kind"
  >,
): ScanResult {
  const id = randomUUID();
  const createdAt = new Date();
  database
    .prepare(
      `INSERT INTO incidents (
        id, kind, target, original_input, risk_score, category, recommendation,
        decision, status, is_blocked, signals_json, report_count, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    )
    .run(
      id,
      input.kind,
      result.target,
      input.input,
      result.riskScore,
      result.category,
      result.recommendation,
      result.decision,
      result.status,
      result.isBlocked ? 1 : 0,
      JSON.stringify(result.signals),
      createdAt.toISOString(),
    );
  return {
    ...result,
    kind: input.kind,
    id,
    originalInput: input.input,
    reportCount: 0,
    createdAt,
  };
}

export function getIncident(id: string): ScanResult | null {
  const row = database
    .prepare("SELECT * FROM incidents WHERE id = ?")
    .get(id) as IncidentRow | undefined;
  return row ? incidentFromRow(row) : null;
}

export interface IncidentFilters {
  search?: string;
  kind?: ScanKind;
  minRisk?: number;
  limit: number;
  offset: number;
}

export function listIncidents(filters: IncidentFilters): {
  items: ScanResult[];
  total: number;
} {
  const clauses: string[] = [];
  const values: SQLInputValue[] = [];

  if (filters.search?.trim()) {
    clauses.push("(target LIKE ? ESCAPE '\\' OR original_input LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\')");
    const search = `%${filters.search.trim().replace(/[\\%_]/g, "\\$&")}%`;
    values.push(search, search, search);
  }
  if (filters.kind) {
    clauses.push("kind = ?");
    values.push(filters.kind);
  }
  if (filters.minRisk !== undefined) {
    clauses.push("risk_score >= ?");
    values.push(filters.minRisk);
  }

  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const countRow = database
    .prepare(`SELECT COUNT(*) AS total FROM incidents ${where}`)
    .get(...values) as { total: number };
  const rows = database
    .prepare(
      `SELECT * FROM incidents ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(...values, filters.limit, filters.offset) as unknown as IncidentRow[];
  return { items: rows.map(incidentFromRow), total: countRow.total };
}

export function getDashboardData(): {
  totalScans: number;
  highRiskScans: number;
  blockedCalls: number;
  reportedTargets: number;
  recentIncidents: ScanResult[];
  weeklyActivity: Array<{ date: Date; count: number }>;
  categoryBreakdown: Array<{ category: string; count: number }>;
} {
  const counts = database
    .prepare(
      `SELECT
        COUNT(*) AS total_scans,
        SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) AS high_risk_scans,
        SUM(CASE WHEN is_blocked = 1 THEN 1 ELSE 0 END) AS blocked_calls
      FROM incidents`,
    )
    .get() as {
    total_scans: number;
    high_risk_scans: number | null;
    blocked_calls: number | null;
  };
  const targetRow = database
    .prepare("SELECT COUNT(*) AS total FROM reputation WHERE report_count > 0")
    .get() as { total: number };
  const recentRows = database
    .prepare("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 6")
    .all() as unknown as IncidentRow[];
  const categoryRows = database
    .prepare(
      `SELECT category, COUNT(*) AS count FROM incidents
       GROUP BY category ORDER BY count DESC, category ASC LIMIT 6`,
    )
    .all() as Array<{ category: string; count: number }>;

  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const start = new Date(today);
  start.setUTCDate(start.getUTCDate() - 6);
  const activityRows = database
    .prepare(
      `SELECT substr(created_at, 1, 10) AS date, COUNT(*) AS count
       FROM incidents WHERE created_at >= ? GROUP BY date`,
    )
    .all(start.toISOString()) as Array<{ date: string; count: number }>;
  const activityByDate = new Map(
    activityRows.map((row) => [row.date, row.count]),
  );
  const weeklyActivity = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(start);
    date.setUTCDate(start.getUTCDate() + index);
    return {
      date,
      count: activityByDate.get(date.toISOString().slice(0, 10)) ?? 0,
    };
  });

  return {
    totalScans: counts.total_scans,
    highRiskScans: counts.high_risk_scans ?? 0,
    blockedCalls: counts.blocked_calls ?? 0,
    reportedTargets: targetRow.total,
    recentIncidents: recentRows.map(incidentFromRow),
    weeklyActivity,
    categoryBreakdown: categoryRows,
  };
}

export function listReputation(
  search: string | undefined,
  limit: number,
): ReputationRecord[] {
  const needle = search?.trim();
  const rows = needle
    ? (database
        .prepare(
          `SELECT * FROM reputation
           WHERE report_count > 0 AND identifier LIKE ? ESCAPE '\\'
           ORDER BY report_count DESC, last_reported_at DESC LIMIT ?`,
        )
        .all(
          `%${needle.replace(/[\\%_]/g, "\\$&")}%`,
          limit,
        ) as unknown as ReputationRow[])
    : (database
        .prepare(
          `SELECT * FROM reputation WHERE report_count > 0
           ORDER BY report_count DESC, last_reported_at DESC LIMIT ?`,
        )
        .all(limit) as unknown as ReputationRow[]);
  return rows.map(reputationFromRow);
}

export function reportIncident(
  id: string,
  reason?: string,
): ReputationRecord | null {
  const incident = getIncident(id);
  if (!incident) return null;

  const now = new Date().toISOString();
  database.exec("BEGIN IMMEDIATE");
  try {
    const existingReport = database
      .prepare("SELECT id FROM reports WHERE incident_id = ?")
      .get(id);
    if (!existingReport) {
      database
        .prepare(
          `INSERT INTO reports (id, incident_id, identifier, kind, reason, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(randomUUID(), id, incident.target, incident.kind, reason ?? null, now);
      database
        .prepare(
          `INSERT INTO reputation (identifier, kind, report_count, risk_boost, last_reported_at)
           VALUES (?, ?, 1, 8, ?)
           ON CONFLICT(kind, identifier) DO UPDATE SET
             report_count = reputation.report_count + 1,
             risk_boost = MIN(35, (reputation.report_count + 1) * 8),
             last_reported_at = excluded.last_reported_at`,
        )
        .run(incident.target, incident.kind, now);
    }
    database
      .prepare(
        `UPDATE incidents
         SET status = CASE WHEN id = ? THEN 'reported' ELSE status END,
             report_count = (SELECT report_count FROM reputation
                             WHERE kind = ? AND identifier = ?)
         WHERE kind = ? AND target = ?`,
      )
      .run(id, incident.kind, incident.target, incident.kind, incident.target);
    database.exec("COMMIT");
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }

  const row = database
    .prepare("SELECT * FROM reputation WHERE kind = ? AND identifier = ?")
    .get(incident.kind, incident.target) as ReputationRow | undefined;
  if (!row) throw new Error("Reputation update did not create a record");
  return reputationFromRow(row);
}

export function hasIncidents(): boolean {
  const row = database
    .prepare("SELECT COUNT(*) AS total FROM incidents")
    .get() as { total: number };
  return row.total > 0;
}
