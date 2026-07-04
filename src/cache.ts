import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type OsintObservation = {
  id: string;
  source: string;
  target: string;
  type: string;
  value: string;
  confidence: number;
  admissionScore: number;
  storageTier: "thin" | "full";
  observedAt: number;
  sourceRef: string;
  metadata?: Record<string, unknown>;
};

export type OsintSourceRecord = {
  source: string;
  target: string;
  fetchedAt: number;
  expiresAt: number;
  rawJson: string;
  rawBytes: number;
  status: "ok" | "error";
  error?: string;
};

export type OsintCacheStatus = {
  source?: string;
  sourceRecords: number;
  observations: number;
  rawBytes: number;
  oldestFetchedAt?: number;
  newestFetchedAt?: number;
};

const MAX_SOURCE_RECORDS_PER_SOURCE = 250;

export class OsintCache {
  readonly dbPath: string;
  #db: DatabaseSync;

  constructor(dbPath = defaultOsintDbPath()) {
    this.dbPath = dbPath;
    mkdirSync(dirname(dbPath), { recursive: true });
    this.#db = new DatabaseSync(dbPath);
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS osint_source_cache (
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        raw_json TEXT NOT NULL,
        raw_bytes INTEGER NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        PRIMARY KEY (source, target)
      );
      CREATE TABLE IF NOT EXISTS osint_observations (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        confidence REAL NOT NULL,
        admission_score REAL NOT NULL,
        storage_tier TEXT NOT NULL,
        observed_at INTEGER NOT NULL,
        source_ref TEXT NOT NULL,
        metadata_json TEXT
      );
      CREATE INDEX IF NOT EXISTS osint_observations_source_target_idx
        ON osint_observations(source, target);
      CREATE INDEX IF NOT EXISTS osint_observations_value_idx
        ON osint_observations(type, value);
    `);
  }

  getFreshSource(source: string, target: string, now = Date.now()): OsintSourceRecord | undefined {
    const row = this.#db.prepare(`
      SELECT source, target, fetched_at, expires_at, raw_json, raw_bytes, status, error
      FROM osint_source_cache
      WHERE source = ? AND target = ? AND expires_at > ?
    `).get(source, target, now) as SourceRow | undefined;
    return row ? sourceRowToRecord(row) : undefined;
  }

  putSource(record: OsintSourceRecord): void {
    this.#db.prepare(`
      INSERT INTO osint_source_cache
        (source, target, fetched_at, expires_at, raw_json, raw_bytes, status, error)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(source, target) DO UPDATE SET
        fetched_at = excluded.fetched_at,
        expires_at = excluded.expires_at,
        raw_json = excluded.raw_json,
        raw_bytes = excluded.raw_bytes,
        status = excluded.status,
        error = excluded.error
    `).run(
      record.source,
      record.target,
      record.fetchedAt,
      record.expiresAt,
      record.rawJson,
      record.rawBytes,
      record.status,
      record.error ?? null,
    );
    this.pruneSource(record.source);
  }

  replaceObservations(source: string, target: string, observations: readonly OsintObservation[]): void {
    const remove = this.#db.prepare(`
      DELETE FROM osint_observations WHERE source = ? AND target = ?
    `);
    const insert = this.#db.prepare(`
      INSERT OR REPLACE INTO osint_observations
        (id, source, target, type, value, confidence, admission_score, storage_tier, observed_at, source_ref, metadata_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    this.#db.exec("BEGIN");
    try {
      remove.run(source, target);
      for (const observation of observations) {
        insert.run(
          observation.id,
          observation.source,
          observation.target,
          observation.type,
          observation.value,
          observation.confidence,
          observation.admissionScore,
          observation.storageTier,
          observation.observedAt,
          observation.sourceRef,
          observation.metadata ? JSON.stringify(observation.metadata) : null,
        );
      }
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  listObservations(source: string, target: string, limit: number): OsintObservation[] {
    const rows = this.#db.prepare(`
      SELECT id, source, target, type, value, confidence, admission_score, storage_tier,
        observed_at, source_ref, metadata_json
      FROM osint_observations
      WHERE source = ? AND target = ?
      ORDER BY confidence DESC, value ASC
      LIMIT ?
    `).all(source, target, limit) as ObservationRow[];
    return rows.map(observationRowToRecord);
  }

  getStatus(source?: string): OsintCacheStatus {
    const row = source
      ? (this.#db.prepare(`
          SELECT COUNT(*) AS source_records, COALESCE(SUM(raw_bytes), 0) AS raw_bytes,
            MIN(fetched_at) AS oldest_fetched_at, MAX(fetched_at) AS newest_fetched_at
          FROM osint_source_cache
          WHERE source = ?
        `).get(source) as StatusRow)
      : (this.#db.prepare(`
          SELECT COUNT(*) AS source_records, COALESCE(SUM(raw_bytes), 0) AS raw_bytes,
            MIN(fetched_at) AS oldest_fetched_at, MAX(fetched_at) AS newest_fetched_at
          FROM osint_source_cache
        `).get() as StatusRow);
    const observationRow = source
      ? (this.#db.prepare(`
          SELECT COUNT(*) AS observations FROM osint_observations WHERE source = ?
        `).get(source) as { observations: number })
      : (this.#db.prepare(`
          SELECT COUNT(*) AS observations FROM osint_observations
        `).get() as { observations: number });
    return {
      ...(source ? { source } : {}),
      sourceRecords: Number(row.source_records ?? 0),
      observations: Number(observationRow.observations ?? 0),
      rawBytes: Number(row.raw_bytes ?? 0),
      ...(row.oldest_fetched_at ? { oldestFetchedAt: Number(row.oldest_fetched_at) } : {}),
      ...(row.newest_fetched_at ? { newestFetchedAt: Number(row.newest_fetched_at) } : {}),
    };
  }

  close(): void {
    this.#db.close();
  }

  private pruneSource(source: string): void {
    this.#db.prepare(`
      DELETE FROM osint_source_cache
      WHERE source = ?
        AND target NOT IN (
          SELECT target FROM osint_source_cache
          WHERE source = ?
          ORDER BY fetched_at DESC
          LIMIT ?
        )
    `).run(source, source, MAX_SOURCE_RECORDS_PER_SOURCE);
    this.#db.prepare(`
      DELETE FROM osint_observations
      WHERE source = ?
        AND target NOT IN (
          SELECT target FROM osint_source_cache WHERE source = ?
        )
    `).run(source, source);
  }
}

export function defaultOsintDbPath(): string {
  const stateRoot = process.env.OPENCLAW_STATE_DIR || join(homedir(), ".openclaw", "state");
  return process.env.OPENCLAW_OSINT_DB_PATH || join(stateRoot, "plugins", "osint", "osint.sqlite");
}

type SourceRow = {
  source: string;
  target: string;
  fetched_at: number;
  expires_at: number;
  raw_json: string;
  raw_bytes: number;
  status: "ok" | "error";
  error: string | null;
};

type ObservationRow = {
  id: string;
  source: string;
  target: string;
  type: string;
  value: string;
  confidence: number;
  admission_score: number;
  storage_tier: "thin" | "full";
  observed_at: number;
  source_ref: string;
  metadata_json: string | null;
};

type StatusRow = {
  source_records: number;
  raw_bytes: number;
  oldest_fetched_at: number | null;
  newest_fetched_at: number | null;
};

function sourceRowToRecord(row: SourceRow): OsintSourceRecord {
  return {
    source: row.source,
    target: row.target,
    fetchedAt: Number(row.fetched_at),
    expiresAt: Number(row.expires_at),
    rawJson: row.raw_json,
    rawBytes: Number(row.raw_bytes),
    status: row.status,
    ...(row.error ? { error: row.error } : {}),
  };
}

function observationRowToRecord(row: ObservationRow): OsintObservation {
  return {
    id: row.id,
    source: row.source,
    target: row.target,
    type: row.type,
    value: row.value,
    confidence: Number(row.confidence),
    admissionScore: Number(row.admission_score),
    storageTier: row.storage_tier,
    observedAt: Number(row.observed_at),
    sourceRef: row.source_ref,
    ...(row.metadata_json ? { metadata: JSON.parse(row.metadata_json) as Record<string, unknown> } : {}),
  };
}
