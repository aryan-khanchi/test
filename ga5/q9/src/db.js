'use strict';
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'mailroom.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS dossier_decisions (
  fingerprint   TEXT PRIMARY KEY,
  dossier_id    TEXT NOT NULL,
  call_id       TEXT NOT NULL,
  action        TEXT NOT NULL,
  target_json   TEXT,
  payload_json  TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
  evaluation_id         TEXT PRIMARY KEY,
  input_digest          TEXT NOT NULL,
  receipt_verifier_json TEXT NOT NULL,
  proposals_json        TEXT NOT NULL,
  response_json         TEXT NOT NULL,
  created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commits (
  evaluation_id TEXT PRIMARY KEY,
  response_json TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  FOREIGN KEY (evaluation_id) REFERENCES evaluations(evaluation_id)
);

CREATE TABLE IF NOT EXISTS executed_actions (
  evaluation_id TEXT NOT NULL,
  call_id       TEXT NOT NULL,
  dossier_id    TEXT NOT NULL,
  action        TEXT NOT NULL,
  target_json   TEXT,
  payload_json  TEXT NOT NULL,
  executed_at   TEXT NOT NULL,
  PRIMARY KEY (evaluation_id, call_id)
);
`);

module.exports = db;
