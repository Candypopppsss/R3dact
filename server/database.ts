import initSqlJs, { Database as SqlJsDatabase } from 'sql.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, writeFileSync, existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface AttackRecord {
    id?: number;
    timestamp: string;
    type: string;
    content: string;
    threat_score: number;
    analysis_result: string;
}

class DatabaseManager {
    private db: SqlJsDatabase | null = null;
    private dbPath: string;
    private initialized = false;

    constructor() {
        this.dbPath = join(__dirname, '..', 'attacks.db');
    }

    async initialize() {
        if (this.initialized) return;

        const SQL = await initSqlJs();

        // Load existing database or create new one
        if (existsSync(this.dbPath)) {
            const buffer = readFileSync(this.dbPath);
            this.db = new SQL.Database(buffer);
        } else {
            this.db = new SQL.Database();
        }

        // Create table if it doesn't exist
        this.db.run(`
      CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT NOT NULL,
        threat_score INTEGER NOT NULL,
        analysis_result TEXT NOT NULL
      )
    `);

        this.save();
        this.initialized = true;
    }

    private save() {
        if (!this.db) return;
        const data = this.db.export();
        writeFileSync(this.dbPath, data);
    }

    async saveAttack(record: AttackRecord): Promise<number> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        this.db.run(
            `INSERT INTO attacks (timestamp, type, content, threat_score, analysis_result)
       VALUES (?, ?, ?, ?, ?)`,
            [record.timestamp, record.type, record.content, record.threat_score, record.analysis_result]
        );

        const result = this.db.exec('SELECT last_insert_rowid() as id');
        this.save();

        return result[0].values[0][0] as number;
    }

    async getAllAttacks(): Promise<AttackRecord[]> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        const result = this.db.exec('SELECT * FROM attacks ORDER BY timestamp DESC');

        if (result.length === 0) return [];

        const columns = result[0].columns;
        const values = result[0].values;

        return values.map(row => {
            const record: any = {};
            columns.forEach((col, idx) => {
                record[col] = row[idx];
            });
            return record as AttackRecord;
        });
    }

    async getAttackById(id: number): Promise<AttackRecord | undefined> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        const result = this.db.exec('SELECT * FROM attacks WHERE id = ?', [id]);

        if (result.length === 0 || result[0].values.length === 0) return undefined;

        const columns = result[0].columns;
        const row = result[0].values[0];
        const record: any = {};

        columns.forEach((col, idx) => {
            record[col] = row[idx];
        });

        return record as AttackRecord;
    }

    async deleteAttack(id: number): Promise<boolean> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        this.db.run('DELETE FROM attacks WHERE id = ?', [id]);
        this.save();

        return true;
    }

    async getStats() {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        const totalResult = this.db.exec('SELECT COUNT(*) as count FROM attacks');
        const avgResult = this.db.exec('SELECT AVG(threat_score) as avg FROM attacks');
        const highResult = this.db.exec('SELECT COUNT(*) as count FROM attacks WHERE threat_score >= 70');

        const total = totalResult[0]?.values[0]?.[0] || 0;
        const avg = avgResult[0]?.values[0]?.[0] || 0;
        const high = highResult[0]?.values[0]?.[0] || 0;

        return {
            totalAttacks: total as number,
            averageThreatScore: Math.round(avg as number),
            highThreatCount: high as number,
        };
    }

    close() {
        if (this.db) {
            this.save();
            this.db.close();
        }
    }
}

export const database = new DatabaseManager();
