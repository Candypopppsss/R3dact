import initSqlJs from 'sql.js';
import type { Database } from 'sql.js';

export interface AttackRecord {
    id?: number;
    timestamp: string;
    type: string;
    content: string;
    threat_score: number;
    analysis_result: any;
}

class ClientDatabaseManager {
    private db: Database | null = null;
    private initialized = false;

    async initialize() {
        if (this.initialized) return;

        try {
            const SQL = await initSqlJs({
                // Use CDN for Wasm to ensure it works in all environments
                locateFile: (file: string) => `https://sql.js.org/dist/${file}`
            });

            this.db = new SQL.Database();

            // Create table
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

            this.initialized = true;
            console.log('Client-side database initialized');
        } catch (error) {
            console.error('Failed to initialize client-side database:', error);
            throw error;
        }
    }

    async saveAttack(record: Omit<AttackRecord, 'id'>): Promise<number> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        this.db.run(
            `INSERT INTO attacks (timestamp, type, content, threat_score, analysis_result)
             VALUES (?, ?, ?, ?, ?)`,
            [
                record.timestamp,
                record.type,
                record.content,
                record.threat_score,
                JSON.stringify(record.analysis_result)
            ]
        );

        const result = this.db.exec('SELECT last_insert_rowid() as id');
        return result[0].values[0][0] as number;
    }

    async getAllAttacks(): Promise<AttackRecord[]> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        const result = this.db.exec('SELECT * FROM attacks ORDER BY timestamp DESC');

        if (result.length === 0) return [];

        const columns = result[0].columns;
        const values = result[0].values;

        return values.map((row: any[]) => {
            const record: any = {};
            columns.forEach((col: string, idx: number) => {
                if (col === 'analysis_result') {
                    record[col] = JSON.parse(row[idx]);
                } else {
                    record[col] = row[idx];
                }
            });
            return record as AttackRecord;
        });
    }

    async deleteAttack(id: number): Promise<boolean> {
        await this.initialize();
        if (!this.db) throw new Error('Database not initialized');

        this.db.run('DELETE FROM attacks WHERE id = ?', [id]);
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
}

export const clientDatabase = new ClientDatabaseManager();
