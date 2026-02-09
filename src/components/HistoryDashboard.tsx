import { useState, useEffect } from 'react';
import { useDatabase } from '../context/DatabaseContext';

interface HistoryDashboardProps {
    refreshTrigger: number;
}

export interface AttackRecord {
    id: number;
    timestamp: string;
    type: string;
    content: string;
    threat_score: number;
    analysis_result?: {
        detection: {
            threatScore: number;
            isPhishing?: boolean;
            category?: string;
            indicators?: any[];
        };
        reasoning: {
            attackType: string;
            attackerIntent: Array<{ intent: string; confidence: number; reasoning: string }>;
            vulnerabilities: Array<{ trigger: string; description: string; severity: 'high' | 'medium' | 'low' }>;
        };
        explanation: {
            riskLevel: string;
            summary: string;
            recommendations?: string[];
            technicalDetails?: Array<{ category: string; findings: string[] }>;
        };
        timestamp: string;
    };
}

interface Stats {
    totalAttacks: number;
    averageThreatScore: number;
    highThreatCount: number;
}

export default function HistoryDashboard({ refreshTrigger }: HistoryDashboardProps) {
    const { db } = useDatabase();
    const [attacks, setAttacks] = useState<AttackRecord[]>([]);
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchData();
    }, [refreshTrigger, db]);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [historyData, statsData] = await Promise.all([
                db.getAllAttacks(),
                db.getStats()
            ]);

            setAttacks(historyData as any);
            setStats(statsData);
        } catch (error: any) {
            console.error('Failed to fetch data from local DB:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: number) => {
        if (!confirm('Delete this attack record?')) return;

        try {
            await db.deleteAttack(id);
            fetchData();
        } catch (error: any) {
            console.error('Delete error:', error);
            alert(`Delete Error: ${error.message}`);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center p-12">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-500"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {stats && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-900/50 border border-gray-800 p-4 rounded-lg">
                        <div className="text-gray-400 text-sm mb-1">Total Threats Detected</div>
                        <div className="text-2xl font-bold text-red-500">{stats.totalAttacks}</div>
                    </div>
                    <div className="bg-gray-900/50 border border-gray-800 p-4 rounded-lg">
                        <div className="text-gray-400 text-sm mb-1">Average Threat Score</div>
                        <div className="text-2xl font-bold text-orange-500">{stats.averageThreatScore}%</div>
                    </div>
                    <div className="bg-gray-900/50 border border-gray-800 p-4 rounded-lg">
                        <div className="text-gray-400 text-sm mb-1">High Risk Incidents</div>
                        <div className="text-2xl font-bold text-red-600">{stats.highThreatCount}</div>
                    </div>
                </div>
            )}

            <div className="bg-gray-900/30 border border-gray-800 rounded-lg overflow-hidden">
                <table className="w-full text-left">
                    <thead className="bg-gray-900/50 text-gray-400 text-sm">
                        <tr>
                            <th className="px-6 py-3 font-medium">Timestamp</th>
                            <th className="px-6 py-3 font-medium">Type</th>
                            <th className="px-6 py-3 font-medium">Threat Level</th>
                            <th className="px-6 py-3 font-medium text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                        {attacks.length === 0 ? (
                            <tr>
                                <td colSpan={4} className="px-6 py-12 text-center text-gray-500">
                                    No threat history found.
                                </td>
                            </tr>
                        ) : (
                            attacks.map((attack) => (
                                <tr key={attack.id} className="hover:bg-gray-800/30 transition-colors">
                                    <td className="px-6 py-4 text-sm text-gray-300">
                                        {new Date(attack.timestamp).toLocaleString()}
                                    </td>
                                    <td className="px-6 py-4 text-sm">
                                        <span className="capitalize px-2 py-1 rounded bg-gray-800 text-gray-300">
                                            {attack.type}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-sm">
                                        <div className="flex items-center gap-2">
                                            <div className="w-16 h-2 bg-gray-800 rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-red-500"
                                                    style={{ width: `${attack.threat_score}%` }}
                                                ></div>
                                            </div>
                                            <span className="text-red-400 font-medium">{attack.threat_score}%</span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <button
                                            onClick={() => handleDelete(attack.id)}
                                            className="text-gray-500 hover:text-red-500 transition-colors p-1"
                                            title="Delete Record"
                                        >
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                            </svg>
                                        </button>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
