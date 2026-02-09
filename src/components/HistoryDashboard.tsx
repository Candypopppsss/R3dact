import { useState, useEffect } from 'react';

interface HistoryDashboardProps {
    refreshTrigger: number;
}

interface AttackRecord {
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
    const [attacks, setAttacks] = useState<AttackRecord[]>([]);
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchData();
    }, [refreshTrigger]);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [historyRes, statsRes] = await Promise.all([
                fetch('/api/history'),
                fetch('/api/stats')
            ]);

            if (historyRes.ok && statsRes.ok) {
                const historyData = await historyRes.json();
                const statsData = await statsRes.json();
                setAttacks(historyData);
                setStats(statsData);
            } else {
                const errorMsg = !historyRes.ok ? `History failed (${historyRes.status})` : `Stats failed (${statsRes.status})`;
                throw new Error(errorMsg);
            }
        } catch (error) {
            console.error('Failed to fetch data:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: number) => {
        if (!confirm('Delete this attack record?')) return;

        try {
            const response = await fetch(`/api/history/${id}`, {
                method: 'DELETE',
            });

            if (response.ok) {
                fetchData();
            }
        } catch (error) {
            console.error('Failed to delete:', error);
        }
    };

    const formatDate = (timestamp: string) => {
        const date = new Date(timestamp);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    const getRiskBadgeClass = (riskLevel?: string) => {
        if (!riskLevel) return 'badge badge-safe';
        return `badge badge-${riskLevel.toLowerCase()}`;
    };

    if (loading) {
        return (
            <div style={{ textAlign: 'center', padding: '3rem' }}>
                <div className="spinner" style={{ width: '40px', height: '40px', margin: '0 auto' }}></div>
                <p style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>Loading history...</p>
            </div>
        );
    }

    return (
        <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
            {/* Statistics Cards */}
            {stats && (
                <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                    gap: '1.5rem',
                    marginBottom: '2rem'
                }}>
                    <div className="card" style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--accent-red)' }}>
                            {stats.totalAttacks}
                        </div>
                        <div style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', textTransform: 'uppercase', letterSpacing: '1px', fontSize: '0.8rem' }}>
                            Total Threats Detected
                        </div>
                    </div>

                    <div className="card" style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--text-primary)' }}>
                            {stats.averageThreatScore}
                        </div>
                        <div style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', textTransform: 'uppercase', letterSpacing: '1px', fontSize: '0.8rem' }}>
                            Average Threat Score
                        </div>
                    </div>

                    <div className="card" style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--accent-red)' }}>
                            {stats.highThreatCount}
                        </div>
                        <div style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', textTransform: 'uppercase', letterSpacing: '1px', fontSize: '0.8rem' }}>
                            High-Risk Attacks
                        </div>
                    </div>
                </div>
            )}

            {/* Attack History */}
            <div className="card">
                <div className="card-header">
                    <h2 className="card-title">Attack History</h2>
                </div>

                {attacks.length === 0 ? (
                    <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                    }}>
                        <p style={{ fontSize: '1.2rem' }}>No threats detected yet</p>
                        <p>Analyze some content to build your threat history</p>
                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {attacks.map((attack, idx) => (
                            <div
                                key={attack.id}
                                className="card"
                                style={{
                                    background: 'var(--bg-tertiary)',
                                    animation: `slideInRight 0.3s ease ${idx * 0.05}s backwards`
                                }}
                            >
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'flex-start',
                                    gap: '1rem',
                                    flexWrap: 'wrap'
                                }}>
                                    <div style={{ flex: 1, minWidth: '250px' }}>
                                        <div style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: '0.75rem',
                                            marginBottom: '0.75rem'
                                        }}>
                                            <span className={getRiskBadgeClass(attack.analysis_result?.explanation?.riskLevel || (attack.analysis_result as any)?.riskLevel)}>
                                                {attack.analysis_result?.explanation?.riskLevel || (attack.analysis_result as any)?.riskLevel || 'Unknown'}
                                            </span>
                                            <span style={{
                                                padding: '0.25rem 0.75rem',
                                                background: 'var(--bg-secondary)',
                                                borderRadius: '0.5rem',
                                                fontSize: '0.875rem',
                                                color: 'var(--text-secondary)'
                                            }}>
                                                {attack.type?.toUpperCase() ?? 'UNKNOWN'}
                                            </span>
                                            <span style={{
                                                fontSize: '0.875rem',
                                                color: 'var(--text-tertiary)'
                                            }}>
                                                {formatDate(attack.timestamp)}
                                            </span>
                                        </div>

                                        <div style={{
                                            fontSize: '1.05rem',
                                            fontWeight: '600',
                                            marginBottom: '0.5rem',
                                            color: 'var(--text-primary)'
                                        }}>
                                            {attack.analysis_result?.reasoning?.attackType ?? 'Generic Attack'}
                                        </div>

                                        <div style={{
                                            fontSize: '0.95rem',
                                            color: 'var(--text-secondary)',
                                            fontFamily: 'Consolas, Monaco, monospace',
                                            background: 'var(--bg-secondary)',
                                            padding: '0.75rem',
                                            borderRadius: '0.5rem',
                                            overflow: 'hidden',
                                            textOverflow: 'ellipsis',
                                            whiteSpace: 'nowrap',
                                            maxWidth: '600px'
                                        }}>
                                            {attack.content}
                                        </div>

                                        <div style={{
                                            marginTop: '0.75rem',
                                            fontSize: '0.875rem',
                                            color: 'var(--text-tertiary)'
                                        }}>
                                            {(() => {
                                                const count = attack.analysis_result?.detection?.indicators?.length || (attack.analysis_result as any)?.indicators || 0;
                                                return `${count} indicator${count !== 1 ? 's' : ''} detected`;
                                            })()}
                                        </div>
                                    </div>

                                    <div style={{
                                        display: 'flex',
                                        flexDirection: 'column',
                                        alignItems: 'center',
                                        gap: '0.5rem'
                                    }}>
                                        <div style={{
                                            background: attack.threat_score >= 70
                                                ? 'linear-gradient(135deg, #ef4444, #7f1d1d)'
                                                : attack.threat_score >= 40
                                                    ? 'linear-gradient(135deg, #dc2626, #450a0a)'
                                                    : 'linear-gradient(135deg, #374151, #1f2937)',
                                            padding: '1rem',
                                            borderRadius: '0.75rem',
                                            textAlign: 'center',
                                            minWidth: '100px'
                                        }}>
                                            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: 'white' }}>
                                                {attack.threat_score}
                                            </div>
                                            <div style={{ fontSize: '0.75rem', color: 'rgba(255, 255, 255, 0.9)' }}>
                                                Threat Score
                                            </div>
                                        </div>

                                        <button
                                            className="btn btn-danger"
                                            onClick={() => handleDelete(attack.id)}
                                            style={{ fontSize: '0.875rem', padding: '0.5rem 1rem' }}
                                        >
                                            Delete
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
