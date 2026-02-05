import { useState } from 'react';

interface ThreatCardProps {
    result: {
        detection: any;
        reasoning: any;
        explanation: any;
        timestamp: string;
    };
}

export default function ThreatCard({ result }: ThreatCardProps) {
    const [showDetails, setShowDetails] = useState(false);
    const { detection, reasoning, explanation } = result;

    const getRiskGradient = (riskLevel: string) => {
        switch (riskLevel) {
            case 'Critical': return 'linear-gradient(135deg, #dc2626, #991b1b)';
            case 'High': return 'linear-gradient(135deg, #f59e0b, #d97706)';
            case 'Medium': return 'linear-gradient(135deg, #eab308, #ca8a04)';
            case 'Low': return 'linear-gradient(135deg, #3b82f6, #2563eb)';
            case 'Safe': return 'linear-gradient(135deg, #10b981, #059669)';
            default: return 'linear-gradient(135deg, #6b7280, #4b5563)';
        }
    };

    return (
        <div className="card" style={{ animation: 'fadeIn 0.4s ease' }}>
            {/* Header with Threat Score */}
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1.5rem',
                flexWrap: 'wrap',
                gap: '1rem'
            }}>
                <div>
                    <h2 style={{ margin: 0, marginBottom: '0.5rem' }}>Analysis Results</h2>
                    <span className={`badge badge-${explanation.riskLevel.toLowerCase()}`}>
                        {explanation.riskLevel} Risk
                    </span>
                </div>
                <div style={{
                    background: getRiskGradient(explanation.riskLevel),
                    padding: '1.5rem',
                    borderRadius: '1rem',
                    textAlign: 'center',
                    minWidth: '150px',
                    boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3)'
                }}>
                    <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'white' }}>
                        {detection.threatScore}
                    </div>
                    <div style={{ fontSize: '0.875rem', color: 'rgba(255, 255, 255, 0.9)', marginTop: '0.25rem' }}>
                        Threat Score
                    </div>
                </div>
            </div>

            {/* Summary */}
            <div style={{
                padding: '1rem',
                background: 'rgba(6, 182, 212, 0.1)',
                borderLeft: '4px solid var(--accent-cyan)',
                borderRadius: '0.5rem',
                marginBottom: '1.5rem'
            }}>
                <div
                    style={{ margin: 0, fontSize: '1.05rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}
                    dangerouslySetInnerHTML={{
                        __html: explanation.summary
                            .replace(/### (.*?)\n/g, '<h4 style="margin: 1rem 0 0.5rem 0; color: var(--accent-cyan);">$1</h4>')
                            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                            .replace(/\*(.*?)\*/g, '<em>$1</em>')
                            .replace(/• (.*?)\n/g, '• $1<br/>')
                    }}
                />
            </div>

            {/* Attack Type */}
            <div style={{ marginBottom: '1.5rem' }}>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--accent-cyan)' }}>
                    Attack Classification
                </h3>
                <div style={{
                    display: 'inline-block',
                    padding: '0.5rem 1rem',
                    background: 'var(--bg-tertiary)',
                    borderRadius: '0.5rem',
                    border: '1px solid var(--border-color)'
                }}>
                    <strong>{reasoning.attackType}</strong>
                </div>
            </div>

            {/* Attacker Intent */}
            {reasoning.attackerIntent && reasoning.attackerIntent.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--accent-purple)' }}>
                        Attacker Intent
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {reasoning.attackerIntent.map((intent: any, idx: number) => (
                            <div
                                key={idx}
                                style={{
                                    padding: '1rem',
                                    background: 'var(--bg-tertiary)',
                                    borderRadius: '0.75rem',
                                    border: '1px solid var(--border-color)'
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                    <strong style={{ color: 'var(--accent-purple)' }}>{intent.intent}</strong>
                                    <span style={{
                                        padding: '0.25rem 0.75rem',
                                        background: 'rgba(168, 85, 247, 0.2)',
                                        borderRadius: '1rem',
                                        fontSize: '0.875rem'
                                    }}>
                                        {intent.confidence}% confidence
                                    </span>
                                </div>
                                <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
                                    {intent.reasoning}
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Vulnerabilities */}
            {reasoning.vulnerabilities && reasoning.vulnerabilities.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--accent-pink)' }}>
                        Psychological Tactics
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '0.75rem' }}>
                        {reasoning.vulnerabilities.map((vuln: any, idx: number) => (
                            <div
                                key={idx}
                                style={{
                                    padding: '1rem',
                                    background: 'var(--bg-tertiary)',
                                    borderRadius: '0.75rem',
                                    border: '1px solid var(--border-color)',
                                    borderLeft: `4px solid ${vuln.severity === 'high' ? '#ef4444' :
                                        vuln.severity === 'medium' ? '#f59e0b' : '#3b82f6'
                                        }`
                                }}
                            >
                                <div style={{ fontWeight: 'bold', marginBottom: '0.5rem', color: 'var(--accent-pink)' }}>
                                    {vuln.trigger}
                                </div>
                                <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                                    {vuln.description}
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Recommendations */}
            {explanation.recommendations && explanation.recommendations.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: 'var(--accent-green)' }}>
                        Recommendations
                    </h3>
                    <ul style={{ margin: 0, paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {explanation.recommendations.map((rec: string, idx: number) => (
                            <li key={idx} style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                {rec}
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {/* Toggle Details Button */}
            <button
                className="btn btn-secondary"
                onClick={() => setShowDetails(!showDetails)}
                style={{ width: '100%', marginTop: '1rem' }}
            >
                {showDetails ? '▲ Hide' : '▼ Show'} Technical Details
            </button>

            {/* Technical Details */}
            {showDetails && (
                <div style={{
                    marginTop: '1.5rem',
                    padding: '1.5rem',
                    background: 'var(--bg-tertiary)',
                    borderRadius: '0.75rem',
                    border: '1px solid var(--border-color)',
                    animation: 'fadeIn 0.3s ease'
                }}>
                    <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', color: 'var(--accent-cyan)' }}>
                        Technical Analysis
                    </h3>

                    {explanation.technicalDetails.map((detail: any, idx: number) => (
                        <div key={idx} style={{ marginBottom: '1.5rem' }}>
                            <h4 style={{ fontSize: '1rem', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
                                {detail.category}
                            </h4>
                            <ul style={{ margin: 0, paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                {detail.findings.map((finding: string, findingIdx: number) => (
                                    <li key={findingIdx} style={{
                                        color: 'var(--text-secondary)',
                                        fontSize: '0.95rem',
                                        lineHeight: 1.6,
                                        fontFamily: 'Consolas, Monaco, monospace'
                                    }}>
                                        {finding}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
