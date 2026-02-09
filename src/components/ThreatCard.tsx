import { useState } from 'react';

// --- Type Definitions for API Response ---
interface Indicator {
    type: string;
    severity: 'high' | 'medium' | 'low';
    description: string;
    evidence?: string;
}

interface DetectionResult {
    threatScore: number;
    isPhishing?: boolean;
    indicators?: Indicator[];
    category?: 'url' | 'email' | 'message';
}

interface IntentAnalysis {
    intent: string;
    confidence: number;
    reasoning: string;
}

interface VulnerabilityAnalysis {
    trigger: string;
    description: string;
    severity?: 'high' | 'medium' | 'low';
}

interface ReasoningResult {
    attackType: string;
    attackerIntent?: IntentAnalysis[];
    vulnerabilities?: VulnerabilityAnalysis[];
    confidence?: number;
}

interface TechnicalDetail {
    category: string;
    findings: string[];
}

interface Explanation {
    summary: string;
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
    detailedAnalysis?: string[];
    recommendations?: string[];
    technicalDetails?: TechnicalDetail[];
}

interface ThreatCardProps {
    result: {
        detection: DetectionResult;
        reasoning: ReasoningResult;
        explanation: Explanation;
        timestamp: string;
    };
}

export default function ThreatCard({ result }: ThreatCardProps) {
    const [showDetails, setShowDetails] = useState(false);
    const { detection, reasoning, explanation } = result;

    const getRiskGradient = (riskLevel: string) => {
        const level = riskLevel?.toLowerCase();
        switch (level) {
            case 'critical': return 'linear-gradient(135deg, #ef4444, #7f1d1d)';
            case 'high': return 'linear-gradient(135deg, #dc2626, #450a0a)';
            case 'medium': return 'linear-gradient(135deg, #374151, #1f2937)';
            case 'low': return 'linear-gradient(135deg, #1f2937, #111827)';
            case 'safe': return 'linear-gradient(135deg, #0b0b0e, #050507)';
            default: return 'linear-gradient(135deg, #1f2937, #0b0b0e)';
        }
    };

    /**
     * Safely formats the markdown-like summary into HTML.
     * Handles missing trailing newlines and different platform line breaks.
     */
    const formatSummary = (summary: string) => {
        if (!summary) return "";
        return summary
            .replace(/### (.*?)(?:\n|\r\n|$)/g, '<h4 style="margin: 1.25rem 0 0.5rem 0; color: var(--accent-red); font-weight: 700;">$1</h4>')
            .replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--text-primary);">$1</strong>')
            .replace(/\*(.*?)\*/g, '<em style="color: var(--text-secondary);">$1</em>')
            .replace(/• (.*?)(?:\n|\r\n|$)/g, '<div style="margin-bottom: 0.25rem; color: var(--text-secondary);">• $1</div>');
    };

    return (
        <div className="card" style={{ animation: 'fadeIn 0.4s ease', position: 'relative', overflow: 'hidden' }}>
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
                    <h2 style={{ margin: 0, marginBottom: '0.5rem', fontSize: '1.5rem' }}>Analysis Results</h2>
                    {explanation?.riskLevel && (
                        <span className={`badge badge-${explanation.riskLevel.toLowerCase()}`}>
                            {explanation.riskLevel} Risk
                        </span>
                    )}
                </div>
                <div style={{
                    background: getRiskGradient(explanation?.riskLevel || 'safe'),
                    padding: '1.25rem',
                    borderRadius: '1rem',
                    textAlign: 'center',
                    minWidth: '140px',
                    boxShadow: 'var(--shadow-md)',
                    border: '1px solid rgba(255, 255, 255, 0.1)'
                }}>
                    <div style={{ fontSize: '2.5rem', fontWeight: '800', color: 'white', lineHeight: 1 }}>
                        {detection?.threatScore ?? 0}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.8)', marginTop: '0.5rem', textTransform: 'uppercase', letterSpacing: '1px', fontWeight: '600' }}>
                        Threat Score
                    </div>
                </div>
            </div>

            {/* Summary Layer */}
            {explanation?.summary && (
                <div style={{
                    padding: '1.25rem',
                    background: 'rgba(239, 68, 68, 0.03)',
                    borderLeft: '4px solid var(--accent-red)',
                    borderRadius: '0.5rem',
                    marginBottom: '1.5rem',
                    border: '1px solid rgba(255, 255, 255, 0.05)'
                }}>
                    <div
                        style={{ margin: 0, fontSize: '1rem', lineHeight: 1.7, color: 'var(--text-secondary)' }}
                        dangerouslySetInnerHTML={{ __html: formatSummary(explanation.summary) }}
                    />
                </div>
            )}

            {/* Attack Classification */}
            {reasoning?.attackType && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Attack Classification
                    </h3>
                    <div style={{
                        display: 'inline-block',
                        padding: '0.6rem 1.25rem',
                        background: 'var(--bg-tertiary)',
                        borderRadius: '0.5rem',
                        border: '1px solid var(--border-color)',
                        fontWeight: '600',
                        fontSize: '0.95rem'
                    }}>
                        {reasoning.attackType}
                    </div>
                </div>
            )}

            {/* Attacker Intent */}
            {reasoning?.attackerIntent && reasoning.attackerIntent.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Attacker Intent
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {reasoning.attackerIntent.map((intent, idx) => (
                            <div
                                key={idx}
                                style={{
                                    padding: '1rem',
                                    background: 'var(--bg-tertiary)',
                                    borderRadius: '0.75rem',
                                    border: '1px solid var(--border-color)',
                                    transition: 'background 0.2s ease'
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                    <strong style={{ color: 'var(--accent-red)' }}>{intent.intent}</strong>
                                    <span style={{
                                        padding: '0.2rem 0.6rem',
                                        background: 'rgba(239, 68, 68, 0.1)',
                                        color: 'var(--accent-red)',
                                        borderRadius: '0.5rem',
                                        fontSize: '0.75rem',
                                        fontWeight: '700'
                                    }}>
                                        {intent.confidence}% confidence
                                    </span>
                                </div>
                                <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.5 }}>
                                    {intent.reasoning}
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Psychological Tactics */}
            {reasoning?.vulnerabilities && reasoning.vulnerabilities.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Psychological Tactics
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
                        {reasoning.vulnerabilities.map((vuln, idx) => (
                            <div
                                key={idx}
                                style={{
                                    padding: '1rem',
                                    background: 'var(--bg-tertiary)',
                                    borderRadius: '0.75rem',
                                    border: '1px solid var(--border-color)',
                                    borderLeft: `4px solid ${vuln.severity === 'high' ? 'var(--accent-red)' :
                                        vuln.severity === 'medium' ? 'var(--accent-yellow)' : 'var(--accent-gray)'
                                        }`
                                }}
                            >
                                <div style={{ fontWeight: '700', marginBottom: '0.5rem', color: 'var(--text-primary)', fontSize: '0.95rem' }}>
                                    {vuln.trigger}
                                </div>
                                <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                                    {vuln.description}
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Recommendations Section */}
            {explanation?.recommendations && explanation.recommendations.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ fontSize: '0.9rem', marginBottom: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Security Recommendations
                    </h3>
                    <div style={{
                        padding: '1rem',
                        background: 'rgba(255, 255, 255, 0.02)',
                        borderRadius: '0.75rem',
                        border: '1px solid rgba(255, 255, 255, 0.05)'
                    }}>
                        <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                            {explanation.recommendations.map((rec, idx) => (
                                <li key={idx} style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.5 }}>
                                    <div dangerouslySetInnerHTML={{ __html: rec.replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--accent-red);">$1</strong>') }} />
                                </li>
                            ))}
                        </ul>
                    </div>
                </div>
            )}

            {/* Action Buttons */}
            <button
                className={`btn ${showDetails ? 'btn-secondary' : 'btn-primary'}`}
                onClick={() => setShowDetails(!showDetails)}
                style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}
            >
                {showDetails ? 'Hide' : 'Show'} Technical Analysis
            </button>

            {/* Technical Details (Accordion Content) */}
            {showDetails && (
                <div style={{
                    marginTop: '1.25rem',
                    padding: '1.5rem',
                    background: 'var(--bg-tertiary)',
                    borderRadius: '0.75rem',
                    border: '1px solid var(--border-color)',
                    animation: 'fadeInUp 0.3s ease',
                    boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.2)'
                }}>
                    <h3 style={{ fontSize: '1.1rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                        Full Diagnostic Data
                    </h3>

                    {explanation?.technicalDetails?.map((detail, idx) => (
                        <div key={idx} style={{ marginBottom: '1.5rem' }}>
                            <h4 style={{ fontSize: '0.85rem', marginBottom: '0.75rem', color: 'var(--accent-red)', textTransform: 'uppercase' }}>
                                {detail.category}
                            </h4>
                            <ul style={{ margin: 0, paddingLeft: '1.25rem', listStyleType: 'square' }}>
                                {detail.findings?.map((finding, findingIdx) => (
                                    <li key={findingIdx} style={{
                                        color: 'var(--text-tertiary)',
                                        fontSize: '0.85rem',
                                        lineHeight: 1.6,
                                        marginBottom: '0.4rem',
                                        fontFamily: 'var(--font-mono, monospace)'
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

