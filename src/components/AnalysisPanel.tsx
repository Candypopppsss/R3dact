import { useState } from 'react';
import { useDatabase } from '../context/DatabaseContext';
import ThreatCard from './ThreatCard';

interface AnalysisPanelProps {
    onAnalysisComplete?: () => void;
}

interface DetectionResult {
    threatScore: number;
    isPhishing?: boolean;
    category?: 'url' | 'email' | 'message';
}

interface ReasoningResult {
    attackType: string;
    attackerIntent: Array<{ intent: string; confidence: number; reasoning: string }>;
    vulnerabilities: Array<{ trigger: string; description: string; severity: 'high' | 'medium' | 'low' }>;
}

interface Explanation {
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
    summary: string;
    recommendations?: string[];
    technicalDetails?: Array<{ category: string; findings: string[] }>;
}

interface AnalysisResult {
    detection: DetectionResult;
    reasoning: ReasoningResult;
    explanation: Explanation;
    timestamp: string;
}

export default function AnalysisPanel({ onAnalysisComplete }: AnalysisPanelProps) {
    const { db } = useDatabase();
    const [input, setInput] = useState('');
    const [inputType, setInputType] = useState<'url' | 'email' | 'message'>('url');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<AnalysisResult | null>(null);

    const handleAnalyze = async () => {
        if (!input.trim()) return;

        setLoading(true);
        setResult(null);

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    content: input,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Analysis failed with status ${response.status}`);
            }

            const data: AnalysisResult = await response.json();

            setResult(data);

            // Save to client-side database if it's a threat
            if (data.detection.threatScore >= 20) {
                await db.saveAttack({
                    timestamp: data.timestamp,
                    type: data.detection.category || 'message',
                    content: input.substring(0, 500),
                    threat_score: data.detection.threatScore,
                    analysis_result: data
                });
            }

            if (onAnalysisComplete) {
                onAnalysisComplete();
            }
        } catch (error: any) {
            console.error('Analysis error:', error);
            alert(`Backend Error: ${error.message}\n\nThis usually happens if the backend is not correctly configured on Vercel or the database initialization failed.`);
        } finally {
            setLoading(false);
        }
    };

    const handleClear = () => {
        setInput('');
        setResult(null);
    };

    const exampleInputs = {
        url: 'http://paypa1-secure.tk/verify-account?user=victim@email.com',
        email: 'URGENT: Your account has been suspended! Click here immediately to verify your identity and restore access within 24 hours or face permanent closure. Verify Now: http://secure-bank-verify.xyz/login',
        message: 'Congratulations! You have won $1,000,000 in our lottery. To claim your prize, please provide your bank account details and social security number immediately.',
    };

    const loadExample = () => {
        setInput(exampleInputs[inputType]);
    };

    return (
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
            <div className="card" style={{ marginBottom: '2rem' }}>
                <div className="card-header">
                    <h2 className="card-title">Threat Analysis</h2>
                </div>

                <div className="input-group">
                    <label className="input-label">Content Type</label>
                    <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="radio"
                                name="type"
                                value="url"
                                checked={inputType === 'url'}
                                onChange={(e) => setInputType(e.target.value as any)}
                                style={{ cursor: 'pointer' }}
                            />
                            <span>URL</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="radio"
                                name="type"
                                value="email"
                                checked={inputType === 'email'}
                                onChange={(e) => setInputType(e.target.value as any)}
                                style={{ cursor: 'pointer' }}
                            />
                            <span>Email</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="radio"
                                name="type"
                                value="message"
                                checked={inputType === 'message'}
                                onChange={(e) => setInputType(e.target.value as any)}
                                style={{ cursor: 'pointer' }}
                            />
                            <span>Message</span>
                        </label>
                    </div>
                </div>

                <div className="input-group">
                    <label className="input-label">
                        {inputType === 'url' ? 'Enter URL to analyze' :
                            inputType === 'email' ? 'Paste email content' :
                                'Paste message content'}
                    </label>
                    <textarea
                        className="textarea"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        placeholder={
                            inputType === 'url'
                                ? 'https://example.com/suspicious-link'
                                : 'Paste the suspicious content here...'
                        }
                        rows={inputType === 'url' ? 3 : 6}
                    />
                </div>

                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <button
                        className="btn btn-primary"
                        onClick={handleAnalyze}
                        disabled={loading || !input.trim()}
                    >
                        {loading ? (
                            <>
                                <span className="spinner"></span>
                                Analyzing...
                            </>
                        ) : (
                            "Analyze Threat"
                        )}
                    </button>
                    <button
                        className="btn btn-secondary"
                        onClick={loadExample}
                        disabled={loading}
                    >
                        Load Example
                    </button>
                    <button
                        className="btn btn-secondary"
                        onClick={handleClear}
                        disabled={loading}
                    >
                        Clear
                    </button>
                </div>
            </div>

            {result && <ThreatCard result={result} />}
        </div>
    );
}
