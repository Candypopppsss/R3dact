import { useState } from 'react';
import './index.css';
import AnalysisPanel from './components/AnalysisPanel';
import HistoryDashboard from './components/HistoryDashboard';

function App() {
    const [activeTab, setActiveTab] = useState<'analyze' | 'history'>('analyze');
    const [refreshHistory, setRefreshHistory] = useState(0);

    const handleAnalysisComplete = () => {
        setRefreshHistory(prev => prev + 1);
    };

    return (
        <div className="app">
            <header className="app-header" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
                <div className="logo-container" style={{ marginBottom: '1.5rem', display: 'inline-block' }}>
                    <svg width="64" height="74" viewBox="0 0 80 92" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M40 0L74.641 20V60L40 80L5.35898 60V20L40 0Z" fill="#ef4444" />
                        <path d="M40 10L65.9808 25V55L40 70L14.0192 55V25L40 10Z" fill="#0B0B0E" />
                        <path d="M40 20L57.3205 30V50L40 60L22.6795 50V30L40 20Z" fill="#ef4444" />
                    </svg>
                </div>
                <h1 className="app-title" style={{
                    fontSize: '3.5rem',
                    fontWeight: 800,
                    letterSpacing: '-0.05em',
                    background: 'linear-gradient(to right, #f87171, #ef4444)',
                    WebkitBackgroundClip: 'text',
                    WebkitTextFillColor: 'transparent',
                    margin: 0
                }}>R3dact</h1>
                <p className="app-subtitle" style={{
                    color: 'var(--text-secondary)',
                    marginTop: '0.5rem',
                    fontSize: '1.1rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em'
                }}>
                    Advanced AI Security Observation Engine
                </p>
            </header>

            <div className="container">
                {/* Tab Navigation */}
                <div style={{
                    display: 'flex',
                    gap: '1rem',
                    marginBottom: '2rem',
                    justifyContent: 'center'
                }}>
                    <button
                        className={`btn ${activeTab === 'analyze' ? 'btn-primary' : 'btn-secondary'}`}
                        onClick={() => setActiveTab('analyze')}
                        style={{ minWidth: '150px' }}
                    >
                        Analyze
                    </button>
                    <button
                        className={`btn ${activeTab === 'history' ? 'btn-primary' : 'btn-secondary'}`}
                        onClick={() => setActiveTab('history')}
                        style={{ minWidth: '150px' }}
                    >
                        History
                    </button>
                </div>

                {/* Content */}
                {activeTab === 'analyze' ? (
                    <AnalysisPanel onAnalysisComplete={handleAnalysisComplete} />
                ) : (
                    <HistoryDashboard refreshTrigger={refreshHistory} />
                )}
            </div>
        </div>
    );
}

export default App;
