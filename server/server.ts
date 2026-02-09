import express from 'express';
import cors from 'cors';
import { detectionEngine } from './detection-engine.js';
import { reasoningEngine } from './reasoning-engine.js';
import { explainabilityEngine } from './explainability.js';

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Analyze endpoint
app.post('/api/analyze', async (req, res) => {
    try {
        const { content, type } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'Content is required' });
        }

        // Run detection
        const detection = detectionEngine.analyze(content, type);

        // Run reasoning
        const reasoning = reasoningEngine.analyzeIntent(detection);

        // Generate explanation
        const explanation = explainabilityEngine.generateExplanation(detection, reasoning);

        // Prepare full analysis result
        const result = {
            detection,
            reasoning,
            explanation,
            timestamp: new Date().toISOString()
        };

        // Note: Database saving is now handled on the client side

        res.json(result);
    } catch (error: any) {
        console.error('Analysis error:', error);
        res.status(500).json({
            error: error.message || 'Analysis failed',
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Health check
app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Only start the server if not running in Vercel or if explicitly running locally
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`AI Security Server running on http://localhost:${PORT}`);
        console.log(`API endpoints available at http://localhost:${PORT}/api`);
    });
}

export default app;
