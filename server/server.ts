import express from 'express';
import cors from 'cors';
import { detectionEngine } from './detection-engine.js';
import { reasoningEngine } from './reasoning-engine.js';
import { explainabilityEngine } from './explainability.js';
import { database } from './database.js';

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

        // Save to database if it's a threat
        if (detection.threatScore >= 20) {
            await database.saveAttack({
                timestamp: result.timestamp,
                type: detection.category,
                content: content.substring(0, 500), // Store first 500 chars
                threat_score: detection.threatScore,
                analysis_result: JSON.stringify({
                    attackType: reasoning.attackType,
                    riskLevel: explanation.riskLevel,
                    indicators: detection.indicators.length
                })
            });
        }

        res.json(result);
    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({ error: 'Analysis failed' });
    }
});

// Get attack history
app.get('/api/history', async (_req, res) => {
    try {
        const attacks = await database.getAllAttacks();

        // Parse the analysis_result JSON for each attack
        const enrichedAttacks = attacks.map(attack => ({
            ...attack,
            analysis_result: JSON.parse(attack.analysis_result)
        }));

        res.json(enrichedAttacks);
    } catch (error) {
        console.error('History retrieval error:', error);
        res.status(500).json({ error: 'Failed to retrieve history' });
    }
});

// Get statistics
app.get('/api/stats', async (_req, res) => {
    try {
        const stats = await database.getStats();
        res.json(stats);
    } catch (error) {
        console.error('Stats retrieval error:', error);
        res.status(500).json({ error: 'Failed to retrieve stats' });
    }
});

// Delete attack record
app.delete('/api/history/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const success = await database.deleteAttack(id);

        if (success) {
            res.json({ message: 'Attack record deleted' });
        } else {
            res.status(404).json({ error: 'Attack record not found' });
        }
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete record' });
    }
});

// Health check
app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`🛡️  AI Security Server running on http://localhost:${PORT}`);
    console.log(`📊 API endpoints available at http://localhost:${PORT}/api`);
});

export default app;
