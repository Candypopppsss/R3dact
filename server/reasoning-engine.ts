import { DetectionResult, Indicator } from './detection-engine.js';

export interface ReasoningResult {
    attackerIntent: IntentAnalysis[];
    vulnerabilities: VulnerabilityAnalysis[];
    confidence: number;
    attackType: string;
}

export interface IntentAnalysis {
    intent: string;
    confidence: number;
    reasoning: string;
}

export interface VulnerabilityAnalysis {
    trigger: string;
    description: string;
    severity: 'high' | 'medium' | 'low';
}

class ReasoningEngine {
    analyzeIntent(detection: DetectionResult): ReasoningResult {
        const intents: IntentAnalysis[] = [];
        const vulnerabilities: VulnerabilityAnalysis[] = [];
        let attackType = 'Unknown';

        // Analyze indicators to determine attacker intent
        const indicatorTypes = detection.indicators.map(i => i.type);
        const indicatorEvidences = detection.indicators.map(i => i.evidence?.toLowerCase() || '').join(' ');

        // Credential Theft Intent
        if (indicatorTypes.includes('Credential Request') ||
            indicatorTypes.includes('Typosquatting')) {
            intents.push({
                intent: 'Credential Theft',
                confidence: 85,
                reasoning: 'Attempts to steal login credentials or personal information through fake login pages or direct requests'
            });
            attackType = 'Phishing - Credential Harvesting';
        }

        // Financial Fraud Intent
        if (indicatorEvidences.includes('bank') ||
            indicatorEvidences.includes('payment') ||
            indicatorEvidences.includes('credit card') ||
            indicatorTypes.includes('Too Good to Be True')) {
            intents.push({
                intent: 'Financial Fraud',
                confidence: 80,
                reasoning: 'Seeks to obtain financial information or trick victims into unauthorized transactions'
            });
            if (attackType === 'Unknown') attackType = 'Financial Phishing';
        }

        // Malware Distribution Intent
        if (indicatorTypes.includes('Suspicious Links') ||
            indicatorTypes.includes('URL Obfuscation')) {
            intents.push({
                intent: 'Malware Distribution',
                confidence: 70,
                reasoning: 'May attempt to deliver malware through suspicious links or downloads'
            });
            if (attackType === 'Unknown') attackType = 'Malware Delivery';
        }

        // Data Harvesting Intent
        if (indicatorTypes.includes('Authority Impersonation') ||
            indicatorEvidences.includes('verify') ||
            indicatorEvidences.includes('update')) {
            intents.push({
                intent: 'Data Harvesting',
                confidence: 75,
                reasoning: 'Collects personal data by impersonating legitimate organizations'
            });
            if (attackType === 'Unknown') attackType = 'Spear Phishing';
        }

        // Account Takeover Intent
        if (indicatorEvidences.includes('suspended') ||
            indicatorEvidences.includes('locked') ||
            indicatorTypes.includes('Threatening Language')) {
            intents.push({
                intent: 'Account Takeover',
                confidence: 78,
                reasoning: 'Uses fear tactics to gain access to user accounts'
            });
            if (attackType === 'Unknown') attackType = 'Account Compromise Attack';
        }

        // Analyze psychological vulnerabilities being exploited

        // Fear/Anxiety
        if (indicatorTypes.includes('Threatening Language') ||
            indicatorTypes.includes('Urgency Tactics')) {
            vulnerabilities.push({
                trigger: 'Fear & Anxiety',
                description: 'Exploits fear of negative consequences (account closure, legal action) to bypass rational thinking',
                severity: 'high'
            });
        }

        // Authority Bias
        if (indicatorTypes.includes('Authority Impersonation')) {
            vulnerabilities.push({
                trigger: 'Authority Bias',
                description: 'Leverages trust in authority figures (banks, government) to appear legitimate',
                severity: 'high'
            });
        }

        // Urgency/Scarcity
        if (indicatorTypes.includes('Urgency Tactics')) {
            vulnerabilities.push({
                trigger: 'Urgency & Time Pressure',
                description: 'Creates artificial time constraints to prevent careful evaluation',
                severity: 'medium'
            });
        }

        // Greed
        if (indicatorTypes.includes('Too Good to Be True')) {
            vulnerabilities.push({
                trigger: 'Greed & Reward Seeking',
                description: 'Appeals to desire for easy money or prizes to lower defenses',
                severity: 'medium'
            });
        }

        // Curiosity
        if (indicatorTypes.includes('Suspicious Links')) {
            vulnerabilities.push({
                trigger: 'Curiosity',
                description: 'Uses mysterious or intriguing links to encourage clicking without verification',
                severity: 'low'
            });
        }

        // Trust/Helpfulness
        if (indicatorTypes.includes('Generic Greeting') ||
            indicatorEvidences.includes('kindly')) {
            vulnerabilities.push({
                trigger: 'Helpfulness & Compliance',
                description: 'Exploits natural tendency to be helpful and comply with requests',
                severity: 'low'
            });
        }

        // Calculate overall confidence based on number and severity of indicators
        const highSeverityCount = detection.indicators.filter(i => i.severity === 'high').length;
        const mediumSeverityCount = detection.indicators.filter(i => i.severity === 'medium').length;

        let confidence = 50;
        confidence += highSeverityCount * 15;
        confidence += mediumSeverityCount * 8;
        confidence = Math.min(95, confidence);

        if (intents.length === 0) {
            intents.push({
                intent: 'Reconnaissance',
                confidence: 50,
                reasoning: 'Insufficient indicators to determine specific intent, possibly probing for vulnerabilities'
            });
            attackType = 'Suspicious Activity';
        }

        return {
            attackerIntent: intents,
            vulnerabilities,
            confidence,
            attackType
        };
    }
}

export const reasoningEngine = new ReasoningEngine();
