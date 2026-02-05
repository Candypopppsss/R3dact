import { DetectionResult, Indicator } from './detection-engine.js';
import { ReasoningResult } from './reasoning-engine.js';

export interface Explanation {
    summary: string;
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
    detailedAnalysis: string[];
    recommendations: string[];
    technicalDetails: TechnicalDetail[];
}

export interface TechnicalDetail {
    category: string;
    findings: string[];
}

class ExplainabilityEngine {
    generateExplanation(detection: DetectionResult, reasoning: ReasoningResult): Explanation {
        const riskLevel = this.determineRiskLevel(detection.threatScore);
        const summary = this.generateSummary(detection, reasoning, riskLevel);
        const detailedAnalysis = this.generateDetailedAnalysis(detection, reasoning);
        const recommendations = this.generateRecommendations(detection, reasoning, riskLevel);
        const technicalDetails = this.generateTechnicalDetails(detection, reasoning);

        return {
            summary,
            riskLevel,
            detailedAnalysis,
            recommendations,
            technicalDetails
        };
    }

    private determineRiskLevel(threatScore: number): 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe' {
        if (threatScore >= 80) return 'Critical';
        if (threatScore >= 60) return 'High';
        if (threatScore >= 40) return 'Medium';
        if (threatScore >= 20) return 'Low';
        return 'Safe';
    }

    private generateSummary(detection: DetectionResult, reasoning: ReasoningResult, riskLevel: string): string {
        if (riskLevel === 'Safe') {
            return 'No significant threats detected. This appears to be legitimate content.';
        }

        const primaryIntent = reasoning.attackerIntent[0]?.intent || 'malicious activity';
        const indicatorCount = detection.indicators.length;

        return `⚠️ ${riskLevel} Risk Detected: This appears to be a ${reasoning.attackType} attempt. ` +
            `Identified ${indicatorCount} suspicious indicator${indicatorCount !== 1 ? 's' : ''} ` +
            `suggesting ${primaryIntent.toLowerCase()}.`;
    }

    private generateDetailedAnalysis(detection: DetectionResult, reasoning: ReasoningResult): string[] {
        const analysis: string[] = [];

        // Threat score explanation
        analysis.push(
            `**Threat Score: ${detection.threatScore}/100** - ` +
            `This score is calculated based on ${detection.indicators.length} detected indicators, ` +
            `weighted by their severity levels.`
        );

        // Attack type and intent
        if (reasoning.attackerIntent.length > 0) {
            const intents = reasoning.attackerIntent
                .map(i => `${i.intent} (${i.confidence}% confidence)`)
                .join(', ');
            analysis.push(
                `**Attacker Intent**: ${intents}. ` +
                `${reasoning.attackerIntent[0].reasoning}`
            );
        }

        // Vulnerability exploitation
        if (reasoning.vulnerabilities.length > 0) {
            const vulnList = reasoning.vulnerabilities
                .map(v => `**${v.trigger}**: ${v.description}`)
                .join(' | ');
            analysis.push(
                `**Psychological Tactics**: This attack exploits human vulnerabilities: ${vulnList}`
            );
        }

        // Indicator breakdown
        const highSeverity = detection.indicators.filter(i => i.severity === 'high');
        const mediumSeverity = detection.indicators.filter(i => i.severity === 'medium');
        const lowSeverity = detection.indicators.filter(i => i.severity === 'low');

        if (highSeverity.length > 0) {
            analysis.push(
                `**Critical Indicators (${highSeverity.length})**: ` +
                highSeverity.map(i => `${i.type} - ${i.description}`).join(' | ')
            );
        }

        if (mediumSeverity.length > 0) {
            analysis.push(
                `**Warning Signs (${mediumSeverity.length})**: ` +
                mediumSeverity.map(i => `${i.type} - ${i.description}`).join(' | ')
            );
        }

        if (lowSeverity.length > 0) {
            analysis.push(
                `**Minor Concerns (${lowSeverity.length})**: ` +
                lowSeverity.map(i => i.type).join(', ')
            );
        }

        return analysis;
    }

    private generateRecommendations(detection: DetectionResult, reasoning: ReasoningResult, riskLevel: string): string[] {
        const recommendations: string[] = [];

        if (riskLevel === 'Critical' || riskLevel === 'High') {
            recommendations.push('🛑 **DO NOT** interact with this content or click any links');
            recommendations.push('🗑️ Delete this message immediately');

            if (detection.category === 'email') {
                recommendations.push('📧 Report as phishing to your email provider');
                recommendations.push('🔒 If you clicked any links, change your passwords immediately');
            }

            if (detection.indicators.some(i => i.type === 'Credential Request')) {
                recommendations.push('⚠️ Never entered credentials? Good! If you did, change passwords NOW');
            }
        }

        if (riskLevel === 'Medium') {
            recommendations.push('⚠️ Exercise extreme caution with this content');
            recommendations.push('🔍 Verify the sender through official channels before responding');
            recommendations.push('🚫 Do not click links or download attachments');
        }

        if (riskLevel === 'Low') {
            recommendations.push('👀 Be cautious and verify the source independently');
            recommendations.push('🔗 Hover over links to check actual destinations before clicking');
        }

        // Specific recommendations based on attack type
        if (reasoning.attackerIntent.some(i => i.intent === 'Credential Theft')) {
            recommendations.push('🔐 Enable two-factor authentication on all important accounts');
        }

        if (reasoning.attackerIntent.some(i => i.intent === 'Financial Fraud')) {
            recommendations.push('💳 Monitor your bank statements for unauthorized transactions');
        }

        if (reasoning.vulnerabilities.some(v => v.trigger === 'Fear & Anxiety')) {
            recommendations.push('🧘 Take a moment to verify - legitimate organizations don\'t create panic');
        }

        if (reasoning.vulnerabilities.some(v => v.trigger === 'Authority Bias')) {
            recommendations.push('📞 Contact the organization directly using official contact information');
        }

        // General best practices
        if (riskLevel !== 'Safe') {
            recommendations.push('📚 Educate yourself and others about these tactics to stay protected');
        }

        return recommendations;
    }

    private generateTechnicalDetails(detection: DetectionResult, reasoning: ReasoningResult): TechnicalDetail[] {
        const details: TechnicalDetail[] = [];

        // Detection indicators
        const indicatorsByType = detection.indicators.reduce((acc, indicator) => {
            if (!acc[indicator.severity]) {
                acc[indicator.severity] = [];
            }
            acc[indicator.severity].push(
                `${indicator.type}: ${indicator.description}${indicator.evidence ? ` (${indicator.evidence})` : ''}`
            );
            return acc;
        }, {} as Record<string, string[]>);

        if (indicatorsByType.high) {
            details.push({
                category: 'High Severity Indicators',
                findings: indicatorsByType.high
            });
        }

        if (indicatorsByType.medium) {
            details.push({
                category: 'Medium Severity Indicators',
                findings: indicatorsByType.medium
            });
        }

        if (indicatorsByType.low) {
            details.push({
                category: 'Low Severity Indicators',
                findings: indicatorsByType.low
            });
        }

        // Intent analysis
        if (reasoning.attackerIntent.length > 0) {
            details.push({
                category: 'Attacker Intent Analysis',
                findings: reasoning.attackerIntent.map(
                    i => `${i.intent} (${i.confidence}% confidence): ${i.reasoning}`
                )
            });
        }

        // Vulnerability exploitation
        if (reasoning.vulnerabilities.length > 0) {
            details.push({
                category: 'Exploited Vulnerabilities',
                findings: reasoning.vulnerabilities.map(
                    v => `${v.trigger} [${v.severity}]: ${v.description}`
                )
            });
        }

        // Attack classification
        details.push({
            category: 'Attack Classification',
            findings: [
                `Type: ${reasoning.attackType}`,
                `Category: ${detection.category}`,
                `Overall Confidence: ${reasoning.confidence}%`,
                `Phishing Detected: ${detection.isPhishing ? 'Yes' : 'No'}`
            ]
        });

        return details;
    }
}

export const explainabilityEngine = new ExplainabilityEngine();
