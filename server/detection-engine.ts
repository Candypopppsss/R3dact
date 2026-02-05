export interface DetectionResult {
    isPhishing: boolean;
    threatScore: number;
    indicators: Indicator[];
    category: 'url' | 'email' | 'message';
}

export interface Indicator {
    type: string;
    severity: 'high' | 'medium' | 'low';
    description: string;
    evidence?: string;
}

class DetectionEngine {
    analyzeURL(url: string): DetectionResult {
        const indicators: Indicator[] = [];
        let threatScore = 0;

        try {
            const urlObj = new URL(url);

            // Check for IP address instead of domain
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname)) {
                indicators.push({
                    type: 'IP Address',
                    severity: 'high',
                    description: 'URL uses IP address instead of domain name',
                    evidence: urlObj.hostname
                });
                threatScore += 25;
            }

            // Check for suspicious TLDs
            const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
            if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) {
                indicators.push({
                    type: 'Suspicious TLD',
                    severity: 'medium',
                    description: 'Domain uses a TLD commonly associated with phishing',
                    evidence: urlObj.hostname.split('.').pop()
                });
                threatScore += 15;
            }

            // Check for typosquatting of common brands
            const commonBrands = ['paypal', 'google', 'microsoft', 'amazon', 'apple', 'facebook', 'netflix', 'instagram'];
            const hostname = urlObj.hostname.toLowerCase();

            for (const brand of commonBrands) {
                if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)) {
                    // Check for common typosquatting patterns
                    const patterns = [
                        brand.replace('l', '1'),
                        brand.replace('o', '0'),
                        brand + '-',
                        brand + 'secure',
                        brand + 'verify',
                        'secure' + brand,
                    ];

                    if (patterns.some(p => hostname.includes(p))) {
                        indicators.push({
                            type: 'Typosquatting',
                            severity: 'high',
                            description: `Possible typosquatting of ${brand}`,
                            evidence: urlObj.hostname
                        });
                        threatScore += 30;
                        break;
                    }
                }
            }

            // Check for excessive subdomains
            const subdomains = urlObj.hostname.split('.');
            if (subdomains.length > 4) {
                indicators.push({
                    type: 'Excessive Subdomains',
                    severity: 'medium',
                    description: 'URL has an unusual number of subdomains',
                    evidence: `${subdomains.length} levels`
                });
                threatScore += 10;
            }

            // Check for suspicious keywords in URL
            const suspiciousKeywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'banking', 'password'];
            const fullURL = url.toLowerCase();
            const foundKeywords = suspiciousKeywords.filter(kw => fullURL.includes(kw));

            if (foundKeywords.length >= 2) {
                indicators.push({
                    type: 'Suspicious Keywords',
                    severity: 'medium',
                    description: 'URL contains multiple security-related keywords',
                    evidence: foundKeywords.join(', ')
                });
                threatScore += 15;
            }

            // Check for URL obfuscation (@ symbol, excessive dashes)
            if (url.includes('@')) {
                indicators.push({
                    type: 'URL Obfuscation',
                    severity: 'high',
                    description: 'URL contains @ symbol, potentially hiding real destination',
                    evidence: url
                });
                threatScore += 25;
            }

            // Check for non-HTTPS
            if (urlObj.protocol === 'http:' && foundKeywords.length > 0) {
                indicators.push({
                    type: 'Insecure Protocol',
                    severity: 'medium',
                    description: 'Sensitive page not using HTTPS encryption',
                    evidence: 'HTTP instead of HTTPS'
                });
                threatScore += 10;
            }

        } catch (error) {
            indicators.push({
                type: 'Invalid URL',
                severity: 'high',
                description: 'Malformed or invalid URL structure',
                evidence: 'Failed to parse URL'
            });
            threatScore += 20;
        }

        return {
            isPhishing: threatScore >= 40,
            threatScore: Math.min(100, threatScore),
            indicators,
            category: 'url'
        };
    }

    analyzeContent(content: string, type: 'email' | 'message'): DetectionResult {
        const indicators: Indicator[] = [];
        let threatScore = 0;
        const lowerContent = content.toLowerCase();

        // Check for urgency indicators
        const urgencyKeywords = [
            'urgent', 'immediately', 'act now', 'limited time', 'expires today',
            'within 24 hours', 'account suspended', 'verify now', 'click here now',
            'last chance', 'final notice', 'action required'
        ];

        const foundUrgency = urgencyKeywords.filter(kw => lowerContent.includes(kw));
        if (foundUrgency.length > 0) {
            indicators.push({
                type: 'Urgency Tactics',
                severity: foundUrgency.length > 2 ? 'high' : 'medium',
                description: 'Message uses urgency to pressure immediate action',
                evidence: foundUrgency.slice(0, 3).join(', ')
            });
            threatScore += foundUrgency.length * 10;
        }

        // Check for credential requests
        const credentialKeywords = [
            'password', 'social security', 'credit card', 'bank account',
            'pin number', 'verify your identity', 'confirm your account',
            'update payment', 'billing information'
        ];

        const foundCredentials = credentialKeywords.filter(kw => lowerContent.includes(kw));
        if (foundCredentials.length > 0) {
            indicators.push({
                type: 'Credential Request',
                severity: 'high',
                description: 'Message requests sensitive personal information',
                evidence: foundCredentials.slice(0, 2).join(', ')
            });
            threatScore += 25;
        }

        // Check for authority impersonation
        const authorityKeywords = [
            'irs', 'fbi', 'police', 'government', 'tax authority',
            'your bank', 'paypal', 'amazon', 'microsoft support',
            'apple support', 'google security'
        ];

        const foundAuthority = authorityKeywords.filter(kw => lowerContent.includes(kw));
        if (foundAuthority.length > 0) {
            indicators.push({
                type: 'Authority Impersonation',
                severity: 'high',
                description: 'Claims to be from trusted authority or organization',
                evidence: foundAuthority[0]
            });
            threatScore += 20;
        }

        // Check for threats/consequences
        const threatKeywords = [
            'account will be closed', 'legal action', 'suspended', 'terminated',
            'frozen', 'locked out', 'penalty', 'fine', 'arrest'
        ];

        const foundThreats = threatKeywords.filter(kw => lowerContent.includes(kw));
        if (foundThreats.length > 0) {
            indicators.push({
                type: 'Threatening Language',
                severity: 'high',
                description: 'Uses threats or negative consequences to coerce action',
                evidence: foundThreats.slice(0, 2).join(', ')
            });
            threatScore += 20;
        }

        // Check for reward/prize offers
        const rewardKeywords = [
            'you won', 'prize', 'lottery', 'inheritance', 'refund',
            'claim your', 'congratulations', 'selected winner', 'free gift'
        ];

        const foundRewards = rewardKeywords.filter(kw => lowerContent.includes(kw));
        if (foundRewards.length > 0) {
            indicators.push({
                type: 'Too Good to Be True',
                severity: 'medium',
                description: 'Offers unrealistic rewards or prizes',
                evidence: foundRewards[0]
            });
            threatScore += 15;
        }

        // Check for suspicious links
        const urlPattern = /https?:\/\/[^\s]+/gi;
        const urls = content.match(urlPattern) || [];

        if (urls.length > 0) {
            const suspiciousUrls = urls.filter(url => {
                const lower = url.toLowerCase();
                return lower.includes('bit.ly') ||
                    lower.includes('tinyurl') ||
                    lower.includes('.tk') ||
                    lower.includes('.xyz') ||
                    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
            });

            if (suspiciousUrls.length > 0) {
                indicators.push({
                    type: 'Suspicious Links',
                    severity: 'medium',
                    description: 'Contains shortened or suspicious URLs',
                    evidence: `${suspiciousUrls.length} suspicious link(s)`
                });
                threatScore += 15;
            }
        }

        // Check for poor grammar/spelling (simple heuristic)
        const grammarIssues = [
            'dear customer', 'dear user', 'dear member',
            'kindly', 'needful', 'revert back'
        ];

        const foundGrammar = grammarIssues.filter(issue => lowerContent.includes(issue));
        if (foundGrammar.length > 0) {
            indicators.push({
                type: 'Generic Greeting',
                severity: 'low',
                description: 'Uses generic, impersonal greeting',
                evidence: foundGrammar[0]
            });
            threatScore += 5;
        }

        return {
            isPhishing: threatScore >= 40,
            threatScore: Math.min(100, threatScore),
            indicators,
            category: type
        };
    }

    analyze(input: string, type?: 'url' | 'email' | 'message'): DetectionResult {
        // Auto-detect if it's a URL
        if (!type) {
            if (input.match(/^https?:\/\//i)) {
                type = 'url';
            } else if (input.includes('@') && input.includes('subject:')) {
                type = 'email';
            } else {
                type = 'message';
            }
        }

        if (type === 'url') {
            return this.analyzeURL(input);
        } else {
            return this.analyzeContent(input, type);
        }
    }
}

export const detectionEngine = new DetectionEngine();
