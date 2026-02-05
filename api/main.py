from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List
import re
import json
import sqlite3
from datetime import datetime
from pathlib import Path

app = FastAPI(title="AI Security Agent")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory storage (simulating persistent memory store)
agent_memory = []

class AISecurityAgent:
    def __init__(self):
        self.db_path = "agent_memory.db"
        self._init_db()
        self.rules = {
            "critical_patterns": [
                r'password', r'ssn', r'credit card', r'pin', r'bank account',
                r'http://\d+\.\d+\.\d+\.\d+', r'verify identity'
            ],
            "suspicious_patterns": [
                r'urgent', r'immediately', r'suspended', r'claim your',
                r'congratulations', r'click here', r'verify now'
            ]
        }

    def _init_db(self):
        """Initialize SQLite database for persistent memory"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    input_text TEXT,
                    classification TEXT,
                    attacker_persona TEXT,
                    risk_score INTEGER
                )
            ''')
            conn.commit()

    def observe(self, text: str) -> str:
        """Step 1: Observe input and look for historical context"""
        return text.strip()

    def check_historical_context(self, persona: str) -> Dict:
        """Query memory for similar historical patterns"""
        if persona == "Benign":
            return None
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM memory WHERE attacker_persona = ? AND timestamp > datetime('now', '-7 days')",
                (persona,)
            )
            count = cursor.fetchone()[0]
            
            if count > 0:
                return {
                    "seen_before": True,
                    "count": count,
                    "message": f"Note: A similar **{persona}** pattern has been observed {count} times in the last 7 days."
                }
        return None

    def analyze(self, input_text: str) -> Dict:
        """Step 2: Analyze threat, infer persona, and assess vulnerability"""
        text_lower = input_text.lower()
        risk_score = 0
        findings = []
        signals = {"credentials": 0, "urgency": 0, "brands": 0, "financial": 0, "authority": 0}

        # Enhanced pattern detection
        for pattern in self.rules["critical_patterns"]:
            if re.search(pattern, text_lower):
                risk_score += 35
                findings.append(f"Critical pattern: {pattern}")
                if any(p in pattern for p in ['password', 'verify', 'ssn']):
                    signals["credentials"] += 1

        for pattern in self.rules["suspicious_patterns"]:
            if re.search(pattern, text_lower):
                risk_score += 15
                findings.append(f"Suspicious pattern: {pattern}")
                if any(p in pattern for p in ['urgent', 'immediately']):
                    signals["urgency"] += 1
                if any(p in pattern for p in ['claim', 'congratulations']):
                    signals["financial"] += 1

        # Brand and Authority detection
        brands = ['paypal', 'microsoft', 'amazon', 'google', 'apple', 'netflix']
        authorities = ['security', 'alert', 'official', 'bank', 'support', 'department']
        
        for brand in brands:
            if brand in text_lower:
                signals["brands"] += 1
                findings.append(f"Reference to brand: {brand}")
        
        for auth in authorities:
            if auth in text_lower:
                signals["authority"] += 1
                findings.append(f"Authority language: {auth}")

        risk_score = min(100, risk_score)
        
        # Human Vulnerability Assessment
        triggers = []
        if signals["urgency"] > 0: triggers.append("Artificial Urgency")
        if signals["authority"] > 0 or signals["brands"] > 0: triggers.append("Authority Bias")
        if signals["financial"] > 0: triggers.append("Emotional Manipulation (Reward/Greed)")
        if signals["credentials"] > 0 and signals["urgency"] > 0: triggers.append("Fear-Induced Compliance")

        vuln_score = (signals["urgency"] * 25) + (signals["authority"] * 15) + (signals["financial"] * 20)
        vuln_score = min(95, max(10, vuln_score)) if risk_score > 20 else 5
        
        if vuln_score >= 75:
            vuln_rating = "Very High"
        elif vuln_score >= 50:
            vuln_rating = "High"
        elif vuln_score >= 25:
            vuln_rating = "Moderate"
        else:
            vuln_rating = "Low"

        # Persona Inference
        if risk_score < 40:
            persona = "Benign"
        elif signals["brands"] > 0 and signals["credentials"] > 0:
            persona = "Brand Impersonator"
        elif signals["credentials"] > 0:
            persona = "Credential Harvester"
        elif signals["urgency"] > 0 or signals["financial"] > 0:
            persona = "Social Engineer"
        else:
            persona = "Unknown Threat"

        classification = "Safe"
        if risk_score >= 70:
            classification = "Phishing"
        elif risk_score >= 40:
            classification = "Suspicious"

        return {
            "score": risk_score,
            "classification": classification,
            "findings": findings,
            "persona": persona,
            "vulnerability": {
                "score": vuln_score,
                "rating": vuln_rating,
                "triggers": triggers
            }
        }

    def decide(self, analysis: Dict) -> str:
        """Step 3: Decide explicit action"""
        score = analysis["score"]
        if score >= 70:
            return "Block and Alert"
        elif score >= 40:
            return "Warn User"
        else:
            return "Allow"

    def explain(self, input_text: str, analysis: Dict, decision: str, history: Dict = None) -> str:
        """Step 4: Explain reasoning with signals, tips, and historical context"""
        persona = analysis["persona"]
        vuln = analysis["vulnerability"]
        
        tips = [
            "Tip: Always hover over links before clicking to see the actual destination URL.",
            "Tip: Legitimate organizations will never ask for your password or SSN via email/message.",
            "Tip: If a message creates extreme urgency, slow down. Attackers use time pressure to bypass logic.",
            "Tip: When in doubt, contact the sender through a known, official channel or website.",
            "Tip: Check for subtle misspellings in brand names (e.g., 'PayPa1' instead of 'PayPal')."
        ]
        
        selected_tip = tips[hash(input_text) % len(tips)]
        
        if decision == "Allow":
            return (
                f"As your AI Security Agent, I have identified this input as **{persona}**. "
                "Following a deep inspection of the content, no malicious heuristics, known phishing patterns, "
                "or social engineering tactics were detected. The message structure and intent appear benign, "
                "and it is safe for you to interact with this content.\n\n"
                f"**Security Awareness**: {selected_tip}"
            )
        
        # Why it was flagged (Plain English)
        explanation = f"As your AI Security Agent, I have decided to **{decision}**.\n\n"
        
        # Add Historical Context if found
        if history and history.get("seen_before"):
            explanation += f"**Historical Context Alert**: {history['message']} This suggests a targeted or automated campaign may be active against your account.\n\n"

        explanation += "### Why this was flagged\n"
        if decision == "Block and Alert":
            explanation += f"This message has been classified as a **High-Risk Threat** from an attacker acting as a **{persona}**. "
            explanation += "My analysis engine detected explicit markers and malicious intent designed to deceive you into disclosing sensitive information. "
            explanation += "The combination of technical indicators and psychological pressure confirms this is an active phishing attempt."
        else:
            explanation += f"This message is considered **Suspicious**. While it may not contain a direct exploit, it uses highly manipulative tactics "
            explanation += "consistent with social engineering attacks. It attempts to prime you for a follow-up action by creating an artificial context or emotional state."
            
        # Which signals contributed
        explanation += "\n\n### Technical Evidence & Threat Signals\n"
        explanation += "I have identified the following patterns that form the basis of this assessment:\n"
        if analysis["findings"]:
            for finding in analysis["findings"][:5]:
                explanation += f"• **{finding}**: This is a known indicator used to establish false trust or urgency.\n"
        
        # Psychological/Vulnerability reasoning
        explanation += f"\n### Psychological Vulnerability Assessment\n"
        explanation += f"This attack has a **{vuln['rating']}** ({vuln['score']}%) likelihood of bypassing standard human defenses because it exploits: *{', '.join(vuln['triggers'])}*.\n\n"
        
        if "Artificial Urgency" in vuln["triggers"]:
            explanation += "**Urgency Exploitation**: The sender is imposing a strict time limit to force a 'system 1' emotional response, preventing you from performing rational verification.\n"
        if "Authority Bias" in vuln["triggers"]:
            explanation += "**Authority Impersonation**: By mimicking trusted institutional language or brands, the attacker attempts to inherit the trust you have in those organizations.\n"
        if "Fear-Induced Compliance" in vuln["triggers"]:
            explanation += "**Fear Tactics**: The message uses threats (like account closure) to trigger a stress response, making you more likely to comply with instructions to avoid a negative outcome.\n"
            
        # Security Tip
        explanation += f"\n### Proactive Security Tip\n{selected_tip}"
            
        return explanation

    def store(self, result: Dict):
        """Step 5: Store in persistent SQLite memory"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO memory (timestamp, input_text, classification, attacker_persona, risk_score) VALUES (?, ?, ?, ?, ?)",
                (result["timestamp"], result["input"], result["analysis"]["classification"], 
                 result["analysis"]["persona"], result["analysis"]["score"])
            )
            conn.commit()

    def run_agent_flow(self, text: str) -> Dict:
        # Flow: Observe -> Analyze -> Decide -> Explain -> Store
        observed_input = self.observe(text)
        analysis = self.analyze(observed_input)
        
        # Check history for the inferred persona
        history = self.check_historical_context(analysis["persona"])
        
        decision = self.decide(analysis)
        explanation = self.explain(observed_input, analysis, decision, history)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "input": observed_input,
            "analysis": analysis,
            "agent_decision": decision,
            "explanation": explanation,
            "attacker_persona": analysis["persona"],
            "vulnerability_assessment": analysis["vulnerability"]
        }
        
        self.store(result)
        return result

# Initialize Agent
agent = AISecurityAgent()

@app.post("/analyze")
async def analyze_endpoint(request: Dict):
    text = request.get("text", "")
    if len(text) < 5:
        raise HTTPException(status_code=400, detail="Input text too short")
    
    # Run the Agentic Flow
    agent_output = agent.run_agent_flow(text)
    
    return {
        "risk_score": agent_output["analysis"]["score"],
        "classification": agent_output["analysis"]["classification"],
        "attacker_persona": agent_output["attacker_persona"],
        "vulnerability_assessment": agent_output["vulnerability_assessment"],
        "agent_decision": agent_output["agent_decision"],
        "explanation": agent_output["explanation"],
        "timestamp": agent_output["timestamp"]
    }

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = Path(__file__).parent / "index.html"
    if index_path.exists():
        return index_path.read_text()
    return "AI Security Agent API is running. index.html not found."

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
