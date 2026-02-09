from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

app = FastAPI(title="AI Security Agent")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for validation
class AnalysisRequest(BaseModel):
    text: str = Field(..., min_length=5, description="The content to analyze for security threats")

class VulnerabilityAssessment(BaseModel):
    score: int
    rating: str
    triggers: List[str]

class AnalysisResponse(BaseModel):
    risk_score: int
    classification: str
    attacker_persona: str
    vulnerability_assessment: VulnerabilityAssessment
    agent_decision: str
    explanation: str
    timestamp: str

class AISecurityAgent:
    def __init__(self):
        self.db_path = "agent_memory.db"
        self._init_db()
        # Pre-compile regex for performance
        self.critical_patterns = re.compile(
            r'password|ssn|credit card|pin|bank account|http://\d+\.\d+\.\d+\.\d+|verify identity', 
            re.IGNORECASE
        )
        self.suspicious_patterns = re.compile(
            r'urgent|immediately|suspended|claim your|congratulations|click here|verify now', 
            re.IGNORECASE
        )

    @contextmanager
    def get_db(self):
        """Safe context manager for SQLite connections"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initialize SQLite database for persistent memory"""
        with self.get_db() as conn:
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
        return text.strip()

    def check_historical_context(self, persona: str) -> Optional[Dict]:
        if persona == "Benign":
            return None
            
        with self.get_db() as conn:
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
        text_lower = input_text.lower()
        findings = []
        signals = {"credentials": 0, "urgency": 0, "brands": 0, "financial": 0, "authority": 0}
        
        # Pattern detection
        critical_matches = self.critical_patterns.findall(text_lower)
        suspicious_matches = self.suspicious_patterns.findall(text_lower)
        
        risk_score = (len(critical_matches) * 35) + (len(suspicious_matches) * 15)
        
        for m in critical_matches:
            findings.append(f"Critical pattern: {m}")
            if any(p in m for p in ['password', 'verify', 'ssn']):
                signals["credentials"] += 1

        for m in suspicious_matches:
            findings.append(f"Suspicious pattern: {m}")
            if any(p in m for p in ['urgent', 'immediately']):
                signals["urgency"] += 1
            if any(p in m for p in ['claim', 'congratulations']):
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
        
        vuln_rating = "Low"
        if vuln_score >= 75: vuln_rating = "Very High"
        elif vuln_score >= 50: vuln_rating = "High"
        elif vuln_score >= 25: vuln_rating = "Moderate"

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
        if risk_score >= 70: classification = "Phishing"
        elif risk_score >= 40: classification = "Suspicious"

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
        score = analysis["score"]
        if score >= 70: return "Block and Alert"
        elif score >= 40: return "Warn User"
        return "Allow"

    def explain(self, input_text: str, analysis: Dict, decision: str, history: Optional[Dict] = None) -> str:
        persona = analysis["persona"]
        vuln = analysis["vulnerability"]
        
        tips = [
            "Tip: Always hover over links before clicking to see the actual destination.",
            "Tip: Legitimate organizations never ask for passwords via email.",
            "Tip: Attackers use time pressure to bypass logic.",
            "Tip: Contact the sender through an official channel if unsure.",
            "Tip: Check for subtle misspellings in brand names."
        ]
        selected_tip = tips[len(input_text) % len(tips)] # Deterministic tip
        
        if decision == "Allow":
            return f"As your AI Security Agent, I have identified this as **{persona}**. No threats detected.\n\n**Security Awareness**: {selected_tip}"
        
        explanation = f"As your AI Security Agent, I have decided to **{decision}**.\n\n"
        if history and history.get("seen_before"):
            explanation += f"**Historical Context Alert**: {history['message']}\n\n"

        explanation += "### Why this was flagged\n"
        if decision == "Block and Alert":
            explanation += f"Classified as a **High-Risk Threat** from a **{persona}**. Malicious markers detected."
        else:
            explanation += f"Considered **Suspicious**. Uses manipulative tactics consistent with social engineering."
            
        explanation += "\n\n### Technical Evidence\n"
        for finding in analysis["findings"][:5]:
            explanation += f"• **{finding}**\n"
        
        explanation += f"\n### Vulnerability Assessment\n"
        explanation += f"Risk level: **{vuln['rating']}** ({vuln['score']}%). Exploits: *{', '.join(vuln['triggers'])}*.\n"
        explanation += f"\n**Proactive Tip**: {selected_tip}"
            
        return explanation

    def store(self, result: Dict):
        with self.get_db() as conn:
            conn.execute(
                "INSERT INTO memory (timestamp, input_text, classification, attacker_persona, risk_score) VALUES (?, ?, ?, ?, ?)",
                (result["timestamp"], result["input"], result["analysis"]["classification"], 
                 result["analysis"]["persona"], result["analysis"]["score"])
            )
            conn.commit()

    def run_agent_flow(self, text: str) -> Dict:
        observed_input = self.observe(text)
        analysis = self.analyze(observed_input)
        history = self.check_historical_context(analysis["persona"])
        decision = self.decide(analysis)
        explanation = self.explain(observed_input, analysis, decision, history)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "input": observed_input,
            "analysis": analysis,
            "agent_decision": decision,
            "explanation": explanation
        }
        self.store(result)
        return result

# Initialize Agent
agent = AISecurityAgent()

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_endpoint(request: AnalysisRequest):
    agent_output = agent.run_agent_flow(request.text)
    
    return {
        "risk_score": agent_output["analysis"]["score"],
        "classification": agent_output["analysis"]["classification"],
        "attacker_persona": agent_output["analysis"]["persona"],
        "vulnerability_assessment": agent_output["analysis"]["vulnerability"],
        "agent_decision": agent_output["agent_decision"],
        "explanation": agent_output["explanation"],
        "timestamp": agent_output["timestamp"]
    }

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = Path(__file__).parent / "index.html"
    return index_path.read_text() if index_path.exists() else "API is running."

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
