# AI Security Guardian - Python FastAPI Backend

## Quick Start

### 1. Install Dependencies
```bash
cd api
pip install -r requirements.txt
```

### 2. Run the Server
```bash
python main.py
```

The API will be available at `http://localhost:8000`

### 3. Test the Endpoint

**Example Request:**
```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT! Your account has been suspended. Click here to verify your identity immediately or face permanent closure."}'
```

**Example Response:**
```json
{
  "risk_score": 85,
  "classification": "Phishing",
  "attacker_persona": "Social Engineer - Creating urgency to bypass critical thinking",
  "recommended_action": "🛑 DO NOT respond or click any links. Delete immediately and report as phishing.",
  "explanation": "This message has been classified as **Phishing** with a risk score of **85/100**.\n\n**Attacker Profile**: Social Engineer - Creating urgency to bypass critical thinking\n\n**Why this is dangerous**:\n• Uses urgency tactics (3 instances)\n• Requests sensitive information (verify your identity)\n• Uses threatening language (suspended)\n• Contains suspicious pattern: click here\n• Contains suspicious pattern: verify account\n\n**What they want**: The attacker is trying to manipulate you into sharing sensitive information. They exploit psychological triggers like fear and urgency to bypass your natural skepticism."
}
```

## API Documentation

Once running, visit:
- **Interactive API Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

## Endpoints

### POST /analyze
Analyzes text for phishing and social engineering attacks.

**Request Body:**
```json
{
  "text": "string (min 10 characters)"
}
```

**Response:**
```json
{
  "risk_score": 0-100,
  "classification": "Safe | Suspicious | Phishing",
  "attacker_persona": "string",
  "recommended_action": "string",
  "explanation": "string"
}
```

### GET /health
Health check endpoint.

## Detection Features

- **Urgency Detection**: Identifies time-pressure tactics
- **Credential Harvesting**: Detects requests for sensitive information
- **Authority Impersonation**: Recognizes fake authority claims
- **Threat Analysis**: Identifies intimidation tactics
- **Reward Scams**: Detects too-good-to-be-true offers
- **Pattern Matching**: Finds suspicious URLs and phrases
- **Behavioral Analysis**: Checks for excessive caps and punctuation

## Risk Score Calculation

- **0-39**: Safe - Low risk, appears legitimate
- **40-69**: Suspicious - Medium risk, verify before acting
- **70-100**: Phishing - High risk, likely malicious

## Integration with Frontend

Update your frontend to point to `http://localhost:8000/analyze` instead of the Node.js backend, or run both backends simultaneously on different ports.
