# CloudShield — Project Presentation & Viva Guide

**Project Title:** CloudShield: Adaptive Cloud Threat Detection & Risk Scoring  
**Project Subtitle:** A Lightweight, Explainable Cloud Security Prototype  
**Audience:** College Viva, Project Defense, Technical Presentation, and Academic Evaluation  

---

## 1. What is the Project About?

**CloudShield** is a transparent, explainable cloud security monitoring prototype designed to solve one of the biggest challenges in cloud infrastructure defense: **distinguishing harmless anomalies from genuine, coordinated attacks**.

Instead of relying on rigid, all-or-nothing binary blocking (e.g., blocking an IP after one error) or complex, opaque "black-box" machine learning algorithms, CloudShield monitors cloud web application events, correlates multiple suspicious activities from the same source, calculates a dynamic **Adaptive Risk Score from 0 to 100**, and provides **explainable security alerts** with a chronological **incident timeline**.

### The Core Architectural Flow
```
User Activity 
      ↓
Security Logs (Telemetry)
      ↓
Threat Detection Rules
      ↓
Adaptive Risk Score (0–100)
      ↓
Threat Level (Normal → Suspicious → High Risk → Critical)
      ↓
Explainable Security Alert & Incident Timeline
```

---

## 2. What Problem Are We Solving?

In cloud environments (such as AWS, Azure, GCP, or private servers), modern applications generate thousands of security logs daily. Security operations teams face four critical challenges:

1. **Alert Fatigue from Isolated Logs:**  
   Traditional intrusion detection systems treat every event in isolation. A single failed password attempt triggers an alert; a user accidentally clicking a protected link triggers another. Analysts are overwhelmed by disconnected notifications.

2. **The "Binary Block" Dilemma (False Positives):**  
   Traditional firewalls often have binary rules: either an IP is completely unrestricted or it is permanently banned. If a legitimate user mistypes their password twice, a binary system blocks them, frustrating customers.

3. **"Black Box" Security Models:**  
   Many enterprise tools claim to use deep learning or complex AI, but when an alert is raised, they cannot explain *why* an IP was blocked. During security audits or troubleshooting, engineers need transparent reasons, not guesswork.

4. **Permanent Penalties Without Recovery:**  
   When an IP address is penalized, traditional systems keep the block active indefinitely or require manual administrator intervention, even after the suspicious behavior has completely stopped.

---

## 3. What Did We Make?

We built a clean, working cybersecurity prototype with **zero bloated dependencies**, specifically designed to be easy to demonstrate and explain during an academic viva.

### The 4 Main Pages

| Page | Primary Purpose | Key Features |
|---|---|---|
| **1. Dashboard** | Executive Cloud Overview | • 4 key statistic cards (Total Events: 1248, Normal: 1095, Suspicious: 121, Critical: 32)<br>• Clean Risk Distribution Chart (Normal, Suspicious, High Risk, Critical)<br>• Recent Security Alerts list with colored severity badges |
| **2. Security Events** | Raw Telemetry Stream | • Tabular view of incoming security events (`Time`, `IP Address`, `Event`, `Endpoint`, `Status`)<br>• Instant 1-click filtering (`All`, `Normal`, `Suspicious`, `High Risk`, `Critical`) |
| **3. Risk Analysis** *(Main Novelty)* | Transparent Risk Scoring | • Direct IP selector (defaulting to critical target `192.168.1.24`)<br>• 0–100 Risk Hero dial & dynamic progress bar<br>• Transparent **Risk Factors Breakdown** (+30, +25, +20, +10, -3 = 82)<br>• **Live Attack Escalation Simulator** (20 → 40 → 65 → 82)<br>• **Adaptive Risk Decay Simulator** (82 → 72 → 62 → 52 → 42 → 25) |
| **4. Incidents** | Correlated Threat Management | • List of correlated security incidents (`Incident ID`, `IP`, `Threat`, `Risk Score`, `Severity`, `Time`, `Status`)<br>• Clickable row opening the **Explainable Alert Modal** with "Why was this flagged?" checklist & **Incident Timeline** |

---

## 4. The 3 Core Novelties of CloudShield

### Novelty 1: Adaptive Risk Scoring (0–100)
Rather than simple binary blocking, CloudShield maintains a stateful risk score for every observed client IP:
- **0–25:** **Normal** (Safe, routine activity)
- **26–50:** **Suspicious** (Low-level anomaly, monitor closely)
- **51–75:** **High Risk** (Elevated threat, issue CAPTCHA / rate-limit)
- **76–100:** **Critical** (Active attack pattern, temporarily restrict IP)

### Novelty 2: Transparent Explainable Alerts
When an incident is flagged, CloudShield doesn't just say *"Attack Detected"*. It explicitly lists the mathematical contributions that led to the score:
- `✓ 3 failed login attempts within 15 seconds (+30)`
- `✓ Unauthorized /admin access attempt (+25)`
- `✓ High request rate exceeding safety threshold (+20)`
- `✓ Unrecognized client IP behavior (+10)`
- `✓ Valid initial TLS handshake (-3)`
- **Total Risk Score: 82 / 100 → Threat Level: CRITICAL**
- **Recommended Action:** `Temporarily monitor or restrict the IP.`

### Novelty 3: Incident Timeline & Adaptive Risk Decay
1. **Incident Timeline:** Groups related security events into a coherent chronological sequence so an investigator can see how the attack progressed from initial failed login to admin probing to API flooding.
2. **Adaptive Risk Decay:** If an IP stops generating suspicious activity, its risk score gradually decreases over time (e.g., $82 \rightarrow 72 \rightarrow 62 \rightarrow 52 \rightarrow 25 \rightarrow 0$). This automatically forgives legitimate users who simply made typos.

---

## 5. Code Logic: How the Risk Engine Works

The core detection and scoring logic is located in [`js/riskEngine.js`](file:///c:/Work/Cloud-Shield/js/riskEngine.js). It is intentionally concise and readable so you can open it and explain it to professors line-by-line:

```javascript
// Rule Weights
const WEIGHTS = {
    FAILED_LOGIN: 10,        // Each bad password attempt
    UNAUTHORIZED_ACCESS: 25, // Probing /admin or /.env
    HIGH_REQUEST_RATE: 20,   // Flooding endpoints
    SUSPICIOUS_IP: 10,       // New IP / script user agent
    NORMAL_ACTIVITY: -5      // Successful auth / routine navigation
};

// Core Risk Calculation Function
function calculateRisk(events) {
    let score = 0;

    for (const event of events) {
        if (event.type === "FAILED_LOGIN") score += 10;
        if (event.type === "UNAUTHORIZED_ACCESS") score += 25;
        if (event.type === "HIGH_REQUEST_RATE") score += 20;
        if (event.type === "SUSPICIOUS_IP") score += 10;
        if (event.type === "NORMAL_ACTIVITY") score -= 5;
    }

    // Bounded mathematically between 0 and 100
    return Math.max(0, Math.min(100, score));
}

// Adaptive Risk Decay (Inactivity Recovery)
function decayRisk(currentScore, decayStep = 10) {
    return Math.max(0, currentScore - decayStep);
}
```

---

## 6. Live Viva Demonstration Script (Step-by-Step)

Follow these exact steps during your demonstration:

| Step | Action | What to Say / Point Out to the Professor |
|---|---|---|
| **Step 1** | Open **Dashboard** | *"Good morning/afternoon professors. This is CloudShield, our adaptive threat detection system. Here on the Dashboard, you see the system monitoring cloud application telemetry in real time. We have 1,248 total events, with the vast majority (1,095) categorized as Normal, and a small, dangerous subset of 32 Critical events shown in the Risk Distribution chart."* |
| **Step 2** | Click **Security Events** | *"Under Security Events, we see the raw stream of events. Notice how an attacker at IP `192.168.1.24` generates multiple failed login attempts on `/login`. We can click our simple severity filters ('Suspicious', 'Critical') to immediately isolate high-risk records."* |
| **Step 3** | Point out Escalating Event | *"Notice that the attacker doesn't just stop at failed logins. At 10:31:22, they attempt an unauthorized `/admin` route probe, and at 10:31:35, they flood the `/api` endpoint with a rapid burst."* |
| **Step 4** | Open **Risk Analysis** | *"This brings us to the core novelty of our project: Adaptive Risk Analysis. For IP `192.168.1.24`, instead of treating these actions as isolated alerts, CloudShield combines them into a single score of 82/100 (Critical). On the right, the professor can see our exact, transparent formula breakdown (+30 for 3 failed logins, +25 for admin access, +20 for high request rate, +10 for new IP, minus 3 for normal activity)."*<br><br>*Click the 'Simulate Next Threat Step' button to show the score climbing: 20 → 40 → 65 → 82.* |
| **Step 5** | Open **Incidents** | *"On the Incidents page, all correlated events are summarized as structured incident records. Notice Incident `CS-001` flagged for `192.168.1.24` with Risk Score 82 and Critical Severity."* |
| **Step 6** | Click Incident `CS-001` | *"When we open this incident, CloudShield displays an Explainable Alert. It provides the exact reasons why it was flagged with checkmarks, recommends restricting the IP, and below that, displays our Incident Timeline showing the complete story of the attack from 10:31:02 to 10:31:36."* |
| **Step 7** | Demonstrate **Risk Decay** | *Go back to Risk Analysis and click 'Simulate Inactivity (Decay -10)'.*<br>*"Finally, CloudShield features Adaptive Risk Decay. When suspicious activity stops, the score gradually cools down: 82 → 72 → 62 → 52 → 42 → 25. This prevents permanent false-positive penalties for legitimate users."* |

---

## 7. Viva Questions & Impressive Answers

### Q1: Why did you use a rule-based weighted risk score instead of a Machine Learning model like LSTM or Random Forest?
> **Answer:**  
> *"In production cybersecurity, transparency and explainability are paramount. Complex ML models act as 'black boxes'—they output an anomaly probability but cannot easily explain to a security engineer why a particular user was blocked. Furthermore, training ML models requires large labeled attack datasets that suffer from concept drift. Our rule-based adaptive scoring provides instantaneous, deterministic, and 100% explainable scoring that can be audited during compliance checks."*

### Q2: What prevents legitimate users who forget their passwords from being permanently blocked?
> **Answer:**  
> *"Two key mechanisms: First, a single failed login only adds +10 points, which keeps the score at 10 (well within the 'Normal' 0–25 range). Second, our system implements **Adaptive Risk Decay**. If no further suspicious activity occurs, the score decays back down to zero. Legitimate users are never penalized permanently."*

### Q3: Why is the risk score strictly bounded between 0 and 100?
> **Answer:**  
> *"Bounding the score between 0 and 100 provides a standardized, universally understood scale for security analysts and automated response systems. Regardless of how many events are processed, the score maps cleanly to four discrete severity tiers: Normal (0–25), Suspicious (26–50), High Risk (51–75), and Critical (76–100)."*

### Q4: How does CloudShield scale to cloud environments?
> **Answer:**  
> *"In a full cloud deployment, web application middleware (like AWS API Gateway, NGINX, or a Flask WSGI filter) sends JSON telemetry logs into a lightweight stream (such as AWS Kinesis or Redis Streams). The CloudShield risk engine processes the stream, maintains an in-memory risk tally per entity IP, and communicates with cloud firewalls (like AWS WAF or Security Groups) when the Critical threshold of 76 is crossed."*

### Q5: What is the significance of the "Incident Timeline"?
> **Answer:**  
> *"In traditional Security Information and Event Management (SIEM) tools, an investigator has to manually query logs and piece together timestamps. CloudShield automatically correlates all events by source IP and renders a chronological Incident Timeline, reducing mean time to detect (MTTD) and mean time to respond (MTTR)."*

---

## 8. How to Run the Project

The project is completely self-contained and can be launched in any of the following simple ways:

### Method 1: Using the 1-Click Python Server (Recommended)
Open your terminal in the project directory and run:
```bash
python run.py
```
This automatically starts a local server on port 8000 and opens `http://127.0.0.1:8000/` in your default browser.

### Method 2: Direct Browser Launch (100% Offline, Zero Server)
Simply double-click [`index.html`](file:///c:/Work/Cloud-Shield/index.html) in Windows File Explorer. All styling, SVG charts, and interactive JavaScript run directly in Google Chrome, Microsoft Edge, Mozilla Firefox, or Apple Safari without needing any internet connection or backend.

### Method 3: Using Standard Python HTTP Server
```bash
python -m http.server 8000
```
Then visit `http://127.0.0.1:8000/`.

---

## 9. File Structure Summary

- [`index.html`](file:///c:/Work/Cloud-Shield/index.html): The complete 4-page responsive Single-Page Application (Dashboard, Events, Risk Analysis, Incidents, and Modal).
- [`css/style.css`](file:///c:/Work/Cloud-Shield/css/style.css): Professional dark cybersecurity theme with responsive grids, status badges, and timeline styling.
- [`js/riskEngine.js`](file:///c:/Work/Cloud-Shield/js/riskEngine.js): The core mathematical risk scoring logic, threshold mapping, decay engine, and explainability generator.
- [`js/securityData.js`](file:///c:/Work/Cloud-Shield/js/securityData.js): Sample telemetry events, aggregated metrics, IP profiles, and incident histories.
- [`js/app.js`](file:///c:/Work/Cloud-Shield/js/app.js): UI orchestration, table filtering, live escalation simulator, and modal dialog handlers.
- [`run.py`](file:///c:/Work/Cloud-Shield/run.py): 1-click Python launcher script with automatic browser opening.
- [`PROJECT_PRESENTATION.md`](file:///c:/Work/Cloud-Shield/PROJECT_PRESENTATION.md): This comprehensive presentation and viva defense document.

