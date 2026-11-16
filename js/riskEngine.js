/**
 * CloudShield - Adaptive Risk Scoring Engine
 * 
 * CORE CONCEPT FOR VIVA PRESENTATION:
 * Instead of simple binary blocking ("all-or-nothing"), CloudShield dynamically
 * scores suspicious behavior from 0 to 100 using transparent weights.
 * 
 * Rule Weights:
 * - Failed Login:         +10 points
 * - Unauthorized Access:  +25 points
 * - High Request Rate:    +20 points
 * - Suspicious IP:        +10 points
 * - Normal Activity:      -5 points
 * 
 * Severity Thresholds:
 * - 0 to 25   : Normal (Green)
 * - 26 to 50  : Suspicious (Yellow)
 * - 51 to 75  : High Risk (Orange)
 * - 76 to 100 : Critical (Red)
 */

const RiskEngine = {
    // Weight constants for each security event type
    WEIGHTS: {
        FAILED_LOGIN: 10,
        UNAUTHORIZED_ACCESS: 25,
        HIGH_REQUEST_RATE: 20,
        SUSPICIOUS_IP: 10,
        NORMAL_ACTIVITY: -5
    },

    // Severity threshold boundaries
    THRESHOLDS: {
        NORMAL_MAX: 25,
        SUSPICIOUS_MAX: 50,
        HIGH_MAX: 75,
        CRITICAL_MAX: 100
    },

    /**
     * Calculates the composite risk score for an array of observed security events.
     * Guaranteed to return a bounded integer between 0 and 100.
     * 
     * @param {Array} events - List of event objects with `type` property
     * @returns {number} Score bounded between 0 and 100
     */
    calculateRisk: function (events) {
        if (!Array.isArray(events) || events.length === 0) {
            return 0;
        }

        let score = 0;

        for (const event of events) {
            if (event.type === "FAILED_LOGIN") score += 10;
            else if (event.type === "UNAUTHORIZED_ACCESS") score += 25;
            else if (event.type === "HIGH_REQUEST_RATE") score += 20;
            else if (event.type === "SUSPICIOUS_IP") score += 10;
            else if (event.type === "NORMAL_ACTIVITY") score -= 5;
            else if (event.riskDelta) score += event.riskDelta;
        }

        // Bounded mathematically between 0 and 100
        return Math.max(0, Math.min(100, score));
    },

    /**
     * Determines threat level and badge attributes from a 0-100 risk score.
     * 
     * @param {number} score - The current risk score
     * @returns {Object} { level, badgeClass, color, description }
     */
    getSeverity: function (score) {
        if (score <= 25) {
            return {
                level: "Normal",
                badgeClass: "badge-normal",
                color: "#10b981",
                description: "Standard legitimate cloud traffic"
            };
        } else if (score <= 50) {
            return {
                level: "Suspicious",
                badgeClass: "badge-suspicious",
                color: "#f59e0b",
                description: "Low-severity anomalies detected"
            };
        } else if (score <= 75) {
            return {
                level: "High Risk",
                badgeClass: "badge-high",
                color: "#f97316",
                description: "Elevated malicious threat patterns"
            };
        } else {
            return {
                level: "Critical",
                badgeClass: "badge-critical",
                color: "#ef4444",
                description: "Immediate threat requiring restriction"
            };
        }
    },

    /**
     * Simulates adaptive risk decay when no suspicious activity occurs.
     * Decreases risk score gradually by the decay amount (default: 10 points)
     * until it returns to zero or baseline.
     * 
     * @param {number} currentScore - The starting risk score
     * @param {number} decayAmount - Points to deduct per inactivity period (default: 10)
     * @returns {number} Decayed score, minimum 0
     */
    decayRisk: function (currentScore, decayAmount = 10) {
        return Math.max(0, currentScore - decayAmount);
    },

    /**
     * Generates an explainability summary for a given score and events list.
     * 
     * @param {Array} events - Security events list
     * @returns {Array<string>} Human-understandable bullet points
     */
    generateExplanation: function (events) {
        const counts = {
            failedLogins: 0,
            unauthorized: 0,
            highRate: 0,
            suspiciousIp: 0
        };

        for (const ev of events) {
            if (ev.type === "FAILED_LOGIN") counts.failedLogins++;
            if (ev.type === "UNAUTHORIZED_ACCESS") counts.unauthorized++;
            if (ev.type === "HIGH_REQUEST_RATE") counts.highRate++;
            if (ev.type === "SUSPICIOUS_IP") counts.suspiciousIp++;
        }

        const explanations = [];
        if (counts.failedLogins > 0) {
            explanations.push(`${counts.failedLogins} failed login attempt${counts.failedLogins > 1 ? 's' : ''}`);
        }
        if (counts.unauthorized > 0) {
            explanations.push(`Unauthorized /admin access attempt`);
        }
        if (counts.highRate > 0) {
            explanations.push(`High request rate exceeding safety threshold`);
        }
        if (counts.suspiciousIp > 0) {
            explanations.push(`Unrecognized client IP behavior`);
        }

        if (explanations.length === 0) {
            explanations.push("Normal application activity observed");
        }

        return explanations;
    }
};

// Export for browser window and Node.js testing environments
if (typeof window !== "undefined") {
    window.RiskEngine = RiskEngine;
}
if (typeof module !== "undefined" && module.exports) {
    module.exports = RiskEngine;
}
