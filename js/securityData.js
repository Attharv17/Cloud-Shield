/**
 * CloudShield - Security Data Source
 * 
 * Contains sample security logs, aggregate metrics, and incident records
 * designed for simple demonstration and easy explanation during a college viva.
 */

const SecurityData = {
    // 1. Dashboard Aggregate Metrics
    summary: {
        totalEvents: 1248,
        normal: 1095,
        suspicious: 121,
        critical: 32
    },

    // 2. Risk Distribution for Charts
    riskDistribution: [
        { label: "Normal", count: 1095, color: "#10b981", percent: 87.7 },
        { label: "Suspicious", count: 121, color: "#f59e0b", percent: 9.7 },
        { label: "High Risk", count: 23, color: "#f97316", percent: 1.8 },
        { label: "Critical", count: 9, color: "#ef4444", percent: 0.8 }
    ],

    // 3. Recent Security Alerts (Dashboard)
    recentAlerts: [
        {
            ip: "192.168.1.24",
            threat: "Brute Force",
            risk: 82,
            status: "Critical",
            time: "10:31:36",
            endpoint: "/admin"
        },
        {
            ip: "192.168.1.91",
            threat: "Unusual Request Rate",
            risk: 64,
            status: "High",
            time: "11:02:15",
            endpoint: "/api/v1/query"
        },
        {
            ip: "192.168.1.105",
            threat: "Directory Traversal Probe",
            risk: 71,
            status: "High",
            time: "11:15:40",
            endpoint: "/etc/passwd"
        },
        {
            ip: "192.168.1.13",
            threat: "Failed Login Attempts",
            risk: 38,
            status: "Suspicious",
            time: "11:25:04",
            endpoint: "/login"
        },
        {
            ip: "192.168.1.5",
            threat: "Normal User Session",
            risk: 12,
            status: "Normal",
            time: "11:30:19",
            endpoint: "/dashboard"
        }
    ],

    // 4. Detailed Security Events Log
    events: [
        {
            time: "10:31:02",
            ip: "192.168.1.24",
            event: "Failed Login",
            type: "FAILED_LOGIN",
            endpoint: "/login",
            status: "Suspicious",
            riskDelta: 10
        },
        {
            time: "10:31:08",
            ip: "192.168.1.24",
            event: "Failed Login",
            type: "FAILED_LOGIN",
            endpoint: "/login",
            status: "Suspicious",
            riskDelta: 10
        },
        {
            time: "10:31:15",
            ip: "192.168.1.24",
            event: "Failed Login",
            type: "FAILED_LOGIN",
            endpoint: "/login",
            status: "Suspicious",
            riskDelta: 10
        },
        {
            time: "10:31:22",
            ip: "192.168.1.24",
            event: "Unauthorized Access",
            type: "UNAUTHORIZED_ACCESS",
            endpoint: "/admin",
            status: "High Risk",
            riskDelta: 25
        },
        {
            time: "10:31:35",
            ip: "192.168.1.24",
            event: "High Request Rate",
            type: "HIGH_REQUEST_RATE",
            endpoint: "/api",
            status: "Critical",
            riskDelta: 20
        },
        {
            time: "10:35:11",
            ip: "192.168.1.13",
            event: "Successful Login",
            type: "NORMAL_ACTIVITY",
            endpoint: "/login",
            status: "Normal",
            riskDelta: -5
        },
        {
            time: "10:42:19",
            ip: "192.168.1.91",
            event: "High Request Rate",
            type: "HIGH_REQUEST_RATE",
            endpoint: "/api/search",
            status: "High Risk",
            riskDelta: 20
        },
        {
            time: "10:43:05",
            ip: "192.168.1.91",
            event: "High Request Rate",
            type: "HIGH_REQUEST_RATE",
            endpoint: "/api/export",
            status: "High Risk",
            riskDelta: 20
        },
        {
            time: "10:44:12",
            ip: "192.168.1.91",
            event: "Rate Limit Exceeded",
            type: "UNAUTHORIZED_ACCESS",
            endpoint: "/api/export",
            status: "High Risk",
            riskDelta: 25
        },
        {
            time: "10:50:30",
            ip: "192.168.1.105",
            event: "Unauthorized Access",
            type: "UNAUTHORIZED_ACCESS",
            endpoint: "/etc/passwd",
            status: "High Risk",
            riskDelta: 25
        },
        {
            time: "10:51:14",
            ip: "192.168.1.105",
            event: "Unauthorized Access",
            type: "UNAUTHORIZED_ACCESS",
            endpoint: "/.env",
            status: "Critical",
            riskDelta: 25
        },
        {
            time: "10:55:01",
            ip: "192.168.1.13",
            event: "Failed Login",
            type: "FAILED_LOGIN",
            endpoint: "/login",
            status: "Suspicious",
            riskDelta: 10
        },
        {
            time: "10:55:22",
            ip: "192.168.1.13",
            event: "Failed Login",
            type: "FAILED_LOGIN",
            endpoint: "/login",
            status: "Suspicious",
            riskDelta: 10
        },
        {
            time: "11:00:10",
            ip: "192.168.1.5",
            event: "Successful Login",
            type: "NORMAL_ACTIVITY",
            endpoint: "/login",
            status: "Normal",
            riskDelta: -5
        },
        {
            time: "11:01:45",
            ip: "192.168.1.5",
            event: "Page Navigation",
            type: "NORMAL_ACTIVITY",
            endpoint: "/dashboard",
            status: "Normal",
            riskDelta: -5
        },
        {
            time: "11:03:12",
            ip: "192.168.1.5",
            event: "Data Query",
            type: "NORMAL_ACTIVITY",
            endpoint: "/api/metrics",
            status: "Normal",
            riskDelta: -5
        }
    ],

    // 5. Tracked IP Profiles for Adaptive Risk Analysis
    ipProfiles: {
        "192.168.1.24": {
            ip: "192.168.1.24",
            score: 82,
            threatLevel: "CRITICAL",
            badgeClass: "badge-critical",
            factors: [
                { name: "Failed Login Attempts", points: "+30", detail: "3 repeated failed attempts on /login" },
                { name: "Unauthorized Admin Access", points: "+25", detail: "Attempted access to privileged /admin endpoint" },
                { name: "High Request Rate", points: "+20", detail: "Burst exceeding 15 req/sec on /api" },
                { name: "New IP Address", points: "+10", detail: "Unrecognized client address without session history" },
                { name: "Normal Activity", points: "-3", detail: "Initial valid TLS handshake" }
            ],
            total: 82,
            escalationSteps: [
                { step: 1, label: "Initial Traffic", score: 20, reason: "New IP + initial failed request" },
                { step: 2, label: "Repeated Logins", score: 40, reason: "3 consecutive failed authentication events" },
                { step: 3, label: "Privilege Probe", score: 65, reason: "Attempted unauthorized /admin endpoint" },
                { step: 4, label: "API Burst Flooding", score: 82, reason: "Rapid API request burst triggers Critical Alert" }
            ],
            decaySteps: [82, 72, 62, 52, 42, 25],
            recommendedAction: "Temporarily monitor or restrict the IP address."
        },
        "192.168.1.91": {
            ip: "192.168.1.91",
            score: 64,
            threatLevel: "HIGH RISK",
            badgeClass: "badge-high",
            factors: [
                { name: "High Request Rate", points: "+40", detail: "Two consecutive burst thresholds reached on /api/export" },
                { name: "Rate Limit Exceeded", points: "+25", detail: "Repeated 429 Too Many Requests response code" },
                { name: "Known Client Subnet", points: "-1", detail: "Matches familiar enterprise subnet range" }
            ],
            total: 64,
            escalationSteps: [
                { step: 1, label: "Baseline Traffic", score: 10, reason: "Routine search query" },
                { step: 2, label: "Burst Detected", score: 35, reason: "Rapid calls to /api/search" },
                { step: 3, label: "Export Abuse", score: 64, reason: "Heavy export queries exceeding safety limit" }
            ],
            decaySteps: [64, 54, 44, 34, 24, 10],
            recommendedAction: "Apply rate limiting policy (HTTP 429) to client IP."
        },
        "192.168.1.13": {
            ip: "192.168.1.13",
            score: 38,
            threatLevel: "SUSPICIOUS",
            badgeClass: "badge-suspicious",
            factors: [
                { name: "Failed Login Attempts", points: "+20", detail: "2 unsuccessful login attempts" },
                { name: "Unfamiliar User Agent", points: "+15", detail: "Python script user agent string" },
                { name: "Subsequent Valid Login", points: "+3", detail: "Resolved with legitimate credentials" }
            ],
            total: 38,
            escalationSteps: [
                { step: 1, label: "First Failure", score: 15, reason: "Single mistyped password" },
                { step: 2, label: "Second Failure", score: 38, reason: "Second consecutive login failure" }
            ],
            decaySteps: [38, 28, 18, 8, 0],
            recommendedAction: "Log warning; issue CAPTCHA challenge on next login."
        },
        "192.168.1.5": {
            ip: "192.168.1.5",
            score: 12,
            threatLevel: "NORMAL",
            badgeClass: "badge-normal",
            factors: [
                { name: "Valid Authenticated Session", points: "-5", detail: "Standard session cookie present" },
                { name: "Standard Browser Headers", points: "-5", detail: "Chrome 122 on Windows 11" },
                { name: "Steady Request Pacing", points: "+22", detail: "General page hits" }
            ],
            total: 12,
            escalationSteps: [
                { step: 1, label: "Logged In", score: 5, reason: "Successful MFA login" },
                { step: 2, label: "Browsing", score: 12, reason: "Routine navigation" }
            ],
            decaySteps: [12, 5, 0],
            recommendedAction: "No action needed. Standard user behavior."
        }
    },

    // 6. Security Incidents List
    incidents: [
        {
            id: "CS-001",
            ip: "192.168.1.24",
            threat: "Brute Force",
            riskScore: 82,
            severity: "Critical",
            time: "10:31",
            status: "Active",
            statusClass: "status-active",
            reason: "Multiple failed authentication attempts followed by unauthorized administrative probing and rapid API burst.",
            reasonsList: [
                "3 failed login attempts within 15 seconds",
                "Unauthorized /admin access attempt",
                "High request rate exceeding threshold (>15 req/s)",
                "Suspicious IP behaviour with unfamiliar user-agent"
            ],
            recommendedAction: "Temporarily monitor or restrict the IP.",
            timeline: [
                { time: "10:31:02", title: "Failed Login", detail: "POST /login (Invalid credentials)", type: "warning" },
                { time: "10:31:08", title: "Failed Login", detail: "POST /login (Invalid credentials, retry 2)", type: "warning" },
                { time: "10:31:15", title: "Failed Login", detail: "POST /login (Invalid credentials, retry 3)", type: "warning" },
                { time: "10:31:22", title: "Unauthorized Admin Access", detail: "GET /admin (HTTP 403 Forbidden)", type: "danger" },
                { time: "10:31:35", title: "High Request Rate", detail: "GET /api (18 req/sec burst)", type: "danger" },
                { time: "10:31:36", title: "Critical Risk Detected", detail: "Composite Risk Score escalated to 82/100", type: "critical" }
            ]
        },
        {
            id: "CS-002",
            ip: "192.168.1.91",
            threat: "Rapid Requests",
            riskScore: 64,
            severity: "High",
            time: "11:02",
            status: "Investigating",
            statusClass: "status-investigating",
            reason: "Automated scraper pattern detected flooding data export endpoints.",
            reasonsList: [
                "Request rate exceeded 30 req/min limit",
                "Repeated 429 Too Many Requests responses",
                "Targeted sensitive data export endpoint /api/export"
            ],
            recommendedAction: "Enforce dynamic rate-limiting and require CAPTCHA challenge.",
            timeline: [
                { time: "10:42:19", title: "Search Burst", detail: "GET /api/search (12 requests in 2s)", type: "warning" },
                { time: "10:43:05", title: "Export Burst", detail: "GET /api/export (Multiple concurrent requests)", type: "warning" },
                { time: "10:44:12", title: "Rate Limit Triggered", detail: "HTTP 429 status code returned", type: "danger" },
                { time: "11:02:15", title: "High Risk Threshold Reached", detail: "Composite score: 64/100", type: "critical" }
            ]
        },
        {
            id: "CS-003",
            ip: "192.168.1.13",
            threat: "Failed Logins",
            riskScore: 38,
            severity: "Suspicious",
            time: "11:25",
            status: "Resolved",
            statusClass: "status-resolved",
            reason: "Two failed login attempts followed by successful password authentication.",
            reasonsList: [
                "2 sequential incorrect password attempts",
                "Password successfully authenticated on attempt #3"
            ],
            recommendedAction: "Resolved automatically upon successful MFA login.",
            timeline: [
                { time: "10:55:01", title: "Failed Login", detail: "POST /login (Bad password)", type: "warning" },
                { time: "10:55:22", title: "Failed Login", detail: "POST /login (Bad password)", type: "warning" },
                { time: "11:00:10", title: "Successful Login", detail: "POST /login (Valid credentials)", type: "success" },
                { time: "11:25:00", title: "Incident Marked Resolved", detail: "Legitimate user confirmed", type: "info" }
            ]
        },
        {
            id: "CS-004",
            ip: "192.168.1.105",
            threat: "Sensitive Endpoint Probing",
            riskScore: 71,
            severity: "High",
            time: "11:40",
            status: "Active",
            statusClass: "status-active",
            reason: "Directory traversal and configuration file probing detected.",
            reasonsList: [
                "Probed system file path /etc/passwd",
                "Attempted access to environment secrets /.env",
                "No previous session history"
            ],
            recommendedAction: "Drop all TCP connections and add IP to firewall watchlist.",
            timeline: [
                { time: "10:50:30", title: "Directory Traversal Attempt", detail: "GET /etc/passwd (HTTP 404)", type: "danger" },
                { time: "10:51:14", title: "Secret Probing", detail: "GET /.env (HTTP 403)", type: "danger" },
                { time: "11:40:00", title: "High Risk Alert Issued", detail: "Composite score: 71/100", type: "critical" }
            ]
        }
    ]
};

// Export for browser window and Node.js testing environments
if (typeof window !== "undefined") {
    window.SecurityData = SecurityData;
}
if (typeof module !== "undefined" && module.exports) {
    module.exports = SecurityData;
}
