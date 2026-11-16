/**
 * CloudShield - Main Application Logic
 * 
 * Coordinates:
 * 1. Single Page View Routing (Dashboard, Security Events, Risk Analysis, Incidents)
 * 2. Event Filtering
 * 3. Dynamic Risk Scoring & Breakdown
 * 4. Interactive Viva Attack Escalation (20 -> 40 -> 65 -> 82)
 * 5. Adaptive Risk Decay Simulation (82 -> 72 -> 62 -> 52 -> 42 -> 25)
 * 6. Explainable Incident Modal & Timeline
 */

const app = {
    currentView: "dashboard",
    selectedIp: "192.168.1.24",
    currentScore: 82,
    currentEscalationIndex: 3, // Starts at fully escalated (82)
    decayStepIndex: 0,

    init: function () {
        this.setupNavigation();
        this.renderDashboard();
        this.renderEvents("all");
        this.setupEventFilters();
        this.setupRiskAnalysis();
        this.renderIncidents();
        this.setupModal();
        this.setupMobileMenu();
    },

    // -------------------------------------------------------------------------
    // 1. Navigation & Routing
    // -------------------------------------------------------------------------
    setupNavigation: function () {
        const navItems = document.querySelectorAll(".nav-item");
        navItems.forEach(item => {
            item.addEventListener("click", (e) => {
                e.preventDefault();
                const targetView = item.getAttribute("data-view");
                this.showView(targetView);
            });
        });
    },

    showView: function (viewName) {
        this.currentView = viewName;

        // Update nav item active classes
        document.querySelectorAll(".nav-item").forEach(item => {
            if (item.getAttribute("data-view") === viewName) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Update page sections
        document.querySelectorAll(".page-view").forEach(section => {
            section.classList.remove("active");
        });

        const targetSection = document.getElementById(`view-${viewName}`);
        if (targetSection) {
            targetSection.classList.add("active");
        }

        // Close mobile sidebar if open
        const sidebar = document.getElementById("sidebar");
        if (sidebar) sidebar.classList.remove("open");

        // Scroll main wrapper to top
        const mainWrapper = document.querySelector(".main-wrapper");
        if (mainWrapper) mainWrapper.scrollTop = 0;
    },

    setupMobileMenu: function () {
        const toggleBtn = document.getElementById("mobile-toggle");
        const sidebar = document.getElementById("sidebar");
        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener("click", () => {
                sidebar.classList.toggle("open");
            });
        }
    },

    // -------------------------------------------------------------------------
    // 2. Dashboard View
    // -------------------------------------------------------------------------
    renderDashboard: function () {
        // Summary metrics
        document.getElementById("stat-total-events").textContent = SecurityData.summary.totalEvents.toLocaleString();
        document.getElementById("stat-normal-events").textContent = SecurityData.summary.normal.toLocaleString();
        document.getElementById("stat-suspicious-events").textContent = SecurityData.summary.suspicious.toLocaleString();
        document.getElementById("stat-critical-events").textContent = SecurityData.summary.critical.toLocaleString();

        // Recent Security Alerts (4-5 alerts)
        const alertsList = document.getElementById("dashboard-alerts-list");
        if (!alertsList) return;

        alertsList.innerHTML = "";
        SecurityData.recentAlerts.forEach(alert => {
            const row = document.createElement("div");
            row.className = "alert-row";
            
            const badgeClass = alert.status === "Critical" ? "badge-critical" :
                               alert.status === "High" ? "badge-high" :
                               alert.status === "Suspicious" ? "badge-suspicious" : "badge-normal";

            row.innerHTML = `
                <div class="alert-main-info">
                    <div class="alert-ip-threat">
                        <span class="alert-ip">${alert.ip}</span>
                        <span class="alert-threat">• ${alert.threat}</span>
                    </div>
                    <div class="alert-meta">Endpoint: ${alert.endpoint} • Time: ${alert.time}</div>
                </div>
                <div class="alert-badges">
                    <span class="risk-score-pill">Risk: ${alert.risk}</span>
                    <span class="badge ${badgeClass}">${alert.status}</span>
                </div>
            `;

            row.addEventListener("click", () => {
                if (alert.ip === "192.168.1.24") {
                    this.openIncidentModal("CS-001");
                } else if (alert.ip === "192.168.1.91") {
                    this.openIncidentModal("CS-002");
                } else if (alert.ip === "192.168.1.13") {
                    this.openIncidentModal("CS-003");
                } else {
                    // Navigate to Risk Analysis for that IP
                    this.selectIp(alert.ip);
                    this.showView("risk");
                }
            });

            alertsList.appendChild(row);
        });
    },

    // -------------------------------------------------------------------------
    // 3. Security Events Table & Simple Filtering
    // -------------------------------------------------------------------------
    setupEventFilters: function () {
        const filterBtns = document.querySelectorAll("#event-filters .filter-btn");
        filterBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                filterBtns.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                const filter = btn.getAttribute("data-filter");
                this.renderEvents(filter);
            });
        });
    },

    renderEvents: function (filter) {
        const tbody = document.getElementById("events-table-body");
        if (!tbody) return;

        tbody.innerHTML = "";
        const filteredEvents = SecurityData.events.filter(ev => {
            if (filter === "all") return true;
            return ev.status === filter;
        });

        if (filteredEvents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:30px; color:var(--text-muted);">No events found matching '${filter}'.</td></tr>`;
            return;
        }

        filteredEvents.forEach(ev => {
            const tr = document.createElement("tr");
            tr.className = "clickable";

            const badgeClass = ev.status === "Critical" ? "badge-critical" :
                               ev.status === "High Risk" ? "badge-high" :
                               ev.status === "Suspicious" ? "badge-suspicious" : "badge-normal";

            tr.innerHTML = `
                <td style="font-family:var(--font-mono); color:var(--text-muted);">${ev.time}</td>
                <td><span class="ip-tag">${ev.ip}</span></td>
                <td style="font-weight:600; color:#ffffff;">${ev.event}</td>
                <td><span class="endpoint-tag">${ev.endpoint}</span></td>
                <td><span class="badge ${badgeClass}">${ev.status}</span></td>
            `;

            tr.addEventListener("click", () => {
                this.selectIp(ev.ip);
                this.showView("risk");
            });

            tbody.appendChild(tr);
        });
    },

    // -------------------------------------------------------------------------
    // 4. Adaptive Risk Analysis View & Simulations
    // -------------------------------------------------------------------------
    setupRiskAnalysis: function () {
        const ipSelect = document.getElementById("risk-ip-select");
        if (ipSelect) {
            ipSelect.value = this.selectedIp;
            ipSelect.addEventListener("change", (e) => {
                this.selectIp(e.target.value);
            });
        }

        // Escalation demo button
        const btnEscalate = document.getElementById("btn-next-escalation");
        if (btnEscalate) {
            btnEscalate.addEventListener("click", () => {
                this.advanceEscalation();
            });
        }

        // Escalation reset button
        const btnResetEscalate = document.getElementById("btn-reset-escalation");
        if (btnResetEscalate) {
            btnResetEscalate.addEventListener("click", () => {
                this.resetEscalation();
            });
        }

        // Decay demo button
        const btnDecay = document.getElementById("btn-decay-risk");
        if (btnDecay) {
            btnDecay.addEventListener("click", () => {
                this.simulateRiskDecay();
            });
        }

        // Decay reset button
        const btnResetDecay = document.getElementById("btn-reset-decay");
        if (btnResetDecay) {
            btnResetDecay.addEventListener("click", () => {
                this.resetDecay();
            });
        }

        this.renderRiskProfile(this.selectedIp);
    },

    selectIp: function (ip) {
        if (!SecurityData.ipProfiles[ip]) {
            ip = "192.168.1.24"; // Default fallback
        }
        this.selectedIp = ip;
        const ipSelect = document.getElementById("risk-ip-select");
        if (ipSelect) ipSelect.value = ip;
        
        const profile = SecurityData.ipProfiles[ip];
        this.currentScore = profile.score;
        this.renderRiskProfile(ip);
    },

    renderRiskProfile: function (ip) {
        const profile = SecurityData.ipProfiles[ip] || SecurityData.ipProfiles["192.168.1.24"];
        
        document.getElementById("risk-display-ip").textContent = `IP Address: ${profile.ip}`;
        this.updateScoreDisplay(profile.score);

        // Factors breakdown list
        const factorsList = document.getElementById("risk-factors-list");
        if (factorsList) {
            factorsList.innerHTML = "";
            profile.factors.forEach(factor => {
                const isNegative = factor.points.startsWith("-");
                const item = document.createElement("div");
                item.className = "factor-item";
                item.innerHTML = `
                    <div class="factor-info">
                        <span class="factor-name">${factor.name}</span>
                        <span class="factor-detail">${factor.detail}</span>
                    </div>
                    <span class="factor-points ${isNegative ? 'negative' : 'positive'}">${factor.points}</span>
                `;
                factorsList.appendChild(item);
            });
        }

        document.getElementById("risk-factors-total").textContent = profile.total;
    },

    updateScoreDisplay: function (score) {
        this.currentScore = score;
        const severity = RiskEngine.getSeverity(score);

        const numberEl = document.getElementById("risk-display-number");
        const badgeEl = document.getElementById("risk-display-badge");
        const progressBar = document.getElementById("risk-progress-bar");

        if (numberEl) {
            numberEl.textContent = score;
            numberEl.style.color = severity.color;
        }

        if (badgeEl) {
            badgeEl.className = `badge ${severity.badgeClass}`;
            badgeEl.textContent = severity.level.toUpperCase();
        }

        if (progressBar) {
            progressBar.style.width = `${Math.min(100, Math.max(0, score))}%`;
            progressBar.style.backgroundColor = severity.color;
        }

        // Highlight matching risk scale marker
        ["normal", "suspicious", "high", "critical"].forEach(key => {
            const el = document.getElementById(`range-${key}`);
            if (el) el.classList.remove("active");
        });

        if (score <= 25) {
            document.getElementById("range-normal")?.classList.add("active");
        } else if (score <= 50) {
            document.getElementById("range-suspicious")?.classList.add("active");
        } else if (score <= 75) {
            document.getElementById("range-high")?.classList.add("active");
        } else {
            document.getElementById("range-critical")?.classList.add("active");
        }
    },

    // Escalation Demonstration: 20 -> 40 -> 65 -> 82
    advanceEscalation: function () {
        const profile = SecurityData.ipProfiles[this.selectedIp] || SecurityData.ipProfiles["192.168.1.24"];
        const steps = profile.escalationSteps || [
            { step: 1, label: "Initial Traffic", score: 20, reason: "New IP detected" },
            { step: 2, label: "Failed Logins", score: 40, reason: "Multiple bad password attempts" },
            { step: 3, label: "Privilege Probe", score: 65, reason: "Unauthorized /admin probe" },
            { step: 4, label: "Critical Burst", score: 82, reason: "Rapid request flood on /api" }
        ];

        this.currentEscalationIndex = (this.currentEscalationIndex + 1) % steps.length;
        const currentStep = steps[this.currentEscalationIndex];

        this.updateScoreDisplay(currentStep.score);

        const feedback = document.getElementById("escalation-feedback");
        if (feedback) {
            feedback.innerHTML = `<strong>Step ${currentStep.step}:</strong> ${currentStep.label} &rarr; Score: <strong>${currentStep.score}</strong> (${currentStep.reason})`;
        }
    },

    resetEscalation: function () {
        this.currentEscalationIndex = 0;
        const profile = SecurityData.ipProfiles[this.selectedIp] || SecurityData.ipProfiles["192.168.1.24"];
        const firstStep = profile.escalationSteps ? profile.escalationSteps[0] : { score: 20 };
        this.updateScoreDisplay(firstStep.score);

        const feedback = document.getElementById("escalation-feedback");
        if (feedback) {
            feedback.innerHTML = `Reset to Step 1 baseline. Score is now <strong>${firstStep.score}</strong>.`;
        }
    },

    // Risk Decay Simulation: 82 -> 72 -> 62 -> 52 -> 42 -> 25
    simulateRiskDecay: function () {
        const decaySteps = [82, 72, 62, 52, 42, 25];
        
        let nextScore = RiskEngine.decayRisk(this.currentScore, 10);
        if (this.currentScore <= 25) {
            nextScore = 0;
        }

        const prevScore = this.currentScore;
        this.updateScoreDisplay(nextScore);

        const feedback = document.getElementById("decay-feedback");
        if (feedback) {
            if (nextScore > 0) {
                feedback.innerHTML = `Inactivity detected: Risk decayed from <strong>${prevScore}</strong> &rarr; <strong>${nextScore}</strong>. Score safely cools off.`;
            } else {
                feedback.innerHTML = `Inactivity period sustained: Risk fully cooled down to <strong>0 (Normal)</strong>.`;
            }
        }
    },

    resetDecay: function () {
        const profile = SecurityData.ipProfiles[this.selectedIp] || SecurityData.ipProfiles["192.168.1.24"];
        this.updateScoreDisplay(profile.score);

        const feedback = document.getElementById("decay-feedback");
        if (feedback) {
            feedback.innerHTML = `Risk score restored to original observed total: <strong>${profile.score}</strong>.`;
        }
    },

    // -------------------------------------------------------------------------
    // 5. Incidents View & Details Modal
    // -------------------------------------------------------------------------
    renderIncidents: function () {
        const tbody = document.getElementById("incidents-table-body");
        if (!tbody) return;

        tbody.innerHTML = "";
        SecurityData.incidents.forEach(inc => {
            const tr = document.createElement("tr");
            tr.className = "clickable";

            const badgeClass = inc.severity === "Critical" ? "badge-critical" :
                               inc.severity === "High" ? "badge-high" : "badge-suspicious";

            tr.innerHTML = `
                <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-blue);">${inc.id}</td>
                <td><span class="ip-tag">${inc.ip}</span></td>
                <td style="font-weight:600; color:#ffffff;">${inc.threat}</td>
                <td style="font-family:var(--font-mono); font-weight:700; color:#ffffff;">${inc.riskScore}</td>
                <td><span class="badge ${badgeClass}">${inc.severity}</span></td>
                <td style="font-family:var(--font-mono); color:var(--text-muted);">${inc.time}</td>
                <td><span class="incident-status-pill ${inc.statusClass}">${inc.status}</span></td>
            `;

            tr.addEventListener("click", () => {
                this.openIncidentModal(inc.id);
            });

            tbody.appendChild(tr);
        });
    },

    setupModal: function () {
        const modal = document.getElementById("incident-modal");
        const closeBtn = document.getElementById("modal-close-btn");
        const dismissBtn = document.getElementById("modal-btn-dismiss");
        const actionBtn = document.getElementById("modal-btn-action");

        const closeModal = () => {
            if (modal) modal.classList.remove("active");
        };

        if (closeBtn) closeBtn.addEventListener("click", closeModal);
        if (dismissBtn) dismissBtn.addEventListener("click", closeModal);

        if (modal) {
            modal.addEventListener("click", (e) => {
                if (e.target === modal) closeModal();
            });
        }

        if (actionBtn) {
            actionBtn.addEventListener("click", () => {
                actionBtn.textContent = "IP Temporarily Restricted ✓";
                actionBtn.style.background = "#059669";
                const statusPill = document.getElementById("modal-incident-status");
                if (statusPill) {
                    statusPill.textContent = "Mitigated";
                    statusPill.className = "incident-status-pill status-resolved";
                }
                setTimeout(() => {
                    closeModal();
                    actionBtn.textContent = "Temporarily Restrict IP";
                    actionBtn.style.background = "#dc2626";
                }, 1200);
            });
        }
    },

    openIncidentModal: function (incidentId) {
        const incident = SecurityData.incidents.find(i => i.id === incidentId) || SecurityData.incidents[0];

        // Header info
        document.getElementById("modal-incident-id").textContent = incident.id;
        const badgeEl = document.getElementById("modal-incident-badge");
        const badgeClass = incident.severity === "Critical" ? "badge-critical" :
                           incident.severity === "High" ? "badge-high" : "badge-suspicious";
        badgeEl.className = `badge ${badgeClass}`;
        badgeEl.textContent = incident.severity;

        // Headline & status
        const headlineEl = document.getElementById("modal-alert-headline");
        headlineEl.textContent = `${incident.severity.toUpperCase()} SECURITY ALERT`;

        const statusPill = document.getElementById("modal-incident-status");
        statusPill.textContent = incident.status;
        statusPill.className = `incident-status-pill ${incident.statusClass}`;

        // IP and score
        document.getElementById("modal-ip-text").textContent = incident.ip;
        document.getElementById("modal-score-text").textContent = `${incident.riskScore} / 100`;
        document.getElementById("modal-threat-text").textContent = incident.threat;

        // Reasons checklist (Explainability)
        const reasonsList = document.getElementById("modal-reasons-list");
        reasonsList.innerHTML = "";
        incident.reasonsList.forEach(reason => {
            const li = document.createElement("li");
            li.textContent = reason;
            reasonsList.appendChild(li);
        });

        // Recommended Action
        document.getElementById("modal-recommended-action").textContent = incident.recommendedAction;

        // Timeline (Incident Timeline Novelty)
        const timelineContainer = document.getElementById("modal-timeline-container");
        timelineContainer.innerHTML = "";

        incident.timeline.forEach(item => {
            const itemEl = document.createElement("div");
            itemEl.className = "timeline-item";
            itemEl.innerHTML = `
                <div class="timeline-marker ${item.type}"></div>
                <div class="timeline-content">
                    <div class="timeline-time-title">
                        <span class="timeline-title">${item.title}</span>
                        <span class="timeline-timestamp">${item.time}</span>
                    </div>
                    <div class="timeline-detail">${item.detail}</div>
                </div>
            `;
            timelineContainer.appendChild(itemEl);
        });

        // Open modal
        const modal = document.getElementById("incident-modal");
        if (modal) modal.classList.add("active");
    }
};

// Initialize application on DOM ready
document.addEventListener("DOMContentLoaded", () => {
    app.init();
});

