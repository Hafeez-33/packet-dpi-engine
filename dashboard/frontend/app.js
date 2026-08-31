/**
 * PACKET DPI ENGINE — STAGE 7 DASHBOARD CLIENT APPLICATION
 */

(function () {
    'use strict';

    // State management
    const state = {
        isPolling: true,
        pollIntervalMs: 1000,
        pollTimer: null,
        currentPage: 1,
        pageSize: 15,
        filters: {
            transport: 'ALL',
            app: 'ALL',
            verdict: 'ALL',
            risk: 'ALL',
            search: ''
        },
        alertFilters: {
            severity: 'ALL',
            category: 'ALL',
            search: ''
        },
        throughputHistory: [], // Array of { pps: number, mbps: number }
        maxHistoryPoints: 40,
        lastSnapshot: null
    };

    // DOM Elements
    const elements = {
        statusBadge: document.getElementById('engine-status-badge'),
        statusText: document.getElementById('engine-status-text'),
        btnTogglePoll: document.getElementById('btn-toggle-poll'),
        pollIconPause: document.getElementById('poll-icon-pause'),
        pollIconPlay: document.getElementById('poll-icon-play'),
        pollBtnLabel: document.getElementById('poll-btn-label'),
        btnRefreshNow: document.getElementById('btn-refresh-now'),

        // KPIs
        kpiTotalPackets: document.getElementById('kpi-total-packets'),
        kpiPps: document.getElementById('kpi-pps'),
        kpiThroughput: document.getElementById('kpi-throughput'),
        kpiMbps: document.getElementById('kpi-mbps'),
        kpiTotalFlows: document.getElementById('kpi-total-flows'),
        kpiActiveFlows: document.getElementById('kpi-active-flows'),
        kpiDpiClassified: document.getElementById('kpi-dpi-classified'),
        kpiDpiRate: document.getElementById('kpi-dpi-rate'),
        kpiBlockedFlows: document.getElementById('kpi-blocked-flows'),
        kpiBlockedPackets: document.getElementById('kpi-blocked-packets'),
        kpiThreatAlerts: document.getElementById('kpi-threat-alerts'),
        kpiThreatDropped: document.getElementById('kpi-threat-dropped'),
        kpiRiskHigh: document.getElementById('kpi-risk-high'),
        kpiRiskSub: document.getElementById('kpi-risk-sub'),

        // Stage 9 Risk Elements
        badgeRiskCrit: document.getElementById('badge-risk-crit'),
        badgeRiskHigh: document.getElementById('badge-risk-high'),
        badgeRiskMed: document.getElementById('badge-risk-med'),
        badgeRiskLow: document.getElementById('badge-risk-low'),
        hostsTbody: document.getElementById('hosts-tbody'),

        // Alerts Table & Filters
        filterAlertSearch: document.getElementById('filter-alert-search'),
        filterAlertSeverity: document.getElementById('filter-alert-severity'),
        filterAlertCategory: document.getElementById('filter-alert-category'),
        alertsTbody: document.getElementById('alerts-tbody'),

        // Chart & Protocols
        sparklineSvg: document.getElementById('sparkline-svg'),
        barProtoTcp: document.getElementById('bar-proto-tcp'),
        barProtoUdp: document.getElementById('bar-proto-udp'),
        barProtoOther: document.getElementById('bar-proto-other'),
        valProtoTcp: document.getElementById('val-proto-tcp'),
        valProtoUdp: document.getElementById('val-proto-udp'),
        valProtoOther: document.getElementById('val-proto-other'),

        valL7Tls: document.getElementById('val-l7-tls'),
        valL7Http: document.getElementById('val-l7-http'),
        valL7Dns: document.getElementById('val-l7-dns'),
        valL7Unknown: document.getElementById('val-l7-unknown'),
        miniBarTls: document.getElementById('mini-bar-tls'),
        miniBarHttp: document.getElementById('mini-bar-http'),
        miniBarDns: document.getElementById('mini-bar-dns'),
        miniBarUnknown: document.getElementById('mini-bar-unknown'),

        // Workers
        workerCountBadge: document.getElementById('worker-count-badge'),
        workerGrid: document.getElementById('worker-grid'),

        // Flows Table & Filters
        filterSearch: document.getElementById('filter-search'),
        filterTransport: document.getElementById('filter-transport'),
        filterApp: document.getElementById('filter-app'),
        filterVerdict: document.getElementById('filter-verdict'),
        filterRisk: document.getElementById('filter-risk'),
        flowsTbody: document.getElementById('flows-tbody'),
        paginationInfo: document.getElementById('pagination-info'),
        paginationCurrentPage: document.getElementById('pagination-current-page'),
        btnPagePrev: document.getElementById('btn-page-prev'),
        btnPageNext: document.getElementById('btn-page-next'),

        // Modal
        flowModal: document.getElementById('flow-modal'),
        modalBackdrop: document.getElementById('modal-backdrop'),
        modalFlowId: document.getElementById('modal-flow-id'),
        modalVerdictBadge: document.getElementById('modal-verdict-badge'),
        modalFlowBody: document.getElementById('modal-flow-body'),
        btnCloseModal: document.getElementById('btn-close-modal')
    };

    // Formatters
    function formatNumber(num) {
        if (num === undefined || num === null) return '0';
        return Number(num).toLocaleString();
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0.00 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
    }

    // Update Status Badge
    function updateStatusBadge(status) {
        elements.statusBadge.className = 'status-badge';
        const s = (status || 'NO_TELEMETRY').toUpperCase();

        if (s === 'ENGINE_RUNNING') {
            elements.statusBadge.classList.add('status-running');
            elements.statusText.textContent = 'RUNNING';
        } else if (s === 'ENGINE_COMPLETED') {
            elements.statusBadge.classList.add('status-completed');
            elements.statusText.textContent = 'COMPLETED';
        } else if (s === 'ENGINE_ERROR') {
            elements.statusBadge.classList.add('status-error');
            elements.statusText.textContent = 'ERROR';
        } else {
            elements.statusBadge.classList.add('status-waiting');
            elements.statusText.textContent = 'NO TELEMETRY';
        }
    }

    // Render Sparkline SVG
    function renderSparkline() {
        const history = state.throughputHistory;
        if (!history || history.length < 2) return;

        const width = 600;
        const height = 160;
        const padding = 20;

        const maxPps = Math.max(...history.map(h => h.pps), 1);
        const maxMbps = Math.max(...history.map(h => h.mbps), 1);

        const stepX = (width - padding * 2) / (history.length - 1);

        let ppsPoints = [];
        let mbpsPoints = [];

        history.forEach((pt, idx) => {
            const x = padding + idx * stepX;
            const yPps = height - padding - (pt.pps / maxPps) * (height - padding * 2);
            const yMbps = height - padding - (pt.mbps / maxMbps) * (height - padding * 2);

            ppsPoints.push(`${x.toFixed(1)},${yPps.toFixed(1)}`);
            mbpsPoints.push(`${x.toFixed(1)},${yMbps.toFixed(1)}`);
        });

        const svgContent = `
            <defs>
                <linearGradient id="grad-cyan" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#06b6d4" stop-opacity="0.3"/>
                    <stop offset="100%" stop-color="#06b6d4" stop-opacity="0.0"/>
                </linearGradient>
            </defs>
            <polyline fill="none" stroke="#8b5cf6" stroke-width="2" stroke-dasharray="4 2" points="${mbpsPoints.join(' ')}" />
            <polyline fill="none" stroke="#06b6d4" stroke-width="2.5" points="${ppsPoints.join(' ')}" />
        `;

        elements.sparklineSvg.innerHTML = svgContent;
    }

    // Update KPIs & Protocol Distribution
    function updateMetrics(snapshot) {
        if (!snapshot) return;
        state.lastSnapshot = snapshot;

        updateStatusBadge(snapshot.engine_status);

        // Update Ribbon
        const tr = snapshot.traffic || {};
        const fl = snapshot.flows_summary || snapshot.flows || {};
        const protoL4 = (snapshot.protocols && snapshot.protocols.transport) || {};
        const protoL7 = (snapshot.protocols && snapshot.protocols.application) || {};
        const dp = snapshot.dpi || protoL7;
        const po = snapshot.policy || {};

        const pps = tr.packets_per_sec ?? tr.packets_per_second ?? 0;
        const bps = tr.bytes_per_sec ?? tr.bytes_per_second ?? 0;

        elements.kpiTotalPackets.textContent = formatNumber(tr.total_packets);
        elements.kpiPps.textContent = `${(pps / 1000).toFixed(2)} kpkts/s`;

        elements.kpiThroughput.textContent = formatBytes(tr.total_bytes);
        elements.kpiMbps.textContent = `${(bps / (1024 * 1024)).toFixed(2)} MB/s`;

        elements.kpiTotalFlows.textContent = formatNumber(fl.total_flows);
        elements.kpiActiveFlows.textContent = `${formatNumber(fl.active_flows)} active · ${formatNumber(fl.completed_flows)} completed`;

        const classifiedL7 = (protoL7.tls || 0) + (protoL7.http || 0) + (protoL7.dns || 0);
        elements.kpiDpiClassified.textContent = formatNumber(classifiedL7);
        const dpiPct = fl.total_flows > 0 ? ((classifiedL7 / fl.total_flows) * 100).toFixed(1) : '0.0';
        elements.kpiDpiRate.textContent = `${dpiPct}% coverage`;

        elements.kpiBlockedFlows.textContent = formatNumber(po.blocked_flows);
        elements.kpiBlockedPackets.textContent = `${formatNumber(po.blocked_packets)} blocked packets`;

        const tm = snapshot.threat_metrics || {};
        const sev = tm.severity_breakdown || {};
        if (elements.kpiThreatAlerts) {
            elements.kpiThreatAlerts.textContent = formatNumber(tm.total_alerts_generated || 0);
            elements.kpiThreatDropped.textContent = `${formatNumber(tm.total_alerts_dropped || 0)} dropped · ${formatNumber(sev.critical || 0)} crit`;
        }

        // Update Stage 9 Risk Metrics
        const rm = snapshot.risk_metrics || {};
        const rd = rm.risk_distribution || {};
        const highCrit = (rd.high || 0) + (rd.critical || 0);
        if (elements.kpiRiskHigh) {
            elements.kpiRiskHigh.textContent = formatNumber(highCrit);
            elements.kpiRiskSub.textContent = `${formatNumber(rm.beaconing_flows_detected || 0)} beacon · ${formatNumber(rm.exfiltration_flows_detected || 0)} exfil`;
        }

        if (elements.badgeRiskCrit) elements.badgeRiskCrit.textContent = `${formatNumber(rd.critical || 0)} Critical`;
        if (elements.badgeRiskHigh) elements.badgeRiskHigh.textContent = `${formatNumber(rd.high || 0)} High`;
        if (elements.badgeRiskMed) elements.badgeRiskMed.textContent = `${formatNumber(rd.medium || 0)} Medium`;
        if (elements.badgeRiskLow) elements.badgeRiskLow.textContent = `${formatNumber(rd.low || 0)} Low`;

        updateHostsTable(rm.top_risky_hosts || []);

        // Update Sparkline History
        state.throughputHistory.push({
            pps: pps,
            mbps: bps ? (bps / (1024 * 1024)) : 0
        });
        if (state.throughputHistory.length > state.maxHistoryPoints) {
            state.throughputHistory.shift();
        }
        renderSparkline();

        // Update Protocol Bars
        const tcpFlows = protoL4.tcp || fl.tcp_flows || 0;
        const udpFlows = protoL4.udp || fl.udp_flows || 0;
        const otherL4 = protoL4.other || fl.other_l4_flows || 0;
        const totalL4 = tcpFlows + udpFlows + otherL4;
        if (totalL4 > 0) {
            elements.barProtoTcp.style.width = `${((tcpFlows / totalL4) * 100).toFixed(1)}%`;
            elements.barProtoUdp.style.width = `${((udpFlows / totalL4) * 100).toFixed(1)}%`;
            elements.barProtoOther.style.width = `${((otherL4 / totalL4) * 100).toFixed(1)}%`;
        }
        elements.valProtoTcp.textContent = formatNumber(tcpFlows);
        elements.valProtoUdp.textContent = formatNumber(udpFlows);
        elements.valProtoOther.textContent = formatNumber(otherL4);

        // Update L7 Bars
        const tlsFlows = protoL7.tls || dp.tls_flows || 0;
        const httpFlows = protoL7.http || dp.http_flows || 0;
        const dnsFlows = protoL7.dns || dp.dns_flows || 0;
        const unkFlows = protoL7.unknown || dp.unknown_l7_flows || 0;
        const totalL7 = tlsFlows + httpFlows + dnsFlows + unkFlows;

        elements.valL7Tls.textContent = formatNumber(tlsFlows);
        elements.valL7Http.textContent = formatNumber(httpFlows);
        elements.valL7Dns.textContent = formatNumber(dnsFlows);
        elements.valL7Unknown.textContent = formatNumber(unkFlows);

        if (totalL7 > 0) {
            elements.miniBarTls.style.width = `${((tlsFlows / totalL7) * 100).toFixed(1)}%`;
            elements.miniBarHttp.style.width = `${((httpFlows / totalL7) * 100).toFixed(1)}%`;
            elements.miniBarDns.style.width = `${((dnsFlows / totalL7) * 100).toFixed(1)}%`;
            elements.miniBarUnknown.style.width = `${((unkFlows / totalL7) * 100).toFixed(1)}%`;
        }

        // Update Workers
        updateWorkers(snapshot.workers || []);
    }

    // Render Stage 9 Top Risky Hosts Table
    function updateHostsTable(hosts) {
        if (!elements.hostsTbody) return;
        if (!hosts || hosts.length === 0) {
            elements.hostsTbody.innerHTML = `<tr><td colspan="5" class="table-empty">No risky host activity detected.</td></tr>`;
            return;
        }

        elements.hostsTbody.innerHTML = hosts.map(h => {
            let riskBadgeClass = 'badge-risk-none';
            if (h.max_flow_risk >= 80) riskBadgeClass = 'badge-risk-crit';
            else if (h.max_flow_risk >= 60) riskBadgeClass = 'badge-risk-high';
            else if (h.max_flow_risk >= 30) riskBadgeClass = 'badge-risk-med';
            else if (h.max_flow_risk > 0) riskBadgeClass = 'badge-risk-low';

            let flags = [];
            if (h.has_beaconing) flags.push('<span class="risk-factor-tag">C2 Beacon</span>');
            if (h.has_exfiltration) flags.push('<span class="risk-factor-tag">Data Exfil</span>');
            if (flags.length === 0) flags.push('<span style="color: var(--text-muted); font-size: 0.75rem;">None</span>');

            return `
                <tr>
                    <td><span class="flow-tuple">${h.ip}</span></td>
                    <td><span class="badge ${riskBadgeClass}">${h.max_flow_risk} / 100</span></td>
                    <td><span class="flow-stats-col">${formatNumber(h.total_flows)}</span></td>
                    <td><span class="flow-stats-col" style="color: #f87171; font-weight: 600;">${formatNumber(h.high_risk_flows)}</span></td>
                    <td>${flags.join(' ')}</td>
                </tr>
            `;
        }).join('');
    }

    // Render Worker Cards
    function updateWorkers(workers) {
        elements.workerCountBadge.textContent = `${workers.length} Worker Threads`;
        if (workers.length === 0) {
            elements.workerGrid.innerHTML = '<div class="table-empty">No active worker pipeline threads reported.</div>';
            return;
        }

        elements.workerGrid.innerHTML = workers.map(w => `
            <div class="worker-card-item">
                <div class="worker-header">
                    <span class="worker-id">Worker Core #${w.worker_id}</span>
                    <span class="badge badge-cyan">${formatNumber(w.packets_processed)} pkts</span>
                </div>
                <div class="worker-metric-row">
                    <span>Queue Depth</span>
                    <span class="worker-metric-val">${w.queue_size || 0}</span>
                </div>
                <div class="worker-metric-row">
                    <span>Flows Created</span>
                    <span class="worker-metric-val">${formatNumber(w.flows_created)}</span>
                </div>
                <div class="worker-metric-row">
                    <span>DPI Classified</span>
                    <span class="worker-metric-val">${formatNumber(w.dpi_classified_flows)}</span>
                </div>
                <div class="worker-metric-row">
                    <span>Blocked Packets</span>
                    <span class="worker-metric-val" style="color: #fb7185">${formatNumber(w.blocked_packets)}</span>
                </div>
            </div>
        `).join('');
    }

    // Fetch and render Flows Table
    async function fetchFlows() {
        try {
            const params = new URLSearchParams({
                page: state.currentPage,
                page_size: state.pageSize,
                transport: state.filters.transport,
                app: state.filters.app,
                verdict: state.filters.verdict,
                risk_level: state.filters.risk
            });
            if (state.filters.search) {
                params.append('search', state.filters.search);
            }

            const res = await fetch(`/api/flows?${params.toString()}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            renderFlowsTable(data);
        } catch (err) {
            console.error('Error fetching flows:', err);
        }
    }

    function renderFlowsTable(data) {
        const flows = data.flows || [];
        elements.paginationInfo.textContent = `Showing ${flows.length} of ${data.total} flows`;
        elements.paginationCurrentPage.textContent = `Page ${data.page} of ${data.total_pages || 1}`;
        elements.btnPagePrev.disabled = data.page <= 1;
        elements.btnPageNext.disabled = data.page >= data.total_pages;

        if (flows.length === 0) {
            elements.flowsTbody.innerHTML = `<tr><td colspan="11" class="table-empty">No flows matching filter criteria.</td></tr>`;
            return;
        }

        elements.flowsTbody.innerHTML = flows.map(f => {
            let appBadgeClass = 'badge-unknown';
            if (f.app_protocol === 'TLS') appBadgeClass = 'badge-tls';
            else if (f.app_protocol === 'HTTP') appBadgeClass = 'badge-http';
            else if (f.app_protocol === 'DNS') appBadgeClass = 'badge-dns';

            let verdictBadgeClass = 'badge-allow';
            if (f.policy_verdict === 'BLOCK') verdictBadgeClass = 'badge-block';
            else if (f.policy_verdict === 'ALERT') verdictBadgeClass = 'badge-alert';

            let riskBadgeClass = 'badge-risk-none';
            if (f.risk_level === 'CRITICAL') riskBadgeClass = 'badge-risk-crit';
            else if (f.risk_level === 'HIGH') riskBadgeClass = 'badge-risk-high';
            else if (f.risk_level === 'MEDIUM') riskBadgeClass = 'badge-risk-med';
            else if (f.risk_level === 'LOW') riskBadgeClass = 'badge-risk-low';

            return `
                <tr>
                    <td><span class="flow-tuple">${f.src_ip}:${f.src_port} &rarr; ${f.dst_ip}:${f.dst_port}</span></td>
                    <td><span class="badge ${riskBadgeClass}">${f.risk_score} (${f.risk_level})</span></td>
                    <td><span class="badge ${f.transport_protocol === 'TCP' ? 'badge-tcp' : 'badge-udp'}">${f.transport_protocol}</span></td>
                    <td><span class="badge ${appBadgeClass}">${f.app_protocol}</span></td>
                    <td><div class="flow-host" title="${f.host_or_sni || '-'}">${f.host_or_sni || '-'}</div></td>
                    <td><span class="badge badge-gray">${f.tcp_state}</span></td>
                    <td><span class="badge ${verdictBadgeClass}">${f.policy_verdict}</span></td>
                    <td><span class="flow-stats-col">${f.packets_forward} pkts / ${formatBytes(f.bytes_forward)}</span></td>
                    <td><span class="flow-stats-col">${f.packets_reverse} pkts / ${formatBytes(f.bytes_reverse)}</span></td>
                    <td><span class="flow-stats-col">${f.duration_ms} ms</span></td>
                    <td>
                        <button class="btn btn-sm btn-control btn-inspect" data-flow-id="${f.flow_id}">Inspect</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach Inspect Click Handlers
        document.querySelectorAll('.btn-inspect').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.target.getAttribute('data-flow-id');
                openFlowModal(id);
            });
        });
    }

    // Modal Inspection
    async function openFlowModal(flowId) {
        try {
            const res = await fetch(`/api/flows/${encodeURIComponent(flowId)}`);
            if (!res.ok) throw new Error('Flow not found');
            const f = await res.json();

            elements.modalFlowId.textContent = `Flow ID: ${f.flow_id}`;
            elements.modalVerdictBadge.className = `badge ${f.policy_verdict === 'BLOCK' ? 'badge-block' : 'badge-allow'}`;
            elements.modalVerdictBadge.textContent = f.policy_verdict;

            const factorsHtml = (f.risk_factors && f.risk_factors.length > 0)
                ? `<div class="risk-factors-list">${f.risk_factors.map(rf => `<span class="risk-factor-tag">${rf}</span>`).join(' ')}</div>`
                : '<span style="color: var(--text-muted);">None (Clean traffic profile)</span>';

            elements.modalFlowBody.innerHTML = `
                <div class="modal-detail-row">
                    <span class="modal-detail-label">5-Tuple</span>
                    <span class="modal-detail-val">${f.src_ip}:${f.src_port} &harr; ${f.dst_ip}:${f.dst_port} [${f.transport_protocol}]</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Composite Risk Score</span>
                    <span class="modal-detail-val"><span class="badge ${f.risk_level === 'CRITICAL' ? 'badge-risk-crit' : (f.risk_level === 'HIGH' ? 'badge-risk-high' : (f.risk_level === 'MEDIUM' ? 'badge-risk-med' : 'badge-risk-low'))}">${f.risk_score} / 100 (${f.risk_level})</span></span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Contributing Risk Factors</span>
                    <span class="modal-detail-val">${factorsHtml}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Behavioral Profiling</span>
                    <span class="modal-detail-val">Mean IAT: ${f.mean_iat_ms ? f.mean_iat_ms.toFixed(1) : '0.0'} ms · Jitter Ratio: ${f.iat_jitter_ratio ? f.iat_jitter_ratio.toFixed(3) : '0.000'} · Byte Ratio: ${f.byte_ratio ? f.byte_ratio.toFixed(2) : '1.00'}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Behavioral Anomaly Flags</span>
                    <span class="modal-detail-val">${f.is_beaconing ? '<span class="risk-factor-tag">Periodic C2 Beaconing</span>' : ''} ${f.is_exfiltration ? '<span class="risk-factor-tag">Data Exfiltration</span>' : ''} ${(!f.is_beaconing && !f.is_exfiltration) ? 'None' : ''}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">L7 Classified Protocol</span>
                    <span class="modal-detail-val">${f.app_protocol}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Hostname / SNI / Domain</span>
                    <span class="modal-detail-val">${f.host_or_sni || 'None extracted'}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">TCP State</span>
                    <span class="modal-detail-val">${f.tcp_state}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Security Policy Verdict</span>
                    <span class="modal-detail-val">${f.policy_verdict} ${f.matched_rule_name ? `(Rule: ${f.matched_rule_name})` : ''}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Forward Traffic</span>
                    <span class="modal-detail-val">${f.packets_forward} packets · ${formatBytes(f.bytes_forward)}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Reverse Traffic</span>
                    <span class="modal-detail-val">${f.packets_reverse} packets · ${formatBytes(f.bytes_reverse)}</span>
                </div>
                <div class="modal-detail-row">
                    <span class="modal-detail-label">Flow Active Duration</span>
                    <span class="modal-detail-val">${f.duration_ms} ms</span>
                </div>
            `;

            elements.flowModal.classList.remove('hidden');
        } catch (err) {
            console.error('Failed to open modal:', err);
        }
    }

    function closeModal() {
        elements.flowModal.classList.add('hidden');
    }

    // Fetch and render Security Alerts Table
    async function fetchAlerts() {
        if (!elements.alertsTbody) return;
        try {
            const params = new URLSearchParams({
                page: 1,
                page_size: 50,
                severity: state.alertFilters.severity,
                category: state.alertFilters.category
            });
            if (state.alertFilters.search) {
                params.append('search', state.alertFilters.search);
            }

            const res = await fetch(`/api/alerts?${params.toString()}`);
            if (!res.ok) return;
            const data = await res.json();
            renderAlertsTable(data.alerts || []);
        } catch (err) {
            console.warn('Error fetching alerts:', err);
        }
    }

    function renderAlertsTable(alerts) {
        if (!elements.alertsTbody) return;

        if (alerts.length === 0) {
            elements.alertsTbody.innerHTML = `<tr><td colspan="9" class="table-empty">No security threat alerts matching criteria.</td></tr>`;
            return;
        }

        elements.alertsTbody.innerHTML = alerts.map(a => {
            let sevBadgeClass = 'badge-info';
            const s = (a.severity || 'INFO').toUpperCase();
            if (s === 'CRITICAL') sevBadgeClass = 'badge-critical';
            else if (s === 'HIGH') sevBadgeClass = 'badge-high';
            else if (s === 'MEDIUM') sevBadgeClass = 'badge-medium';
            else if (s === 'LOW') sevBadgeClass = 'badge-low';

            const timeStr = a.timestamp_us > 0 ? new Date(a.timestamp_us / 1000).toLocaleTimeString() : '-';
            const targetTuple = `${a.dst_ip}:${a.dst_port}`;
            const snippet = a.matched_snippet ? `<span class="alert-snippet" title="${a.matched_snippet}">${a.matched_snippet}</span>` : '-';

            return `
                <tr>
                    <td><span class="flow-tuple">#${a.alert_id}</span></td>
                    <td><span class="flow-stats-col">${timeStr}</span></td>
                    <td><span class="badge ${sevBadgeClass}">${a.severity}</span></td>
                    <td><span class="badge-cat">${a.category}</span></td>
                    <td><span style="font-weight: 600; color: #f1f5f9">${a.signature}</span></td>
                    <td><span class="flow-tuple">${a.src_ip}</span></td>
                    <td><span class="flow-tuple">${targetTuple}</span></td>
                    <td><span style="color: var(--text-secondary); font-size: 0.75rem">${a.trigger_reason || a.description}</span></td>
                    <td>${snippet}</td>
                </tr>
            `;
        }).join('');
    }

    // Polling Loop
    async function poll() {
        try {
            const res = await fetch('/api/metrics');
            if (res.ok) {
                const snapshot = await res.json();
                updateMetrics(snapshot);
            }
            await fetchFlows();
            await fetchAlerts();
        } catch (err) {
            console.warn('Polling error:', err);
            updateStatusBadge('NO_TELEMETRY');
        }

        if (state.isPolling) {
            state.pollTimer = setTimeout(poll, state.pollIntervalMs);
        }
    }

    function togglePolling() {
        state.isPolling = !state.isPolling;
        if (state.isPolling) {
            elements.pollIconPause.classList.remove('hidden');
            elements.pollIconPlay.classList.add('hidden');
            elements.pollBtnLabel.textContent = 'Live Sync';
            poll();
        } else {
            clearTimeout(state.pollTimer);
            elements.pollIconPause.classList.add('hidden');
            elements.pollIconPlay.classList.remove('hidden');
            elements.pollBtnLabel.textContent = 'Paused';
        }
    }

    // Event Listeners
    elements.btnTogglePoll.addEventListener('click', togglePolling);
    elements.btnRefreshNow.addEventListener('click', () => {
        poll();
    });

    elements.filterTransport.addEventListener('change', (e) => {
        state.filters.transport = e.target.value;
        state.currentPage = 1;
        fetchFlows();
    });

    elements.filterApp.addEventListener('change', (e) => {
        state.filters.app = e.target.value;
        state.currentPage = 1;
        fetchFlows();
    });

    elements.filterVerdict.addEventListener('change', (e) => {
        state.filters.verdict = e.target.value;
        state.currentPage = 1;
        fetchFlows();
    });

    if (elements.filterRisk) {
        elements.filterRisk.addEventListener('change', (e) => {
            state.filters.risk = e.target.value;
            state.currentPage = 1;
            fetchFlows();
        });
    }

    let searchTimeout;
    elements.filterSearch.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            state.filters.search = e.target.value;
            state.currentPage = 1;
            fetchFlows();
        }, 250);
    });

    if (elements.filterAlertSeverity) {
        elements.filterAlertSeverity.addEventListener('change', (e) => {
            state.alertFilters.severity = e.target.value;
            fetchAlerts();
        });
    }

    if (elements.filterAlertCategory) {
        elements.filterAlertCategory.addEventListener('change', (e) => {
            state.alertFilters.category = e.target.value;
            fetchAlerts();
        });
    }

    if (elements.filterAlertSearch) {
        let alertSearchTimeout;
        elements.filterAlertSearch.addEventListener('input', (e) => {
            clearTimeout(alertSearchTimeout);
            alertSearchTimeout = setTimeout(() => {
                state.alertFilters.search = e.target.value;
                fetchAlerts();
            }, 250);
        });
    }

    elements.btnPagePrev.addEventListener('click', () => {
        if (state.currentPage > 1) {
            state.currentPage--;
            fetchFlows();
        }
    });

    elements.btnPageNext.addEventListener('click', () => {
        state.currentPage++;
        fetchFlows();
    });

    elements.btnCloseModal.addEventListener('click', closeModal);
    elements.modalBackdrop.addEventListener('click', closeModal);

    // Initial Start
    poll();
})();
