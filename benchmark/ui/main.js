const API_BASE = window.location.origin;

// State
let currentResults = null;

// DOM Elements
const views = {
    input: document.getElementById('input-view'),
    result: document.getElementById('result-view')
};

const elements = {
    yamlInput: document.getElementById('yaml-input'),
    runBtn: document.getElementById('run-btn'),
    loadLastBtn: document.getElementById('load-last-btn'),
    newBtn: document.getElementById('new-btn'),
    resultsBody: document.getElementById('results-body'),
    historyList: document.getElementById('history-list'),
    logConsole: document.getElementById('log-console'),
    modal: document.getElementById('modal'),
    modalTitle: document.getElementById('modal-title'),
};

// Formatter blocks
const diffChartEl = document.getElementById('diff-chart-container');
const latChartEl = document.getElementById('lat-chart-container');

async function init() {
    setupWebSocket();
    attachEventListeners();
    await loadLatestHistory();
}

function setupWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'start') {
            elements.logConsole.innerHTML = '';
            elements.logConsole.style.display = 'block';
            appendToLog(data.summary);
        } else if (data.type === 'progress') {
            elements.runBtn.textContent = `Running... (${data.current}/${data.total})`;
            if (data.log) {
                appendToLog(data.log);
            }
        } else if (data.type === 'complete') {
            elements.runBtn.textContent = 'Start Execution';
            elements.runBtn.disabled = false;
            // Hide log console after a slight delay or keep it? User said "once all completed only u should go to results page"
            setTimeout(() => {
                elements.logConsole.style.display = 'none';
                if (data.report && data.report.run_id) {
                    loadResult(data.report.run_id);
                }
            }, 1000);
            loadLatestHistory();
        } else if (data.type === 'error') {
            elements.runBtn.textContent = 'Start Execution';
            elements.runBtn.disabled = false;
            appendToLog(`[ERROR] ${data.message}`, 'fail');
            alert('Error: ' + data.message);
        }
    };
    ws.onclose = () => {
        setTimeout(setupWebSocket, 3000);
    };
}

function appendToLog(text, forceStatus = null) {
    if (!elements.logConsole) return;
    
    const line = document.createElement('div');
    line.className = 'log-line';
    
    let processedText = text;
    let statusClass = '';
    
    if (forceStatus === 'fail' || text.includes('[FAIL]')) statusClass = 'status-fail';
    else if (text.includes('[PASS]')) statusClass = 'status-pass';
    else if (text.includes('[WARN]')) statusClass = 'status-warn';
    
    if (statusClass) {
        processedText = text.replace(/\[(PASS|WARN|FAIL)\]/, `<span class="${statusClass}">[$1]</span>`);
    }
    
    const timestamp = new Date().toLocaleTimeString();
    line.innerHTML = `<span class="timestamp">${timestamp}</span>${processedText}`;
    
    elements.logConsole.appendChild(line);
    elements.logConsole.scrollTop = elements.logConsole.scrollHeight;
}

async function loadLatestHistory() {
    try {
        const res = await fetch(`${API_BASE}/results`);
        const data = await res.json();
        if (data && data.length > 0) {
            renderHistory(data);
            // Load the most recent run (first in list usually, assuming sorted by timestamp desc)
            const latestRunId = data[0].id;
            await loadResult(latestRunId);
        }
    } catch (e) {
        console.error('Failed to load history', e);
    }
}

function renderHistory(historyData) {
    if (!elements.historyList) return;
    elements.historyList.innerHTML = historyData.map((item, index) => `
        <div class="history-item ${index === 0 ? 'active' : ''}" onclick="loadResult('${item.id}'); document.querySelectorAll('.history-item').forEach(el=>el.classList.remove('active')); this.classList.add('active');">
            <span class="run-id">${item.id}</span>
            <span class="run-meta">${new Date(item.timestamp).toLocaleDateString()} ${new Date(item.timestamp).toLocaleTimeString()} | Score: ${item.score.toFixed(3)}</span>
        </div>
    `).join('');
}

async function loadResult(runId) {
    try {
        const res = await fetch(`${API_BASE}/results/${runId}`);
        const data = await res.json();
        currentResults = data;
        renderReport(data);
        showView('result');
    } catch (e) {
        console.error('Failed to load result', e);
    }
}

function showView(viewName) {
    Object.keys(views).forEach(key => {
        if (views[key]) {
            if (key === viewName) {
                views[key].classList.add('active');
            } else {
                views[key].classList.remove('active');
            }
        }
    });
}

function renderReport(report) {
    if (!report) return;

    // Metadata
    document.getElementById('meta-run-id').textContent = report.run_id;
    document.getElementById('meta-dataset-hash').textContent = (report.dataset_hash || '').substring(0, 16);
    document.getElementById('meta-model-version').textContent = report.model_name || 'claude-sonnet-4.6';
    document.getElementById('meta-total-cases').textContent = report.total_cases;
    document.getElementById('meta-elapsed').textContent = `${(report.elapsed_total_seconds || 0).toFixed(1)}s`;
    document.getElementById('meta-cost').textContent = `$${(report.total_cost_usd || 0).toFixed(3)}`;

    // Metrics
    const compileRate = (report.pattern_summaries && report.pattern_summaries.length > 0) 
        ? Math.round(report.pattern_summaries[0].compile_rate * 100) 
        : 0;
    
    let convRate = 0;
    if (report.pattern_summaries && report.pattern_summaries.length > 0) {
        convRate = Math.round((report.pattern_summaries[0].convergence_rate || 0) * 100);
    }

    let intentCoverageSum = 0;
    report.results.forEach(r => { intentCoverageSum += r.intent_coverage; });
    const avgIntent = report.total_cases > 0 ? (intentCoverageSum / report.total_cases) : 0;

    document.getElementById('metric-compile').textContent = `${compileRate}%`;
    document.getElementById('metric-convergence').textContent = `${convRate}%`;
    document.getElementById('metric-intent').textContent = avgIntent.toFixed(2);
    document.getElementById('metric-score').textContent = (report.avg_final_score || 0).toFixed(3);

    // Charts
    renderDifficultyChart(report);
    renderLatencyChart(report);

    // Grid table
    elements.resultsBody.innerHTML = report.results.map(res => {
        const dotClass = res.compile_pass ? 'pass' : 'fail';
        return `
        <tr onclick="inspectResult('${res.id}')">
            <td>${res.id}</td>
            <td style="text-transform: capitalize;">${res.difficulty}</td>
            <td><span class="status-dot ${dotClass}"></span></td>
            <td>${(res.intent_coverage * 100).toFixed(0)}%</td>
            <td>${res.latency_seconds.toFixed(1)}s</td>
            <td style="font-weight: 600;">${res.final_score.toFixed(3)}</td>
        </tr>
    `}).join('');
}

function renderDifficultyChart(report) {
    if (!report.difficulty_summaries) return;
    
    // Find max count for scaling
    const maxCount = Math.max(...report.difficulty_summaries.map(d => d.count), 1);
    
    diffChartEl.innerHTML = report.difficulty_summaries.map(d => {
        const width = (d.count / maxCount) * 100;
        return `
        <div class="bar-chart-row">
            <div class="bar-label" style="text-transform: capitalize;">${d.difficulty}</div>
            <div class="bar-container">
                <div class="bar-fill" style="width: ${width}%"></div>
            </div>
            <div class="bar-value">${d.count}</div>
        </div>
        `;
    }).join('');
}

function renderLatencyChart(report) {
    const buckets = {
        '0-5s': 0,
        '5-10s': 0,
        '10-20s': 0,
        '20s+': 0
    };

    report.results.forEach(r => {
        if (r.latency_seconds < 5) buckets['0-5s']++;
        else if (r.latency_seconds < 10) buckets['5-10s']++;
        else if (r.latency_seconds < 20) buckets['10-20s']++;
        else buckets['20s+']++;
    });

    const maxCount = Math.max(...Object.values(buckets), 1);

    latChartEl.innerHTML = Object.entries(buckets).map(([label, count]) => {
        const width = (count / maxCount) * 100;
        return `
        <div class="bar-chart-row">
            <div class="bar-label">${label}</div>
            <div class="bar-container">
                <div class="bar-fill" style="width: ${width}%"></div>
            </div>
            <div class="bar-value">${count}</div>
        </div>
        `;
    }).join('');
}

window.inspectResult = (id) => {
    const res = currentResults.results.find(r => r.id === id);
    if (!res) return;

    document.getElementById('modal-title').textContent = `Inspection: ${id}`;
    
    document.getElementById('f-difficulty').textContent = res.difficulty || '--';
    document.getElementById('f-compile').textContent = res.compile_pass ? 'yes' : 'no';
    document.getElementById('f-converged').textContent = res.converged ? 'yes' : 'no';
    document.getElementById('f-retries').textContent = `${res.retries_used || 0} / ${res.max_retries || 0}`;
    document.getElementById('f-latency').textContent = `${(res.latency_seconds || 0).toFixed(2)}s`;
    document.getElementById('f-tokens').textContent = `${res.tokens_prompt || 0} / ${res.tokens_completion || 0}`;

    // Features
    document.getElementById('f-req-features').innerHTML = (res.required_features || []).length 
        ? res.required_features.map(f => `<li>${f}</li>`).join('') 
        : '<li>none</li>';

    document.getElementById('f-det-features').innerHTML = (res.detected_features || []).length 
        ? res.detected_features.map(f => `<li>${f}</li>`).join('') 
        : '<li>none</li>';

    const misFeatures = (res.missing_features || []);
    const extFeatures = (res.extraneous_features || []);
    const halFeatures = (res.hallucinated_features || []);
    
    document.getElementById('f-mis-features').innerHTML = misFeatures.length 
        ? misFeatures.map(f => `<li class="missing">${f}</li>`).join('') 
        : '<li>none</li>';

    document.getElementById('f-ext-features').innerHTML = extFeatures.length 
        ? extFeatures.map(f => `<li>${f}</li>`).join('') 
        : '<li>none</li>';
        
    document.getElementById('f-hal-features').innerHTML = halFeatures.length 
        ? halFeatures.map(f => `<li class="hallucinated">${f}</li>`).join('') 
        : '<li>none</li>';

    if (res.failure_layer) {
        document.getElementById('f-failure-layer-container').style.display = 'block';
        document.getElementById('f-failure-layer').textContent = res.failure_layer;
    } else {
        document.getElementById('f-failure-layer-container').style.display = 'none';
    }

    document.getElementById('f-code').textContent = res.code || '// No generated code available';

    elements.modal.classList.add('active');
};

function attachEventListeners() {
    elements.runBtn.onclick = async () => {
        const yaml = elements.yamlInput.value.trim();
        if (!yaml) return alert('Please enter YAML');

        const request = {
            yaml_content: yaml,
            tags: [],
            model: null
        };

        elements.runBtn.textContent = 'Executing...';
        elements.runBtn.disabled = true;

        try {
            const res = await fetch(`${API_BASE}/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request)
            });
            const data = await res.json();
            console.log('Run started', data);
        } catch (e) {
            elements.runBtn.textContent = 'Start Execution';
            elements.runBtn.disabled = false;
            alert('Failed to start run');
        }
    };

    elements.newBtn.onclick = () => showView('input');
    elements.loadLastBtn.onclick = loadLatestHistory;

    document.getElementById('close-modal').onclick = () => {
        elements.modal.classList.remove('active');
    };
    
    // Close on click outside
    document.getElementById('modal').addEventListener('click', (e) => {
        if (e.target.id === 'modal') {
            elements.modal.classList.remove('active');
        }
    });
}

init();
