const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/ws`;

// State
let ws = null;
let currentResults = null;
let history = [];

// DOM Elements
const views = {
    input: document.getElementById('input-view'),
    progress: document.getElementById('progress-view'),
    result: document.getElementById('result-view')
};

const elements = {
    yamlInput: document.getElementById('yaml-input'),
    tagsInput: document.getElementById('tags-input'),
    modelSelect: document.getElementById('model-select'),
    runBtn: document.getElementById('run-btn'),
    newBtn: document.getElementById('new-btn'),
    historyList: document.getElementById('history-list'),
    connectionStatus: document.getElementById('connection-status'),
    logOutput: document.getElementById('log-output'),
    progressBar: document.getElementById('progress-bar-fill'),
    caseCount: document.getElementById('case-count'),
    currentCaseName: document.getElementById('current-case-name'),
    resultsBody: document.getElementById('results-body'),
    finalScore: document.getElementById('final-score'),
    passRate: document.getElementById('pass-rate'),
    avgLatency: document.getElementById('avg-latency'),
    modal: document.getElementById('modal'),
    modalTitle: document.getElementById('modal-title'),
    codePreview: document.getElementById('code-preview'),
    jsonPreview: document.getElementById('json-preview'),
    copyAiBtn: document.getElementById('copy-ai-btn')
};

// Initialization
async function init() {
    setupWebSocket();
    loadHistory();
    attachEventListeners();
}

function setupWebSocket() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        elements.connectionStatus.textContent = 'Connected';
        elements.connectionStatus.className = 'status-badge connected';
    };
    ws.onclose = () => {
        elements.connectionStatus.textContent = 'Disconnected';
        elements.connectionStatus.className = 'status-badge disconnected';
        setTimeout(setupWebSocket, 3000);
    };
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWsMessage(data);
    };
}

function handleWsMessage(data) {
    if (data.type === 'start') {
        showView('progress');
        elements.logOutput.innerHTML = `<div class="log-entry sys">${data.summary}</div>`;
        elements.progressBar.style.width = '0%';
        elements.caseCount.textContent = `0 / ${data.total}`;
    } else if (data.type === 'progress') {
        const percent = (data.current / data.total) * 100;
        elements.progressBar.style.width = `${percent}%`;
        elements.caseCount.textContent = `${data.current} / ${data.total}`;
        elements.currentCaseName.textContent = data.case_id;
        
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.textContent = data.log;
        elements.logOutput.appendChild(entry);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    } else if (data.type === 'complete') {
        console.log('Benchmark complete:', data.report);
        currentResults = data.report;
        try {
            renderResults(data.report);
            showView('result');
            loadHistory();
        } catch (err) {
            console.error('Error rendering results:', err);
            alert('Failed to render results: ' + err.message);
        }
    } else if (data.type === 'error') {
        alert('Error: ' + data.message);
        showView('input');
    }
}

async function loadHistory() {
    try {
        const res = await fetch(`${API_BASE}/results`);
        const data = await res.json();
        history = data;
        renderHistory();
    } catch (e) {
        console.error('Failed to load history', e);
    }
}

function renderHistory() {
    elements.historyList.innerHTML = history.map(item => `
        <div class="history-item" onclick="loadResult('${item.id}')">
            <span class="run-id">${item.id}</span>
            <span class="run-meta">${new Date(item.timestamp).toLocaleString()} | Score: ${item.score.toFixed(3)}</span>
        </div>
    `).join('');
}

async function loadResult(runId) {
    try {
        const res = await fetch(`${API_BASE}/results/${runId}`);
        const data = await res.json();
        currentResults = data;
        renderResults(data);
        showView('result');
    } catch (e) {
        alert('Failed to load result');
    }
}

function showView(viewName) {
    Object.keys(views).forEach(key => {
        views[key].classList.toggle('hidden', key !== viewName);
    });
}

function renderResults(report) {
    if (!report) return;
    
    elements.finalScore.textContent = (report.avg_final_score || 0).toFixed(3);
    
    const passRate = (report.pattern_summaries && report.pattern_summaries.length > 0) 
        ? Math.round(report.pattern_summaries[0].compile_rate * 100) 
        : 0;
    elements.passRate.textContent = `${passRate}%`;
    
    elements.avgLatency.textContent = `${(report.avg_latency || 0).toFixed(1)}s`;

    elements.resultsBody.innerHTML = report.results.map(res => `
        <tr>
            <td>${res.id}</td>
            <td><span class="subtitle">${res.difficulty}</span></td>
            <td><span class="${res.compile_pass ? 'badge-pass' : 'badge-fail'}">${res.compile_pass ? 'SUCCESS' : 'FAIL'}</span></td>
            <td>${res.intent_coverage * 100}%</td>
            <td>${res.latency_seconds.toFixed(1)}s</td>
            <td><span class="${res.final_score > 0.7 ? 'badge-pass' : 'badge-fail'}">${res.final_score.toFixed(3)}</span></td>
            <td><button class="btn-text" onclick="inspectResult('${res.id}')">Inspect</button></td>
        </tr>
    `).join('');
}

window.inspectResult = (id) => {
    const res = currentResults.results.find(r => r.id === id);
    if (!res) return;

    elements.modalTitle.textContent = `Inspection: ${id}`;
    elements.codePreview.textContent = res.code || '// No code generated';
    elements.jsonPreview.textContent = JSON.stringify(res, null, 2);
    elements.modal.classList.remove('hidden');
};

function attachEventListeners() {
    elements.runBtn.onclick = async () => {
        const yaml = elements.yamlInput.value.trim();
        if (!yaml) return alert('Please enter YAML');

        const request = {
            yaml_content: yaml,
            tags: elements.tagsInput.value ? elements.tagsInput.value.split(',') : [],
            model: elements.modelSelect.value || null
        };

        try {
            const res = await fetch(`${API_BASE}/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request)
            });
            const data = await res.json();
            console.log('Run started', data);
        } catch (e) {
            alert('Failed to start run');
        }
    };

    elements.newBtn.onclick = () => showView('input');
    
    elements.copyAiBtn.onclick = () => {
        if (!currentResults) return;
        const markdown = generateAiReport(currentResults);
        navigator.clipboard.writeText(markdown);
        elements.copyAiBtn.textContent = 'Copied!';
        setTimeout(() => elements.copyAiBtn.textContent = 'Copy Profile for AI', 2000);
    };

    document.getElementById('close-modal').onclick = () => {
        elements.modal.classList.add('hidden');
    };

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
            
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.remove('hidden');
        };
    });
}

function generateAiReport(report) {
    let md = `# NexOps Benchmark Report: ${report.run_id}\n\n`;
    md += `**Overall Score:** ${(report.avg_final_score || 0).toFixed(3)}\n`;
    
    const compileRate = (report.pattern_summaries && report.pattern_summaries.length > 0)
        ? (report.pattern_summaries[0].compile_rate * 100)
        : 0;
    md += `**Compile Rate:** ${compileRate}%\n`;
    md += `**Avg Latency:** ${(report.avg_latency || 0).toFixed(1)}s\n\n`;
    
    md += `## Individual Results\n\n`;
    report.results.forEach(res => {
        md += `### ${res.id} (${res.difficulty})\n`;
        md += `- **Status:** ${res.compile_pass ? 'Passed' : 'Failed'}\n`;
        md += `- **Score:** ${res.final_score.toFixed(3)}\n`;
        if (res.missing_features.length) md += `- **Missing Features:** ${res.missing_features.join(', ')}\n`;
        if (res.hallucinated_features.length) md += `- **Hallucinated:** ${res.hallucinated_features.join(', ')}\n`;
        if (res.failure_layer) md += `- **Failure Layer:** ${res.failure_layer}\n`;
        md += `\n`;
    });
    
    md += `\n---\n*Generated by NexOps Benchmark Visualizer*`;
    return md;
}

init();
