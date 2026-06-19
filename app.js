// App State
let state = {
    interfaces: [],
    selectedInterface: '',
    filter: '',
    isSniffing: false,
    packets: [], // Local summaries
    selectedPacketId: null,
    autoScroll: true,
    
    // Live Stats
    totalPackets: 0,
    totalBytes: 0,
    tempPacketCount: 0, // Used for PPS calculation
    ppsRate: 0,
    
    // Charts Data
    protocolCounts: {
        'TCP': 0,
        'UDP': 0,
        'ICMP': 0,
        'ARP': 0,
        'HTTP': 0,
        'DNS': 0,
        'Other': 0
    },
    rateHistory: Array(15).fill(0),
    rateLabels: Array(15).fill('')
};

// Global Chart References
let protocolChart = null;
let rateChart = null;
let sseConnection = null;
let ppsTimer = null;

// DOM Elements
const interfaceSelect = document.getElementById('interface-select');
const filterInput = document.getElementById('filter-input');
const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const btnClear = document.getElementById('btn-clear');
const btnExport = document.getElementById('btn-export');
const btnImportTrigger = document.getElementById('btn-import-trigger');
const pcapFileInput = document.getElementById('pcap-file-input');

const statTotalPackets = document.getElementById('stat-total-packets');
const statPacketsRate = document.getElementById('stat-packets-rate');
const statTotalData = document.getElementById('stat-total-data');
const statStatusText = document.getElementById('stat-status-text');
const snifferStatusDot = document.getElementById('sniffer-status-dot');

const packetList = document.getElementById('packet-list');
const packetSearch = document.getElementById('packet-search');
const autoScrollToggle = document.getElementById('auto-scroll-toggle');

const inspectedPacketId = document.getElementById('inspected-packet-id');
const layersTree = document.getElementById('layers-tree');
const hexdumpView = document.getElementById('hexdump-view');
const payloadView = document.getElementById('payload-view');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Initial Setup
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadInterfaces();
    checkSnifferStatus();
    setupEventListeners();
    
    // Start clock for BPF rate charts
    startPpsTimer();
});

// Setup Event Listeners
function setupEventListeners() {
    // Controls
    btnStart.addEventListener('click', startSniffing);
    btnStop.addEventListener('click', stopSniffing);
    btnClear.addEventListener('click', clearCapture);
    
    // PCAP Tools
    btnExport.addEventListener('click', exportPcap);
    btnImportTrigger.addEventListener('click', () => pcapFileInput.click());
    pcapFileInput.addEventListener('change', importPcap);
    
    // Search Filter
    packetSearch.addEventListener('input', filterPacketTable);
    
    // Auto Scroll Toggle
    autoScrollToggle.addEventListener('change', (e) => {
        state.autoScroll = e.target.checked;
    });
    
    // Inspector Tabs
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
}

// Initialize Charts
function initCharts() {
    // 1. Protocol Pie Chart
    const protoCtx = document.getElementById('protocol-chart').getContext('2d');
    protocolChart = new Chart(protoCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(state.protocolCounts),
            datasets: [{
                data: Object.values(state.protocolCounts),
                backgroundColor: [
                    '#0ea5e9', // TCP - Sky
                    '#a855f7', // UDP - Violet
                    '#f59e0b', // ICMP - Amber
                    '#10b981', // ARP - Emerald
                    '#ec4899', // HTTP - Pink
                    '#14b8a6', // DNS - Teal
                    '#6b7280'  // Other - Gray
                ],
                borderWidth: 1,
                borderColor: '#1e293b'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9ca3af',
                        font: { family: 'Outfit', size: 10 }
                    }
                }
            },
            cutout: '60%'
        }
    });

    // 2. Traffic Rate Line Chart
    // Pre-populate last 15 seconds labels
    for(let i=0; i<15; i++) {
        state.rateLabels[i] = `${14-i}s ago`;
    }
    
    const rateCtx = document.getElementById('rate-chart').getContext('2d');
    rateChart = new Chart(rateCtx, {
        type: 'line',
        data: {
            labels: state.rateLabels,
            datasets: [{
                label: 'Packets/sec',
                data: state.rateHistory,
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.05)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 1,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: {
                        color: '#6b7280',
                        font: { family: 'Outfit', size: 9 },
                        stepSize: 5
                    }
                },
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#6b7280',
                        font: { family: 'Outfit', size: 9 }
                    }
                }
            }
        }
    });
}

// Query Network Interfaces
async function loadInterfaces() {
    try {
        const response = await fetch('/api/interfaces');
        const data = await response.json();
        
        if (data.success) {
            state.interfaces = data.interfaces;
            interfaceSelect.innerHTML = '';
            
            data.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface.name;
                opt.textContent = `${iface.description} (${iface.ip})`;
                
                // Set default choice to first active IP or Loopback
                if (iface.ip !== 'N/A' && iface.ip !== '127.0.0.1' && !state.selectedInterface) {
                    opt.selected = true;
                    state.selectedInterface = iface.name;
                }
                interfaceSelect.appendChild(opt);
            });
            
            // If no interface selected yet, choose the first one
            if (!state.selectedInterface && data.interfaces.length > 0) {
                state.selectedInterface = data.interfaces[0].name;
                interfaceSelect.value = state.selectedInterface;
            }
            
            interfaceSelect.addEventListener('change', (e) => {
                state.selectedInterface = e.target.value;
            });
        } else {
            showNotification('Error loading network interfaces.', 'error');
        }
    } catch(err) {
        console.error("Interfaces fetch failed:", err);
        showNotification('Failed to contact server for network interfaces.', 'error');
    }
}

// Check if sniffer is running in background on startup
async function checkSnifferStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        if (data.success && data.sniffing) {
            state.isSniffing = true;
            state.selectedInterface = data.interface;
            state.filter = data.filter;
            
            interfaceSelect.value = data.interface;
            filterInput.value = data.filter;
            
            updateSnifferUiState(true);
            connectSse();
        } else {
            updateSnifferUiState(false);
        }
    } catch(err) {
        console.error("Status check failed:", err);
    }
}

// Start Sniffing
async function startSniffing() {
    if (!state.selectedInterface) {
        showNotification('Please select a network interface first.', 'warning');
        return;
    }
    
    state.filter = filterInput.value.trim();
    
    try {
        const response = await fetch('/api/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                interface: state.selectedInterface,
                filter: state.filter
            })
        });
        const data = await response.json();
        
        if (data.success) {
            state.isSniffing = true;
            updateSnifferUiState(true);
            connectSse();
            showNotification('Sniffer started successfully!', 'success');
        } else {
            showNotification(data.error || 'Failed to start sniffing.', 'error');
        }
    } catch(err) {
        console.error("Start sniffing error:", err);
        showNotification('Network connection failure starting sniffer.', 'error');
    }
}

// Stop Sniffing
async function stopSniffing() {
    try {
        const response = await fetch('/api/stop', { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            state.isSniffing = false;
            updateSnifferUiState(false);
            disconnectSse();
            showNotification('Sniffer stopped.', 'info');
        } else {
            showNotification(data.error || 'Failed to stop sniffing.', 'error');
        }
    } catch(err) {
        console.error("Stop sniffing error:", err);
        showNotification('Network connection failure stopping sniffer.', 'error');
    }
}

// Clear Captured History
async function clearCapture() {
    try {
        const response = await fetch('/api/clear', { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            // Reset counters
            state.packets = [];
            state.totalPackets = 0;
            state.totalBytes = 0;
            state.tempPacketCount = 0;
            state.ppsRate = 0;
            state.selectedPacketId = null;
            
            // Reset charts data
            Object.keys(state.protocolCounts).forEach(k => state.protocolCounts[k] = 0);
            state.rateHistory.fill(0);
            
            // Clear inspector views
            inspectedPacketId.textContent = 'No Packet Selected';
            layersTree.innerHTML = `
                <div class="inspector-placeholder">
                    <i class="fa-solid fa-network-wired"></i>
                    <p>Select a packet from the table to inspect its structural details.</p>
                </div>`;
            hexdumpView.textContent = 'Select a packet to view hex bytes.';
            payloadView.textContent = 'Select a packet to view decoded ascii payload.';
            
            // Update UI
            updateDashboardMetrics();
            updateCharts();
            renderPacketTable();
            
            showNotification('Packet history cleared.', 'info');
        }
    } catch(err) {
        console.error("Clear capture error:", err);
    }
}

// PCAP Export
function exportPcap() {
    if (state.packets.length === 0) {
        showNotification('No packets captured to export.', 'warning');
        return;
    }
    
    // Direct window download
    window.location.href = '/api/export';
    showNotification('Exporting PCAP session...', 'success');
}

// PCAP Import
async function importPcap(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    // Show loading indicator
    packetList.innerHTML = `<tr class="placeholder-row"><td colspan="7"><i class="fa-solid fa-spinner fa-spin"></i> Parsing PCAP file. Please wait...</td></tr>`;
    
    try {
        const response = await fetch('/api/import', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        
        if (data.success) {
            state.packets = data.packets;
            state.totalPackets = data.packets.length;
            
            // Re-calculate bytes and protocol distribution
            let byteCount = 0;
            // Clear protocols
            Object.keys(state.protocolCounts).forEach(k => state.protocolCounts[k] = 0);
            
            state.packets.forEach(pkt => {
                byteCount += pkt.length;
                incrementProtocolCount(pkt.protocol);
            });
            state.totalBytes = byteCount;
            
            updateDashboardMetrics();
            updateCharts();
            renderPacketTable();
            
            showNotification(data.status, 'success');
        } else {
            showNotification(data.error || 'Failed to import PCAP.', 'error');
            renderPacketTable(); // Restore
        }
    } catch(err) {
        console.error("Import PCAP error:", err);
        showNotification('Network connection failure importing PCAP.', 'error');
        renderPacketTable(); // Restore
    } finally {
        pcapFileInput.value = ''; // Reset file input
    }
}

// Server Sent Events (SSE) stream listener
function connectSse() {
    disconnectSse(); // Close active ones if any
    
    sseConnection = new EventSource('/api/stream');
    
    sseConnection.onmessage = (event) => {
        if (!event.data) return;
        
        try {
            const packet = JSON.parse(event.data);
            processIncomingPacket(packet);
        } catch(err) {
            console.error("Error parsing stream packet:", err);
        }
    };
    
    sseConnection.onerror = (err) => {
        console.error("SSE stream error, re-establishing:", err);
        // EventSource automatically reconnects, but let's log it.
    };
}

function disconnectSse() {
    if (sseConnection) {
        sseConnection.close();
        sseConnection = null;
    }
}

// Core packet processor
function processIncomingPacket(packet) {
    // 1. Add to state history (maintain max length 3000)
    if (state.packets.length >= 3000) {
        state.packets.shift();
    }
    state.packets.push(packet);
    
    // 2. Update stats
    state.totalPackets++;
    state.totalBytes += packet.length;
    state.tempPacketCount++; // Count for PPS rate calculation
    
    // 3. Update protocol counts
    incrementProtocolCount(packet.protocol);
    
    // 4. Update UI Dashboard Cards
    updateDashboardMetrics();
    
    // 5. Append Row to Table
    appendPacketRow(packet);
}

function incrementProtocolCount(proto) {
    const knownProtos = ['TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'DNS'];
    if (knownProtos.includes(proto)) {
        state.protocolCounts[proto]++;
    } else {
        state.protocolCounts['Other']++;
    }
}

// Update UI metrics cards
function updateDashboardMetrics() {
    statTotalPackets.textContent = state.totalPackets.toLocaleString();
    
    // Data unit helper
    if (state.totalBytes < 1024) {
        statTotalData.innerHTML = `${state.totalBytes} <span class="unit">B</span>`;
    } else if (state.totalBytes < 1024 * 1024) {
        statTotalData.innerHTML = `${(state.totalBytes / 1024).toFixed(1)} <span class="unit">KB</span>`;
    } else {
        statTotalData.innerHTML = `${(state.totalBytes / (1024 * 1024)).toFixed(2)} <span class="unit">MB</span>`;
    }
}

// Update Charts datasets
function updateCharts() {
    // 1. Protocol Pie
    if (protocolChart) {
        protocolChart.data.datasets[0].data = Object.values(state.protocolCounts);
        protocolChart.update('none'); // Update without transition lag
    }
    
    // 2. Traffic Line
    if (rateChart) {
        rateChart.data.datasets[0].data = state.rateHistory;
        rateChart.update('none');
    }
}

// PPS calculation scheduler
function startPpsTimer() {
    ppsTimer = setInterval(() => {
        state.ppsRate = state.tempPacketCount;
        state.tempPacketCount = 0;
        
        statPacketsRate.innerHTML = `${state.ppsRate} <span class="unit">pps</span>`;
        
        // Push rates history
        state.rateHistory.shift();
        state.rateHistory.push(state.ppsRate);
        
        // Redraw charts
        updateCharts();
        
        // Periodically refresh the Protocol Doughnut chart nicely
        if (protocolChart && state.totalPackets % 50 === 0) {
            protocolChart.data.datasets[0].data = Object.values(state.protocolCounts);
            protocolChart.update();
        }
    }, 1000);
}

// Append single row to table
function appendPacketRow(packet) {
    const searchVal = packetSearch.value.toLowerCase();
    
    // Check if table contains placeholder row and delete it
    const placeholder = packetList.querySelector('.placeholder-row');
    if (placeholder) {
        placeholder.remove();
    }
    
    // Check Search filter matches
    const matchesFilter = filterMatches(packet, searchVal);
    
    const row = document.createElement('tr');
    row.id = `packet-row-${packet.id}`;
    row.classList.add(`row-${packet.protocol.toLowerCase()}`);
    if (!matchesFilter) {
        row.style.display = 'none';
    }
    
    row.innerHTML = `
        <td>${packet.id}</td>
        <td>${packet.time}</td>
        <td title="${packet.source}">${packet.source}</td>
        <td title="${packet.destination}">${packet.destination}</td>
        <td><span class="badge badge-${packet.protocol.toLowerCase()}">${packet.protocol}</span></td>
        <td>${packet.length}</td>
        <td title="${escapeHtml(packet.info)}">${escapeHtml(packet.info)}</td>
    `;
    
    // Row click selection
    row.addEventListener('click', () => {
        selectPacketRow(packet.id);
    });
    
    packetList.appendChild(row);
    
    // Maintain maximum table elements in DOM (e.g. 500 rows displayed) to prevent DOM slowing
    if (packetList.children.length > 500) {
        packetList.children[0].remove();
    }
    
    // Auto-Scroll behavior
    if (state.autoScroll && matchesFilter) {
        packetList.parentElement.scrollTop = packetList.parentElement.scrollHeight;
    }
}

// Select a packet row
function selectPacketRow(id) {
    // Deselect old
    const oldRow = document.querySelector('.active-row');
    if (oldRow) {
        oldRow.classList.remove('active-row');
    }
    
    // Select new
    const newRow = document.getElementById(`packet-row-${id}`);
    if (newRow) {
        newRow.classList.add('active-row');
    }
    
    state.selectedPacketId = id;
    inspectedPacketId.textContent = `Packet #${id}`;
    
    // Fetch packet details
    fetchPacketDetails(id);
}

// Fetch packet details from API
async function fetchPacketDetails(id) {
    layersTree.innerHTML = `<div class="inspector-placeholder"><i class="fa-solid fa-spinner fa-spin"></i><p>Fetching packet structure...</p></div>`;
    hexdumpView.textContent = "Loading bytes...";
    payloadView.textContent = "Loading payload...";
    
    try {
        const response = await fetch(`/api/packet/${id}`);
        const data = await response.json();
        
        if (data.success) {
            // Render Protocol Tree
            renderLayersTree(data.layers);
            
            // Render Hex Dump
            hexdumpView.textContent = data.hexdump || "No binary representation available.";
            
            // Render Payload
            payloadView.textContent = data.payload || "No application payload extracted.";
        } else {
            layersTree.innerHTML = `<div class="inspector-placeholder"><i class="fa-solid fa-triangle-exclamation"></i><p>Error: ${data.error}</p></div>`;
        }
    } catch(err) {
        console.error("Failed to load packet details:", err);
        layersTree.innerHTML = `<div class="inspector-placeholder"><i class="fa-solid fa-triangle-exclamation"></i><p>Connection error loading details.</p></div>`;
    }
}

// Render Protocol tree layers
function renderLayersTree(layers) {
    layersTree.innerHTML = '';
    
    layers.forEach((layer, index) => {
        const block = document.createElement('div');
        block.classList.add('layer-block');
        
        // Collapse state: open first 2 layers by default, collapse others
        if (index >= 3) {
            block.classList.add('collapsed');
        }
        
        const title = document.createElement('div');
        title.classList.add('layer-title');
        title.innerHTML = `
            <span><i class="fa-solid fa-chevron-down"></i> &nbsp; ${layer.name} Protocol</span>
            <span style="font-size: 0.7rem; color: #6b7280; font-family: monospace;">(${Object.keys(layer.fields).length} fields)</span>
        `;
        
        // Accordion click toggle
        title.addEventListener('click', () => {
            block.classList.toggle('collapsed');
            const icon = title.querySelector('i');
            if (block.classList.contains('collapsed')) {
                icon.className = 'fa-solid fa-chevron-right';
            } else {
                icon.className = 'fa-solid fa-chevron-down';
            }
        });
        
        const fieldsContainer = document.createElement('div');
        fieldsContainer.classList.add('layer-fields');
        
        Object.entries(layer.fields).forEach(([fieldName, val]) => {
            const nameSpan = document.createElement('span');
            nameSpan.classList.add('field-name');
            nameSpan.textContent = `${fieldName}:`;
            
            const valSpan = document.createElement('span');
            valSpan.classList.add('field-value');
            valSpan.textContent = val;
            
            fieldsContainer.appendChild(nameSpan);
            fieldsContainer.appendChild(valSpan);
        });
        
        block.appendChild(title);
        block.appendChild(fieldsContainer);
        layersTree.appendChild(block);
    });
}

// Render full table of packets (used on Import or clear)
function renderPacketTable() {
    packetList.innerHTML = '';
    
    if (state.packets.length === 0) {
        packetList.innerHTML = `
            <tr class="placeholder-row">
                <td colspan="7">No packets captured yet. Select an interface and click <strong>Start</strong> to sniff traffic.</td>
            </tr>`;
        return;
    }
    
    state.packets.forEach(pkt => {
        appendPacketRow(pkt);
    });
}

// Search Filter function
function filterPacketTable() {
    const searchVal = packetSearch.value.toLowerCase();
    
    state.packets.forEach(pkt => {
        const row = document.getElementById(`packet-row-${pkt.id}`);
        if (!row) return;
        
        if (filterMatches(pkt, searchVal)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

function filterMatches(packet, query) {
    if (!query) return true;
    
    return packet.source.toLowerCase().includes(query) ||
           packet.destination.toLowerCase().includes(query) ||
           packet.protocol.toLowerCase().includes(query) ||
           packet.info.toLowerCase().includes(query) ||
           packet.id.toString().includes(query);
}

// UI State Updater
function updateSnifferUiState(running) {
    if (running) {
        btnStart.disabled = true;
        btnStop.disabled = false;
        interfaceSelect.disabled = true;
        filterInput.disabled = true;
        
        snifferStatusDot.className = 'status-dot capturing';
        statStatusText.textContent = 'SNIFFING';
    } else {
        btnStart.disabled = false;
        btnStop.disabled = true;
        interfaceSelect.disabled = false;
        filterInput.disabled = false;
        
        snifferStatusDot.className = 'status-dot idle';
        statStatusText.textContent = 'IDLE';
    }
}

// Notifications Helper
function showNotification(msg, type = 'info') {
    // Simple modern floating banner
    const notification = document.createElement('div');
    notification.className = `custom-banner banner-${type}`;
    
    let iconClass = 'fa-circle-info';
    if (type === 'success') iconClass = 'fa-circle-check';
    if (type === 'warning') iconClass = 'fa-triangle-exclamation';
    if (type === 'error') iconClass = 'fa-circle-xmark';
    
    notification.innerHTML = `
        <i class="fa-solid ${iconClass}"></i>
        <span>${msg}</span>
    `;
    
    // Inline banner styles injected dynamically for simplicity
    Object.assign(notification.style, {
        position: 'fixed',
        bottom: '2rem',
        right: '2rem',
        padding: '0.75rem 1.25rem',
        borderRadius: '6px',
        backgroundColor: '#1e293b',
        borderLeft: '4px solid #06b6d4',
        color: '#f3f4f6',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.3)',
        fontSize: '0.85rem',
        fontWeight: '500',
        zIndex: '1000',
        transform: 'translateY(100px)',
        opacity: '0',
        transition: 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)'
    });
    
    if (type === 'success') notification.style.borderLeftColor = '#10b981';
    if (type === 'error') notification.style.borderLeftColor = '#f43f5e';
    if (type === 'warning') notification.style.borderLeftColor = '#f59e0b';
    if (type === 'info') notification.style.borderLeftColor = '#0ea5e9';
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateY(0)';
        notification.style.opacity = '1';
    }, 10);
    
    // Remove after 3s
    setTimeout(() => {
        notification.style.transform = 'translateY(100px)';
        notification.style.opacity = '0';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

// Escape HTML utility
function escapeHtml(text) {
    if (!text) return '';
    return text
        .toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}