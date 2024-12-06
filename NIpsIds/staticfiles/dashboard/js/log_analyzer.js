const urlParams = new URLSearchParams(window.location.search);
const isLiveMode = urlParams.get('live') === 'true';

if (isLiveMode) {
    // Hide file input elements
    document.querySelector('.form-group').style.display = 'none';
    setupWebSocket();
}

function setupWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const socket = new WebSocket(`${protocol}${window.location.host}/ws/snort_console_output/`);

    socket.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);
            if (data.output) {
                // Clean and parse the line
                const line = data.output.trim().replace(/^\d+\|/, '');
                parseLiveLine(line);
            }
        } catch (error) {
            console.error("Error processing WebSocket message:", error);
        }
    };

    socket.onclose = function (event) {
        console.log("WebSocket closed. Attempting to reconnect in 5 seconds...");
        setTimeout(setupWebSocket, 5000);
    };

    socket.onerror = function (error) {
        console.error("WebSocket error:", error);
    };

    return socket;
}

const ROWS_PER_PAGE = 1000;
let currentPage = 1;
let allTableRows = [];

function updatePagination() {
    const totalPages = Math.ceil(allTableRows.length / ROWS_PER_PAGE);
    const tbody = document.getElementById('logTableBody');
    const paginationDiv = document.getElementById('pagination');

    // Clear current table
    tbody.innerHTML = '';

    // Calculate start and end indices
    const start = (currentPage - 1) * ROWS_PER_PAGE;
    const end = Math.min(start + ROWS_PER_PAGE, allTableRows.length);

    // Add rows for current page
    for (let i = start; i < end; i++) {
        tbody.appendChild(allTableRows[i].cloneNode(true));
    }

    // Update pagination controls
    paginationDiv.innerHTML = `
        <button onclick="changePage(1)" ${currentPage === 1 ? 'disabled' : ''}>First</button>
        <button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>Previous</button>
        <button class="active">Page ${currentPage} of ${totalPages}</button>
        <button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Next</button>
        <button onclick="changePage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''}>Last</button>
    `;
}

function changePage(newPage) {
    currentPage = newPage;
    updatePagination();
}

function parseLiveLine(line) {
    if (!line.trim() || line.includes('GET /check-snort-status/')) return;

    try {
        line = line.replace(/^Alert:\s*/, '').trim();

        // Parse timestamp and would_drop
        const timestampMatch = line.match(/^(\d{2}\/\d{2}(?:\/\d{2})?-\d{2}:\d{2}:\d{2}\.\d+)/);
        const timestamp = timestampMatch ? timestampMatch[1] : '';
        const would_drop = line.includes('[would_drop]') ? 'would_drop' : '';

        // Parse rule ID and message
        const ruleMatch = line.match(/\[\d+:\d+:\d+\]/);
        const ruleId = ruleMatch ? ruleMatch[0] : '';
        // Updated regex to handle messages without quotes
        const messageMatch = line.match(/"([^"]+)"|\] ([^\[\]]+) \[\*\*/);
        const alertMessage = messageMatch ? (messageMatch[1] || messageMatch[2] || '') : '';

        // Parse priority
        const priorityMatch = line.match(/\[Priority:\s*(\d+)\]/);
        const priority = priorityMatch ? priorityMatch[1] : '';

        // Parse protocol and IPs
        const protocolMatch = line.match(/{(\w+)}/);
        const protocol = protocolMatch ? protocolMatch[1] : '';

        // Parse source and destination
        const ipPortPattern = /(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s*->\s*(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/;
        const ipMatch = line.match(ipPortPattern);
        
        if (timestamp && protocol) {
            const row = document.createElement('tr');
            
            const srcIp = ipMatch ? ipMatch[1] : '';
            const srcPort = ipMatch ? (ipMatch[2] || '') : '';
            const dstIp = ipMatch ? ipMatch[3] : '';
            const dstPort = ipMatch ? (ipMatch[4] || '') : '';

            row.insertCell().textContent = timestamp;
            row.insertCell().textContent = would_drop ? `${would_drop} ${ruleId}` : ruleId;
            row.insertCell().textContent = alertMessage;
            row.insertCell().textContent = priority;
            row.insertCell().textContent = protocol;
            row.insertCell().textContent = srcIp;
            row.insertCell().textContent = srcPort;
            row.insertCell().textContent = dstIp;
            row.insertCell().textContent = dstPort;

            // Add actions column
            const actionsCell = row.insertCell();
            actionsCell.innerHTML = `<button class="btn btn-sm btn-info" onclick="showDetails(this)">Details</button>`;

            // Add priority-based styling
            row.classList.add(`priority-${getPriorityClass(priority)}`);

            if (would_drop) {
                row.classList.add('would-drop');
            }

            allTableRows.unshift(row);
            updatePagination();
        }
    } catch (error) {
        console.error("Error parsing line:", error, line);
    }
}

function getPriorityClass(priority) {
    switch (priority) {
        case '1': return 'high';
        case '2': return 'medium';
        case '3': return 'low';
        default: return 'low';
    }
}

function showDetails(button) {
    const row = button.closest('tr');
    const cells = row.cells;
    const details = {
        timestamp: cells[0].textContent,
        ruleId: cells[1].textContent,
        message: cells[2].textContent,
        priority: cells[3].textContent,
        protocol: cells[4].textContent,
        source: `${cells[5].textContent}:${cells[6].textContent}`,
        destination: `${cells[7].textContent}:${cells[8].textContent}`
    };

    alert(
        `Alert Details:\n
Time: ${details.timestamp}
Rule ID: ${details.ruleId}
Message: ${details.message}
Priority: ${details.priority}
Protocol: ${details.protocol}
Source: ${details.source}
Destination: ${details.destination}`
    );
}

// Helper function to apply search filter to new rows
function applySearchFilter(row) {
    const searchInput = document.getElementById('search');
    const searchText = searchInput.value.toLowerCase();

    if (!searchText) {
        row.style.display = '';
        return;
    }

    const columnMap = {
        'time:': 0,
        'id:': 1,
        'mess:': 2,
        'prio:': 3,
        'proto:': 4,
        'src:': 5,
        'dst:': 6
    };

    let columnToSearch = -1;
    let searchValue = searchText;

    for (const [dork, column] of Object.entries(columnMap)) {
        if (searchText.startsWith(dork)) {
            columnToSearch = column;
            searchValue = searchText.substring(dork.length);
            break;
        }
    }

    let found = false;
    if (columnToSearch === -1) {
        // Search all columns
        for (let i = 0; i < row.cells.length; i++) {
            const cellText = (row.cells[i].textContent || '').toLowerCase();
            if (cellText.includes(searchValue)) {
                found = true;
                break;
            }
        }
    } else {
        // Search specific column
        const cellText = (row.cells[columnToSearch].textContent || '').toLowerCase();
        found = cellText.includes(searchValue);
    }

    row.style.display = found ? '' : 'none';
}

function updateFileName(input) {
    const fileName = input.files[0] ? input.files[0].name : 'No file chosen';
    document.getElementById('selectedFileName').textContent = fileName;

    // Automatically parse logs when file is selected
    if (input.files[0]) {
        parseLogs();
    }
}

function parseLogs() {
    const fileInput = document.getElementById('logFile');
    const errorMessage = document.getElementById('errorMessage');
    errorMessage.style.display = 'none';

    if (!fileInput.files || !fileInput.files[0]) {
        errorMessage.textContent = 'Please select a log file first';
        errorMessage.style.display = 'block';
        return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
        const text = e.target.result;
        const lines = text.split('\n');
        
        // Clear existing rows
        allTableRows = [];
        
        lines.forEach(line => {
            if (!line.trim()) return;
            
            // Clean and parse the line
            line = line.replace(/^Alert:\s*/, '').trim();
            parseLiveLine(line);
        });

        // Reset to first page and update pagination
        currentPage = 1;
        updatePagination();
        
        // Add search event listener
        const searchInput = document.getElementById('search');
        searchInput.value = '';
        searchInput.addEventListener('input', searchLogs);
    };
    reader.readAsText(fileInput.files[0]);
}

function sortTable(columnIndex) {
    const isAscending = document.getElementById('logTable').getAttribute('data-sort-asc') === 'true';

    allTableRows.sort((rowA, rowB) => {
        const cellA = rowA.cells[columnIndex].textContent.trim();
        const cellB = rowB.cells[columnIndex].textContent.trim();

        if (!isNaN(cellA) && !isNaN(cellB)) {
            return isAscending ? cellA - cellB : cellB - cellA;
        }
        return isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
    });

    document.getElementById('logTable').setAttribute('data-sort-asc', !isAscending);
    currentPage = 1;
    updatePagination();
}

function searchLogs() {
    try {
        const searchInput = document.getElementById('search');
        const searchText = searchInput.value.trim();
        const searchTerms = parseSearchQuery(searchText);
        let visibleCount = 0;

        // Reset display state for all rows
        allTableRows.forEach(row => {
            const matches = searchTerms.length === 0 || searchTerms.every(term => matchSearchTerm(row, term));
            row.style.display = matches ? '' : 'none';
            if (matches) visibleCount++;
        });

        // Update search count
        const searchCount = document.getElementById('searchCount');
        if (searchCount) {
            searchCount.textContent = `${visibleCount} result${visibleCount !== 1 ? 's' : ''}`;
        }

        // Reset to first page and update pagination
        currentPage = 1;
        updatePagination();
    } catch (error) {
        console.error('Search error:', error);
    }
}

function parseSearchQuery(query) {
    if (!query) return [];
    
    const terms = [];
    let currentTerm = '';
    let inQuotes = false;

    // Split query into terms, respecting quoted phrases
    for (let i = 0; i < query.length; i++) {
        if (query[i] === '"') {
            inQuotes = !inQuotes;
            continue;
        }
        if (query[i] === ' ' && !inQuotes) {
            if (currentTerm) {
                terms.push(currentTerm.trim());
                currentTerm = '';
            }
        } else {
            currentTerm += query[i];
        }
    }
    if (currentTerm) {
        terms.push(currentTerm.trim());
    }

    return terms.map(term => {
        const dorkMap = {
            'time:': 0,
            'id:': 1,
            'mess:': 2,
            'prio:': 3,
            'proto:': 4,
            'src:': 5,
            'srcport:': 6,
            'dst:': 7,
            'dstport:': 8
        };

        for (const [dork, column] of Object.entries(dorkMap)) {
            if (term.toLowerCase().startsWith(dork)) {
                return {
                    column,
                    value: term.substring(dork.length).toLowerCase(),
                    exact: term.includes('"')
                };
            }
        }

        return {
            column: -1,
            value: term.toLowerCase(),
            exact: term.includes('"')
        };
    });
}

function matchSearchTerm(row, term) {
    if (!row.cells || row.cells.length === 0) return false;

    const value = term.value.replace(/^"|"$/g, '');

    if (term.column === -1) {
        // Search all columns
        return Array.from(row.cells).some(cell => {
            const cellText = (cell.textContent || '').toLowerCase();
            return term.exact ? cellText === value : cellText.includes(value);
        });
    } else {
        // Search specific column
        const cellText = (row.cells[term.column].textContent || '').toLowerCase();
        return term.exact ? cellText === value : cellText.includes(value);
    }
}

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function getUrls() {
    const container = document.querySelector('.container');
    return {
        checkSnortUrl: container.dataset.checkSnortUrl,
        switchIpsUrl: container.dataset.switchIpsUrl,
        openAnalyzerUrl: container.dataset.openAnalyzerUrl
    };
}

function switchToIPS() {
    const urls = getUrls();

    fetch(urls.switchIpsUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error switching to IPS mode: ' + data.error);
            } else {
                alert('Successfully switched to IPS mode');
                document.getElementById('switchModeBtn').disabled = true;
                document.getElementById('logging').innerText = data.message;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error switching to IPS mode');
        });
}

function checkSnortStatus() {
    const urls = getUrls();

    fetch(urls.checkSnortUrl)
        .then(response => response.json())
        .then(data => {
            const statusDiv = document.getElementById('snortStatus');
            const statusText = document.getElementById('statusText');
            const modeStatus = document.getElementById('modeStatus');
            const streamButton = document.getElementById('streamButton');

            if (data.running) {
                statusDiv.style.display = 'block';
                statusDiv.className = 'alert alert-success';

                let modes = [];
                if (data.ids_running) modes.push(`IDS (PID: ${data.ids_pid})`);
                if (data.ips_running) modes.push(`IPS (PID: ${data.ips_pid})`);

                statusText.textContent = 'Snort is running';
                modeStatus.textContent = `Active modes: ${modes.join(', ')}`;
                streamButton.style.display = 'block';
            } else {
                statusDiv.style.display = 'block';
                statusDiv.className = 'alert alert-warning';
                statusText.textContent = 'Snort is not running';
                modeStatus.textContent = '';
                streamButton.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error checking Snort status:', error);
            const statusDiv = document.getElementById('snortStatus');
            statusDiv.style.display = 'block';
            statusDiv.className = 'alert alert-danger';
            document.getElementById('statusText').textContent = 'Error checking Snort status';
        });
}

function startStreaming() {
    const urls = getUrls();
    window.location.href = `${urls.openAnalyzerUrl}?live=true`;
}

// Check status every 5 seconds
checkSnortStatus();
setInterval(checkSnortStatus, 5000);

// Initialize search functionality
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(searchLogs, 300));
    }
});

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
