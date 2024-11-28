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

function parseLiveLine(line) {
if (!line.trim()) return;

try {
line = line.replace(/^Alert:\s*/, '').trim();

// Updated regex to parse all fields including ports
const pattern = /^(\d{2}\/\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[[\*]+\]\s+\[([^\]]+)\]\s+"([^"]+)"\s+\[[\*]+\]\s+\[Priority:\s*(\d+)\]\s+(?:\[AppID:\s*([^\]]+)\])?\s*{(\w+)}\s+(?:(\S+):(\d+))?\s*->\s*(?:(\S+):(\d+))?/;

const match = line.match(pattern);

if (match) {
    const [
        ,
        timestamp,
        ruleId,
        alertMessage,
        priority,
        appId,
        protocol,
        sourceIp,
        sourcePort,
        destIp,
        destPort
    ] = match;

    const tbody = document.getElementById('logTableBody');
    const row = tbody.insertRow(0);

    // Add cells matching table headers
    row.insertCell().textContent = timestamp;
    row.insertCell().textContent = ruleId;
    row.insertCell().textContent = alertMessage;
    row.insertCell().textContent = priority;
    row.insertCell().textContent = protocol;
    row.insertCell().textContent = sourceIp || '';
    row.insertCell().textContent = sourcePort || '';
    row.insertCell().textContent = destIp || '';
    row.insertCell().textContent = destPort || '';

    // Add actions column
    const actionsCell = row.insertCell();
    actionsCell.innerHTML = `<button class="btn btn-sm btn-info" onclick="showDetails(this)">Details</button>`;

    // Add priority-based styling
    row.classList.add(`priority-${getPriorityClass(priority)}`);

    // Limit table rows
    const maxRows = 1000;
    while (tbody.rows.length > maxRows) {
        tbody.deleteRow(tbody.rows.length - 1);
    }

    // Apply any existing filters
    applySearchFilter(row);
} else {
    console.warn("Could not parse live line:", line);
}
} catch (error) {
console.error("Error parsing live line:", error);
}
}

function getPriorityClass(priority) {
switch(priority) {
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
        const tbody = document.getElementById('logTableBody');
        tbody.innerHTML = '';

        lines.forEach(line => {
            if (!line.trim() || !line.includes('Alert:')) return;

            // Remove "Alert: " prefix and clean the line
            line = line.replace(/^Alert:\s*/, '').trim();

            // Updated regex pattern to match the sample log format
            const pattern = /^(\d{2}\/\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[[\*]+\]\s+\[([^\]]+)\]\s+"([^"]+)"\s+\[[\*]+\]\s+\[Priority:\s*(\d+)\]\s+(?:\[AppID:\s*([^\]]+)\])?\s*{(\w+)}\s+(\S+)\s+->\s+(\S+)/;

            const match = line.match(pattern);

            if (match) {
                const [
                    ,
                    timestamp,
                    ruleId,
                    alertMessage,
                    priority,
                    appId,
                    protocol,
                    source,
                    destination
                ] = match;

                const row = tbody.insertRow();

                // Add cells with the parsed data
                row.insertCell().textContent = timestamp;
                row.insertCell().textContent = ruleId;
                row.insertCell().textContent = alertMessage;
                row.insertCell().textContent = priority;
                row.insertCell().textContent = protocol;
                row.insertCell().textContent = source;
                row.insertCell().textContent = destination;

            } else {
                console.warn("Could not parse log line:", line);
            }
        });

        // Add search event listener after populating the table
        const searchInput = document.getElementById('search');
        searchInput.value = '';
        searchInput.addEventListener('input', searchLogs);
    };
    reader.readAsText(fileInput.files[0]);
}

function sortTable(columnIndex) {
    const table = document.getElementById('logTable');
    const tbody = table.tBodies[0];
    const rows = Array.from(tbody.rows);
    const isAscending = table.getAttribute('data-sort-asc') === 'true';

    rows.sort((rowA, rowB) => {
        const cellA = rowA.cells[columnIndex].textContent.trim();
        const cellB = rowB.cells[columnIndex].textContent.trim();

        if (!isNaN(cellA) && !isNaN(cellB)) {
            return isAscending ? cellA - cellB : cellB - cellA;
        }

        return isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
    });

    table.setAttribute('data-sort-asc', !isAscending);
    tbody.append(...rows);
}

function searchLogs() {
    try {
        const searchInput = document.getElementById('search');
        const searchText = searchInput.value.toLowerCase();
        const tbody = document.getElementById('logTableBody');
        const rows = tbody.getElementsByTagName('tr');

        // Define column mappings for search dorks
        const columnMap = {
            'time:': 0,  // Timestamp
            'id:': 1,    // Rule ID
            'mess:': 2,  // Alert Message
            'prio:': 3,  // Priority
            'proto:': 4, // Protocol
            'src:': 5,   // Source
            'dst:': 6    // Destination
        };

        // Check if search uses a dork
        let columnToSearch = -1; // -1 means search all columns
        let searchValue = searchText;

        for (const [dork, column] of Object.entries(columnMap)) {
            if (searchText.startsWith(dork)) {
                columnToSearch = column;
                searchValue = searchText.substring(dork.length);
                break;
            }
        }

        Array.from(rows).forEach(row => {
            if (row.cells.length < 7) return; // Skip invalid rows

            let found = false;
            if (columnToSearch === -1) {
                // Search all columns
                for (let i = 0; i < row.cells.length; i++) {
                    const cellText = (row.cells[i].textContent || row.cells[i].innerText || '').toLowerCase();
                    if (cellText.includes(searchValue)) {
                        found = true;
                        break;
                    }
                }
            } else {
                // Search specific column
                const cellText = (row.cells[columnToSearch].textContent || row.cells[columnToSearch].innerText || '').toLowerCase();
                found = cellText.includes(searchValue);
            }

            row.style.display = found ? '' : 'none';
        });
    } catch (error) {
        console.error('Search error:', error);
    }
}

// Update the search input placeholder to show available dorks
document.getElementById('search').placeholder = "Search (use: mess:, id:, proto:, src:, dst:, prio:, time:)";

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
