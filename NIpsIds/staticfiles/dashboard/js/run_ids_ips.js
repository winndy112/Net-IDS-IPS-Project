const csrftoken = getCookie('csrftoken');
function getUrls() {
    const container = document.querySelector('.container');
    return {
        runSnort: container.dataset.runSnort,
        stopIds: container.dataset.stopIds,
        stopIps: container.dataset.stopIps,
    }
}
async function startSnort(event) {
    event.preventDefault(); // Prevent form from submitting normally
    const urls = getUrls();

    const hours = document.getElementById('hours').value;
    const interface = document.getElementById('interface').value;
    const configFile = document.getElementById('configFile').value;
    const captureType = document.getElementById('captureType').value;
    try {
        const response = await fetch(urls.runSnort, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify({
                hours: hours,
                interface: interface,
                config_file: configFile,
                capture_type: captureType,
                action: 'start'
            })
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message);
            document.getElementById('logging').innerText += data.message + " with pid: " + data.pid + "\n";
        } else {
            alert('Error starting Snort: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error connecting to server');
    }
}

async function stopIDS() {
    const urls = getUrls();
    try {
        const response = await fetch(urls.stopIds, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            }
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message + " with pid: " + data.pid);
            document.getElementById('logging').innerText += data.message + " with pid: " + data.pid;
        } else {
            alert('Error stopping Snort: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error connecting to server');
    }
}
async function stopIPS() {
    const urls = getUrls();
    try {
        const response = await fetch(urls.stopIps, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            }
        });

        const data = await response.json();
        if (response.ok) {
            alert(data.message + " with pid: " + data.pid);
            document.getElementById('logging').innerText += data.message + " with pid: " + data.pid;
        } else {
            alert('Error stopping Snort: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error connecting to server');
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

let socket = null;

function setupWebSocket() {
    if (socket !== null) {
        console.log("Closing existing socket connection");
        socket.close();
    }

    const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const host = window.location.hostname;
    const port = '8080'; // Explicitly set port to match Daphne
    const wsUrl = `${protocol}${host}:${port}/ws/snort_console_output/`;

    console.log("Attempting WebSocket connection to:", wsUrl);

    socket = new WebSocket(wsUrl);

    socket.onopen = function (event) {
        console.log("WebSocket connection established");
        const consoleOutput = document.getElementById("console-output");
        consoleOutput.innerHTML = "<div style='color: green;'>WebSocket Connected ✓</div>";
    };

    socket.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);
            const consoleOutput = document.getElementById("console-output");
            consoleOutput.innerHTML += `<div>${data.output}</div>`;
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        } catch (error) {
            console.error("Error processing message:", error);
        }
    };

    socket.onerror = function (error) {
        console.error("WebSocket error:", error);
        const consoleOutput = document.getElementById("console-output");
        consoleOutput.innerHTML = "<div style='color: red;'>WebSocket Error: Connection failed ✗</div>";
    };

    socket.onclose = function (event) {
        console.log("WebSocket closed. Attempting to reconnect in 5 seconds...");
        const consoleOutput = document.getElementById("console-output");
        consoleOutput.innerHTML = "<div style='color: orange;'>WebSocket Disconnected. Reconnecting...</div>";
        setTimeout(setupWebSocket, 5000);
    };

    return socket;
}

// Initialize WebSocket when the page loads
document.addEventListener('DOMContentLoaded', function () {
    console.log("Page loaded, initializing WebSocket");
    setupWebSocket();
});

document.addEventListener('DOMContentLoaded', () => {
    const interfaceSelect = document.getElementById('interface');

    fetch('/get-interfaces/')
        .then(response => response.json())
        .then(data => {
            interfaceSelect.innerHTML = '<option value="">Select interface</option>';
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                interfaceSelect.appendChild(option);
            });
        })
        .catch(error => console.error('Failed to load interfaces:', error));
});
