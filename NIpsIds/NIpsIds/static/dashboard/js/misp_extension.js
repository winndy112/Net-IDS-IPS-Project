let scheduleInterval;

function logMessage(message) {
    const logElement = document.getElementById('log');
    logElement.textContent += message + '\n';
    logElement.scrollTop = logElement.scrollHeight;
}

async function exportEvent() {
    const eventId = document.getElementById('eventId').value;
    if (!eventId || eventId <= 0) {
        alert('Please enter a positive Event ID');
        return;
    }
    try {
        logMessage(`Exporting event with ID: ${eventId}`);
        
        const response = await fetch('/export-event/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ event_id: eventId })
        });

        if (response.ok) {
            const result = await response.json();
            logMessage(result.message);
        } else {
            const errorText = await response.text();
            logMessage(`Error exporting event: ${response.status} - ${errorText}`);
        }
    } catch (error) {
        logMessage('Error exporting event: ' + error);
    }
}

async function startSchedule() {
    const scheduleTime = document.getElementById('scheduleTime').value;
    const timeUnit = document.getElementById('timeUnit').value;
    if (!scheduleTime || scheduleTime <= 0) {
        alert('Please enter a positive schedule time (greater than zero)');
        return;
    }

    let interval;
    switch (timeUnit) {
        case 'minutes':
            interval = scheduleTime * 60 * 1000;
            break;
        case 'hours':
            interval = scheduleTime * 60 * 60 * 1000;
            break;
        case 'days':
            interval = scheduleTime * 24 * 60 * 60 * 1000;
            break;
        default:
            interval = scheduleTime * 60 * 1000;
    }

    logMessage(`Starting schedule with interval: ${scheduleTime} ${timeUnit}`);

    scheduleInterval = setInterval(async () => {
        try {
            logMessage('Searching for new event to export...');
            const response = await fetch('/start-schedule-misp/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const result = await response.json();
                logMessage(result.message);
            } else {
                const errorText = await response.text();
                logMessage(`Error exporting event: ${response.status} - ${errorText}`);
            }
        } catch (error) {
            logMessage('Error exporting event: ' + error);
        }
    }, interval);
}

function stopSchedule() {
    if (scheduleInterval) {
        clearInterval(scheduleInterval);
        scheduleInterval = null;
        logMessage('Schedule stopped.');
    } else {
        logMessage('No active schedule to stop.');
    }
}
