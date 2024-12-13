function toggleTCPState() {
    const direction = document.getElementById('tcp_direction').value;
    const tcpState = document.getElementById('tcp_state');

    // Enable tcpState dropdown if a direction is selected, otherwise disable it
    tcpState.disabled = direction === '';
}

function toggleHttpFields() {
    const httpMethod = document.getElementById('http_request_method').value;
    const httpResponseCode = document.getElementById('http_response_code').value;

    document.getElementById('http_request_method').style.display = httpResponseCode ? 'none' : 'inline-block';
    document.getElementById('http_response_code').style.display = httpMethod ? 'none' : 'inline-block';
}

function updateFields() {
    const protocol = document.getElementById('protocol').value;
    const tcp = document.getElementById('tcp_field');
    const udp = document.getElementById('udp_field');
    const icmp = document.getElementById('icmp_field');
    if (protocol === 'tcp') {
        tcp.style.display = 'block';
        udp.style.display = 'none';
        icmp.style.display = 'none';
    } else if (protocol === 'udp') {
        tcp.style.display = 'none';
        udp.style.display = 'block';
        icmp.style.display = 'none';
    } else if (protocol === 'icmp') {
        tcp.style.display = 'none';
        udp.style.display = 'none';
        icmp.style.display = 'block';
    }
}

// Add this new validation function
function validateRuleInputs() {
    const errors = [];

    // Required fields validation
    const action = document.getElementById('action').value;
    const protocol = document.getElementById('protocol').value;
    const sid = document.getElementById('sid').value;
    const msg = document.getElementById('msg').value;

    if (!action) errors.push("Action is required");
    if (!protocol) errors.push("Protocol is required");
    if (!sid) errors.push("SID is required");
    if (!msg) errors.push("Message is required");

    // IP address validation
    const srcIp = document.getElementById('src_ip').value;
    const destIp = document.getElementById('dest_ip').value;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^any$/;

    if (srcIp && srcIp !== 'any' && !ipRegex.test(srcIp)) {
        errors.push("Invalid source IP address");
    }
    if (destIp && destIp !== 'any' && !ipRegex.test(destIp)) {
        errors.push("Invalid destination IP address");
    }

    // Port validation
    const srcPort = document.getElementById('src_port').value;
    const destPort = document.getElementById('dest_port').value;
    const portRegex = /^([1-9][0-9]{0,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]|any)$/;

    if (srcPort && srcPort !== 'any' && !portRegex.test(srcPort)) {
        errors.push("Invalid source port (must be 1-65535 or 'any')");
    }
    if (destPort && destPort !== 'any' && !portRegex.test(destPort)) {
        errors.push("Invalid destination port (must be 1-65535 or 'any')");
    }

    // SID and Rev validation
    if (sid && !(/^\d+$/.test(sid))) {
        errors.push("SID must be a positive number");
    }
    const rev = document.getElementById('rev').value;
    if (rev && !(/^\d+$/.test(rev))) {
        errors.push("Revision must be a positive number");
    }

    return errors;
}

// Modify the existing generateSnortRule function to include validation
function generateSnortRule() {
    // Validate inputs first
    const validationErrors = validateRuleInputs();
    if (validationErrors.length > 0) {
        alert('Please fix the following errors:\n' + validationErrors.join('\n'));
        return;
    }

    // Get the values from input fields
    const action = document.getElementById('action').value;
    const protocol = document.getElementById('protocol').value;
    const srcIp = document.getElementById('src_ip').value || 'any';
    const srcPort = document.getElementById('src_port').value || 'any';
    const destIp = document.getElementById('dest_ip').value || 'any';
    const destPort = document.getElementById('dest_port').value || 'any';
    const sid = document.getElementById('sid').value;
    const rev = document.getElementById('rev').value;
    const msg = document.getElementById('msg').value;
    // Properly escape any existing backslashes and quotes
    const escapedMsg = msg.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const classType = document.getElementById('class_type').value;
    const priority = document.getElementById('priority').value;
    const gid = document.getElementById('gid').value;

    // Extra fields for protocol-specific rules
    let protocolOptions = '';
    if (protocol === 'tcp') {
        const httpMethod = document.getElementById('http_request_method').value;
        const httpResponseCode = document.getElementById('http_response_code').value;
        const ack = document.getElementById('ack').checked ? 'A' : '';
        const syn = document.getElementById('syn').checked ? 'S' : '';
        const psh = document.getElementById('psh').checked ? 'P' : '';
        const rst = document.getElementById('rst').checked ? 'R' : '';
        const fin = document.getElementById('fin').checked ? 'F' : '';
        const urg = document.getElementById('urg').checked ? 'U' : '';
        const direction = document.getElementById('tcp_direction').value;
        const tcpState = document.getElementById('tcp_state').value;
        const flags = ack + syn + psh + rst + fin + urg;
        protocolOptions = `${httpMethod ? `content:"${httpMethod}"; http_method; ` : ''}` +
            `${httpResponseCode ? `content:"${httpResponseCode}"; http_stat_code; ` : ''}` +
            `${flags ? 'flags:' + flags + '; ' : ''}` +
            `${direction ? 'flow:' + direction + (tcpState ? ',' + tcpState : '') + '; ' : ''}`;
    } else if (protocol === 'icmp') {
        const icmpType = document.getElementById('itype').value;
        const icmpTypeValue = document.getElementById('itype_value').value;
        const icmpCode = document.getElementById('icode').value;
        const icmpCodeValue = document.getElementById('icode_value').value;

        protocolOptions = `${icmpType ? 'itype:' + (icmpType === '=' ? '' : icmpType) + icmpTypeValue + '; ' : ''}` +
            `${icmpCode ? 'icode:' + (icmpCode === '=' ? '' : icmpCode) + icmpCodeValue + '; ' : ''}`;
    } else if (protocol === 'udp') {
        const direction = document.getElementById('udp_direction').value;
        protocolOptions = direction ? `flow:${direction};` : '';
    }

    // Additional rule options
    const dataSizeOperator = document.getElementById('data_size').value;
    const dataSizeValue = document.getElementById('data_size_value').value;
    const referenceType = document.getElementById('reference').value;
    const referenceValue = document.getElementById('reference_value').value;
    const thresholdType = document.getElementById('threshold_tracking_type').value;
    const trkBy = document.getElementById('trk_by').value;
    const count = document.getElementById('count').value;
    const seconds = document.getElementById('seconds').value;

    // Construct rule options
    let ruleOptions = `(msg:"${escapedMsg}";`;
    if (classType) ruleOptions += ` classtype:${classType};`;
    if (priority) ruleOptions += ` priority:${priority};`;
    if (gid) ruleOptions += ` gid:${gid};`;
    if (sid) ruleOptions += ` sid:${sid};`;
    if (rev) ruleOptions += ` rev:${rev};`;
    if (dataSizeOperator && dataSizeValue) {
        ruleOptions += ` dsize:${dataSizeOperator !== '=' ? dataSizeOperator : ''}${dataSizeValue};`;
    }
    if (referenceType && referenceValue) ruleOptions += ` reference:${referenceType},${referenceValue};`;
    if (thresholdType && trkBy && count && seconds) {
        ruleOptions += ` threshold:${thresholdType}, track ${trkBy}, count ${count}, seconds ${seconds};`;
    }
    if (protocolOptions) {
        ruleOptions += `${protocolOptions}`;
    }
    ruleOptions += ')';

    // Full rule syntax
    const snortRule = `${action} ${protocol} ${srcIp} ${srcPort} -> ${destIp} ${destPort} ${ruleOptions}`;

    // Display generated rule in output div
    document.getElementById('ruleOutput').innerText = snortRule;
}

// Modify the existing saveRuleToFile function to include validation
function saveRuleToFile() {
    const rule = document.getElementById('ruleOutput').innerText.trim();
    if (!rule) {
        alert('Please generate a rule first');
        return;
    }

    fetch('/save-rule/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `rule=${encodeURIComponent(rule)}`,
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.ok) {
                let message = data.message || 'Rule saved successfully.';
                if (data.needs_drop_action) {
                    message += '\nHigh priority threat detected! Rule has been automatically added to IPS rules with DROP action.';
                }
                alert(message);
                loadRulesetStatus(); // Refresh the rules table
            } else {
                alert('Error saving rule: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error saving rule: ' + error.message);
        });
}

function loadRulesetStatus() {
    fetch('/get-ruleset-status/')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.getElementById('rulesTableBody');
            tableBody.innerHTML = '';

            data.forEach(rule => {
                const row = document.createElement('tr');
                row.innerHTML = `
                <td>${rule.name}</td>
                <td><span class="badge ${rule.status ? 'badge-success' : 'badge-danger'}">
                    ${rule.status ? 'Enabled' : 'Disabled'}
                </span></td>
                <td>${rule.count}</td>
                <td>
                    <button onclick="toggleRuleStatus('${rule.name}')" 
                            class="btn btn-sm ${rule.status ? 'btn-danger' : 'btn-success'}">
                        ${rule.status ? 'Disable' : 'Enable'}
                    </button>
                </td>
            `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading ruleset status:', error));
}

function toggleRuleStatus(ruleName) {
    fetch('/toggle-rule-status/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ rule_name: ruleName })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadRulesetStatus(); // Refresh the table
            } else {
                alert('Error toggling rule status: ' + data.error);
            }
        })
        .catch(error => console.error('Error:', error));
}

// Load ruleset status when page loads
document.addEventListener('DOMContentLoaded', loadRulesetStatus);