from django.shortcuts import render
from django.http import JsonResponse
import json
import os
import signal
import subprocess
import time
import threading
from datetime import datetime
from django.views.decorators.http import require_http_methods
import asyncio
from channels.layers import get_channel_layer
from django.views.decorators.csrf import csrf_exempt
from pathlib import Path
import requests
import urllib3
from dotenv import load_dotenv
from .utils import get_interfaces

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_dir = Path(__file__).resolve().parent.parent.parent

global_hours = 0
global_interface = None 
global_config_file = None
global_capture_type = None
global_action = None
global_daq_module = "afpacket"
global_ids_pid = None
global_ips_pid = None
ruleset_dir = "/usr/local/etc/rules/"
snort_conf_path = '/usr/local/etc/snort/snort.lua'
load_dotenv()

def homepage(request):
    return render(request, 'dashboard/homepage.html')

def generate_rules(request):
    return render(request, 'dashboard/gen_rules.html')

def run_ids_ips(request):
    return render(request, 'dashboard/run_ids_ips.html')

def open_log_analyzer(request):
    return render(request, 'dashboard/log_analyzer.html')

def misp_extension(request):
    return render(request, 'dashboard/misp_extension.html')

@require_http_methods(["GET"])
def get_interfaces_list(request):
    interfaces = get_interfaces()
    return JsonResponse({'interfaces': interfaces})

def validate_rule(rule):
    """Validate Snort rule syntax"""
    required_components = ['alert', 'log', 'pass', 'drop', 'reject']  # Valid actions
    protocols = ['tcp', 'udp', 'icmp', 'ip']
    
    # Basic structure check
    if not rule or not isinstance(rule, str):
        return False, "Invalid rule format"
        
    parts = rule.split()
    if len(parts) < 7:  # Minimum components for a valid rule
        return False, "Rule missing required components"
        
    # Validate action
    if parts[0] not in required_components:
        return False, "Invalid action"
        
    # Validate protocol
    if parts[1] not in protocols:
        return False, "Invalid protocol"
        
    # Check for basic rule structure (->)
    if '->' not in rule:
        return False, "Missing direction operator (->)"
        
    # Check for rule options (enclosed in parentheses)
    if not (rule.count('(') == 1 and rule.count(')') == 1):
        return False, "Invalid rule options format"
        
    # Validate msg field existence
    if 'msg:' not in rule:
        return False, "Missing msg field"
        
    # Validate sid field existence
    if 'sid:' not in rule:
        return False, "Missing sid field"
    
    return True, "Rule validation successful"

@csrf_exempt
def save_rule(request):
    global ruleset_dir
    if request.method == 'POST':
        try:
            rule = request.POST.get('rule', '')
            if rule:
                # Validate rule
                is_valid, message = validate_rule(rule)
                if not is_valid:
                    return JsonResponse({'error': f'Invalid rule: {message}'}, status=400)

                # Convert escaped double quotes back to regular quotes
                rule = rule.replace('\\"', '"')

                # Check priority level and action
                priority_match = rule.find('priority:')
                action = rule.split()[0]
                is_high_priority = False
                needs_drop_action = False

                if priority_match != -1:
                    priority_str = rule[priority_match:].split(';')[0]
                    priority_num = ''.join(filter(str.isdigit, priority_str))
                    is_high_priority = priority_num in ['1', '2']
                    needs_drop_action = is_high_priority and action != 'drop'

                # Define the paths to the files
                local_path = os.path.join(ruleset_dir, 'local.rules')
                ips_path = os.path.join(ruleset_dir, 'misp-result/ips.rules')

                # Save to local.rules
                command = f"echo '{rule}' | sudo tee -a {local_path} > /dev/null"
                subprocess.run(command, shell=True, check=True, executable='/bin/bash')

                # Handle high priority rules
                if needs_drop_action:
                    drop_rule = rule.replace(action, 'drop', 1)
                    command = f"echo '{drop_rule}' | sudo tee -a {ips_path} > /dev/null"
                    subprocess.run(command, shell=True, check=True, executable='/bin/bash')

                response_message = 'Rule saved successfully'
                if needs_drop_action:
                    response_message = f'Rule saved with priority {priority_num}'

                return JsonResponse({
                    'message': response_message,
                    'ok': True,
                    'is_high_priority': is_high_priority,
                    'needs_drop_action': needs_drop_action
                })
            else:
                return JsonResponse({'error': 'No rule provided'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Following the timer to stop snort
def stop_snort_after_hours(pid, hours):
    """Helper function to stop Snort after specified hours"""
    time.sleep(hours * 3600)  # Convert hours to seconds
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # Process already terminated

def gen_command_line(alert_path):
    global global_hours
    global global_interface
    global global_config_file
    global global_capture_type
    global global_action
    command = ['snort']  # Add sudo
    # print(f"Capture type: {global_capture_type}") 
    if global_capture_type == "IDS":
        if global_ids_pid:
            return "false"
        command.extend([
                '-i', global_interface,
                '-c', global_config_file,
                '-l', alert_path,
                '-A', 'alert_fast',
                '-k', 'none',
                '-y',
            ])
    elif global_capture_type =="IPS":
        if global_ips_pid:
            return "false"
        command.extend([
            '-Q',
            '--daq', global_daq_module,
            '--daq-mode', 'inline',
            '-i', f'{global_interface}:eth1',
            '-c', global_config_file,
            '-l', alert_path,
            '-A', 'alert_fast',
            # '-k', 'none',
            # '-y',
        ])
    else:
        return JsonResponse({'error': f'Invalid Capture type'}, status=400)
    return command

@require_http_methods(["POST"])
def run_snort(request):
    global global_hours, global_interface, global_config_file
    global global_capture_type, global_action
    global global_ids_pid, global_ips_pid

    # Create specific directories
    # user = os.environ.get('USER')
    base_path = "log"
    alert_path = os.path.join(base_path, "alert_fast")
    
    # Create directories with proper permissions
    os.makedirs(alert_path, mode=0o755, exist_ok=True)
    os.chmod(alert_path, 0o755)

    try:
        data = json.loads(request.body)
        global_hours = float(data.get('hours', 0))
        global_interface = data.get('interface')
        global_config_file = data.get('config_file') 
        global_capture_type = data.get('capture_type')
        global_action = data.get('action')
        # Generate timestamped log filename
        # timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = "alert_fast.txt"
        log_file_path = os.path.join(alert_path, log_filename)
        
        os.environ['SNORT_LOG_FILE'] = log_filename

        # Modified Snort command
        command = gen_command_line(alert_path)
        # prevent dupplicate snort process
        if command == "false":
            return JsonResponse({'error': 'Snort is already running'}, status=400)
    
        print(f"Alert/Log directory path: {log_file_path}")
        print(f"Received parameters: hours={global_hours}, interface={global_interface}, config={global_config_file}, type={global_capture_type}, action={global_action}")
        print(f"Command: {' '.join(command)}")
    
        if global_action == 'start':
            # Check if Snort is available
            try:
                test = subprocess.run(['snort', '--version'], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                print("Snort version check...", test.stdout)
            except subprocess.CalledProcessError as e:
                return JsonResponse({'error': f'Snort not available: {str(e)}'}, status=500)
            # Create a new session for the process
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # This replaces preexec_fn=os.setsid
                bufsize=1,
                universal_newlines=True
            )
            
            # Check immediate errors
            time.sleep(2)
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                error_msg = f"Snort failed to start.\nStdout: {stdout}\nStderr: {stderr}"
                return JsonResponse({'error': error_msg}, status=500)

            # # Store only the main Snort process PID
            # main_pid = None
            # try:
            #     # Use ps command to find the actual Snort process
            #     ps_output = subprocess.check_output(['ps', '-o', 'pid,ppid,command', '--no-headers'], 
            #                                      universal_newlines=True)
            #     for line in ps_output.splitlines():
            #         if 'snort' in line and not 'sudo' in line:
            #             main_pid = int(line.split()[0])
            #             break
            # except Exception as e:
            #     print(f"Error finding main Snort PID: {e}")
                # main_pid = process.pid
            # print("Test 1" + main_pid)
            
            if global_capture_type == "IDS":
                global_ids_pid = process.pid
                request.session['snort_ids_pid'] = process.pid
            elif global_capture_type == "IPS":
                global_ips_pid = process.pid
                request.session['snort_ips_pid'] = process.pid
            request.session['log_file'] = log_file_path
            # Start output monitoring thread
            def monitor_output():
                channel_layer = get_channel_layer()
                retry_count = 0
                max_retries = 30
                buffer_size = 4096  # Optimal buffer size for reading
                last_check = time.time()
                check_interval = 0.05  # 50ms interval for process checks

                # Wait for log file with exponential backoff
                while not os.path.exists(log_file_path):
                    if retry_count >= max_retries:
                        print(f"Error: Log file {log_file_path} not found after {max_retries} attempts")
                        return
                    time.sleep(min(0.1 * (2 ** retry_count), 1.0))  # Exponential backoff with max 1 second
                    retry_count += 1

                try:
                    # Use buffered IO for better performance
                    with open(log_file_path, 'r', buffering=buffer_size) as f:
                        # Seek to end of file
                        f.seek(0, 2)
                        
                        # Batch process alerts
                        pending_alerts = []
                        max_batch_size = 10
                        
                        while True:
                            # Process available lines
                            while len(pending_alerts) < max_batch_size:
                                line = f.readline()
                                if not line:
                                    break
                                pending_alerts.append(line.strip())

                            # Send batch of alerts if available
                            if pending_alerts:
                                asyncio.run(channel_layer.group_send(
                                    "snort_console",
                                    {
                                        "type": "send_console_output",
                                        "output": pending_alerts
                                    }
                                ))
                                pending_alerts = []

                            # Check process status periodically instead of every iteration
                            current_time = time.time()
                            if current_time - last_check >= check_interval:
                                if global_ids_pid is None and global_ips_pid is None:
                                    break
                                last_check = current_time

                            # Adaptive sleep based on activity
                            if not pending_alerts:
                                time.sleep(0.05)  # Sleep longer when inactive
                            else:
                                time.sleep(0.01)  # Sleep less when active

                except FileNotFoundError:
                    print(f"Error: Log file {log_file_path} was removed")
                except Exception as e:
                    print(f"Error monitoring log file: {str(e)}")
                finally:
                    # Flush any remaining alerts
                    if pending_alerts:
                        try:
                            asyncio.run(channel_layer.group_send(
                                "snort_console",
                                {
                                    "type": "send_console_output",
                                    "output": pending_alerts
                                }
                            ))
                        except Exception:
                            pass

            monitor_thread = threading.Thread(target=monitor_output, daemon=True)
            monitor_thread.start()

            # Start timer thread
            timer_thread = threading.Thread(target=stop_snort_after_hours, args=(process.pid, global_hours), daemon=True)
            timer_thread.start()
            
            return JsonResponse({
                'message': f'Snort started successfully in {global_capture_type} mode and will run for {global_hours} hours. Logging to {log_file_path}',
                'pid': process.pid,
                'log_file': log_file_path
            }, status=200)
        else: # nếu action != start 
            return JsonResponse({'error': 'No running Snort process found'}, status=404)
    except ValueError as e:
        return JsonResponse({'error': 'Invalid hours format'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def switch_ids_to_ips(request):
    global global_hours
    global global_interface
    global global_config_file
    global global_capture_type
    global global_action
    global global_ips_pid
    global global_ids_pid
    try:
        pid = request.session.get('snort_ips_pid')
        if pid:
            return JsonResponse({'error': 'IPS mode process is running'})
        
        # Get the base alert path, not the full file path
        alert_path = "log/alert_fast"  # Use the directory path only
        
        global_capture_type = "IPS"
        command = gen_command_line(alert_path)
        
        print(f"Starting Snort in IPS mode with command: {' '.join(command)}")

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Check for immediate errors
        time.sleep(2)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            error_msg = f"Snort failed to start in IPS mode.\nStdout: {stdout}\nStderr: {stderr}"
            print("DEBUG: " + error_msg)
            return JsonResponse({'error': error_msg}, status=500)

        # Save new process PID
        global_ips_pid = process.pid
        request.session['snort_ips_pid'] = global_ips_pid
        
        # Terminate the IDS process
        ids_pid = request.session.get('snort_ids_pid')
        if ids_pid:
            try:
                os.kill(ids_pid, signal.SIGTERM)
                del request.session['snort_ids_pid']
                
            except ProcessLookupError:
                del request.session['snort_ids_pid']
        global_ids_pid = None
        
        return JsonResponse({
            'message': f'Snort successfully switched to IPS mode. IPS PID: {global_ips_pid}',
            'pid': global_ips_pid,
            'log_file': os.path.join(alert_path, "alert_fast.txt")
        }, status=200)
      
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
# stop ids or ips function
@require_http_methods(["POST"])
def stop_ids(request):
    global global_ids_pid
    try:
        if global_ids_pid:
            tmp = global_ids_pid
            try:
               # Kill process group
                pgid = os.getpgid(global_ids_pid)
                os.killpg(pgid, signal.SIGTERM)
                
                # Wait briefly and verify
                time.sleep(1)
                
                # Force kill if still running
                try:
                    os.kill(global_ids_pid, 0)  # Check if process exists
                    os.killpg(pgid, signal.SIGKILL)  # Force kill if still running
                except ProcessLookupError:
                    pass  # Process already terminated
                
                global_ids_pid = None
                del request.session['snort_ids_pid']
                return JsonResponse({
                    'message': 'Snort process stopped successfully IDS process',
                    'pid': tmp
                })
            except ProcessLookupError:
                del request.session['snort_ids_pid']
                return JsonResponse({
                    'message': 'Snort IDS process was already terminated',
                    'pid': tmp
                })
        else:
            return JsonResponse({
                'error': 'No running Snort IDS process found'
            }, status=404)
            
    except Exception as e:
        return JsonResponse({
            'error': f'Error stopping Snort IDS: {str(e)}'
        }, status=500)
    
@require_http_methods(["POST"])
def stop_ips(request):
    global global_ips_pid
    try:
        if  global_ips_pid or request.session.get('snort_ips_pid'):
            tmp = global_ips_pid
            try:
                os.kill(global_ips_pid, signal.SIGTERM)
                del request.session['snort_ips_pid']
                global_ips_pid = None
                return JsonResponse({
                    'message': 'Snort process stopped successfully IPS process',
                    'pid': tmp
                })
            except ProcessLookupError:
                del request.session['snort_ips_pid']
                return JsonResponse({
                    'message': 'Snort IPS process was already terminated',
                    'pid': tmp
                })
        else:
            return JsonResponse({
                'error': 'No running Snort IPS mode process found'
            }, status=404)
    except Exception as e:
        return JsonResponse({
            'error': f'Error stopping Snort IPS: {str(e)}'
        }, status=500)
    
# views.py - Update check_snort_status function
def check_snort_status(request):
    global global_ids_pid, global_ids_pid    
    status = {
        'ids_running': False,
        'ips_running': False,
        'running': False
    }

    def check_process(pid):
        try:
            if pid:
                os.kill(int(pid), 0)  # Check if process exists
                return True
        except (OSError, ProcessLookupError, ValueError):
            return False
        return False

    # Check IDS status
    if check_process(global_ids_pid):
        status['ids_running'] = True
        status['ids_pid'] = global_ids_pid
        status['running'] = True
    elif global_ids_pid:
        del request.session['snort_ids_pid']

    # Check IPS status 
    if check_process(global_ips_pid):
        status['ips_running'] = True
        status['ips_pid'] = global_ips_pid
        status['running'] = True
    elif global_ips_pid:
        del request.session['snort_ips_pid']

    return JsonResponse(status)

###################################### MISP #########################################
def get_tag_id(tag_name, headers, misp_url, verify_cert):
    tags_url = f"{misp_url}/tags/index"
    response = requests.get(tags_url, headers=headers, verify=verify_cert)
    if (response.status_code == 200):
        tags = response.json()
        for tag in tags:
            if tag['name'] == tag_name:
                return tag['id']
    return None

@csrf_exempt
@require_http_methods(["POST"])
def start_schedule_misp(request):
    global ruleset_dir
    try:
        MISP_URL = os.getenv('MISP_URL', 'https://localhost')
        API_KEY = os.getenv('API_KEY')
        VERIFY_CERT = False

        headers = {
            "Authorization": API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # Function to get the latest event that is not tagged as exported
        def get_latest_event(misp_url, headers, verify_cert):
            events_url = f"{misp_url}/events/restSearch"
            data = {
                "tags": "!exported",
                "limit": 1,
                "published": True,
                "returnFormat": "json",
                "sort": "date DESC"  # Sort by date in descending order
            }
            response = requests.post(events_url, headers=headers, json=data, verify=verify_cert)
            if response.status_code == 200:
                events = response.json()
                if 'response' in events and events['response']:
                    return events['response'][0]
                else:
                    print("No events found with the specified criteria.")
                    return None
            else:
                print(f"Error fetching events: {response.status_code} - {response.text}")
                return None

        # Function to export event to Snort rules
        def export_event_to_snort(event):
            event_id = event['Event']['id']
            tags = [tag['name'] for tag in event['Event']['Tag']]
            event_category = classify_tags(tags)
            threat_level = event['Event'].get('threat_level_id')
            is_high_threat = threat_level == '1'

            attributes_url = f"{MISP_URL}/attributes/restSearch"
            attributes_data = {
                "eventid": event_id,
                "returnFormat": "snort",
                "page": 1
            }
            threat_level_dict = {
                    "1": "High",
                    "2": "Medium",
                    "3": "Low",
                    "4": "Unknown"
                }

            response = requests.post(attributes_url, headers=headers, json=attributes_data, verify=VERIFY_CERT)
            if response.status_code == 200:
                snort_rules = response.text
                rules = [line for line in snort_rules.splitlines() if line and not line.startswith('#')]
                rule_count = len(rules)

                if rule_count > 0:
                    output_dir = os.path.join(ruleset_dir, 'misp-result')
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)

                    # Write to categorized rules file
                    cate_file_name = f"{event_category}.rules"
                    file_path = os.path.join(output_dir, cate_file_name)
                    with open(file_path, 'a') as file:
                        file.write("\n".join(rules) + "\n")

                    # If high threat, also write to ips.rules with "drop"
                    ips_file_name = None
                    
                    if is_high_threat:
                        ips_file_name = "ips.rules"
                        ips_file_path = os.path.join(output_dir, ips_file_name)
                        drop_rules = [line.replace("alert", "drop", 1) for line in rules]
                        with open(ips_file_path, 'a') as file:
                            file.write("\n".join(drop_rules) + "\n")
                    # Get the tag ID for 'exported'
                    tag_id = os.getenv('EXPORTED_TAG_ID')
                    if not tag_id:
                        return JsonResponse({'error': 'Failed to find tag ID for "exported"'}, status=500)
                    # Tag the event as exported
                    tag_url = f"{MISP_URL}/events/addTag/{event_id}/{tag_id}/local:1"
                    tag_response = requests.post(tag_url, headers=headers, verify=VERIFY_CERT)
                    if tag_response.status_code != 200:
                        return JsonResponse({'error': f"Failed to tag event as exported: {tag_response.status_code} - {tag_response.text}"}, status=tag_response.status_code)
                    
                    if ips_file_name is None:
                        return JsonResponse({
                            'message': f'{rule_count} Snort rules from event ID {event_id} (Threat level: {threat_level_dict[str(threat_level)]}) appended to file {cate_file_name}',
                            'file_path': file_path
                        }, status=200)
                    else:
                        return JsonResponse({
                        'message': f'{rule_count} Snort rules from event ID {event_id} (Threat level: {threat_level_dict[str(threat_level)]}) appended to file {cate_file_name} and {ips_file_name}' ,
                        'file_path': file_path
                    }, status=200)
                else:
                    tag_id = os.getenv('EXPORTED_TAG_ID')
                    if not tag_id:
                        return JsonResponse({'error': 'Failed to find tag ID for "exported"'}, status=500)
                    # Tag the event as exported
                    tag_url = f"{MISP_URL}/events/addTag/{event_id}/{tag_id}/local:1"
                    tag_response = requests.post(tag_url, headers=headers, verify=VERIFY_CERT)
                    return JsonResponse({'message': f'No valid Snort rules from event ID {event_id} to append'}, status=200)
            else:
                return JsonResponse({'error': f"Error exporting event: {response.status_code} - {response.text}"}, status=response.status_code)

        event = get_latest_event(MISP_URL, headers, VERIFY_CERT)
        if event:
            return export_event_to_snort(event)
        else:
            return JsonResponse({'message': 'No new event to export to Snort'}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def export_event(request):
    global ruleset_dir
    try:
        data = json.loads(request.body)
        event_id = data.get('event_id')
        if not event_id:
            return JsonResponse({'error': 'Event ID is required'}, status=400)

        MISP_URL = os.getenv('MISP_URL', 'https://localhost') 

        API_KEY = os.getenv('API_KEY')
        VERIFY_CERT = False

        headers = {
            "Authorization": API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # First request to get event information and check tags
        event_url = f"{MISP_URL}/events/view/{event_id}"
        event_response = requests.get(event_url, headers=headers, verify=VERIFY_CERT)

        if event_response.status_code == 200:
            event_data = event_response.json()
            if 'Event' in event_data:
                tags = [tag['name'] for tag in event_data['Event']['Tag']]
                if 'exported' in tags:
                    return JsonResponse({'message': 'Event already exported!'}, status=200)
                
                event_category = classify_tags(tags)
                print("Event Category:", event_category)

                # Check if the event has a high threat model
                threat_level_dict = {
                    "1": "High",
                    "2": "Medium",
                    "3": "Low",
                    "4": "Unknown"
                }
                threat_level = event_data['Event'].get('threat_level_id')
                is_high_threat = threat_level == '1'  # Assuming '1' indicates high threat

                # Second request to get snort rules if tags are valid
                attributes_url = f"{MISP_URL}/attributes/restSearch"
                attributes_data = {
                    "eventid": event_id,
                    "returnFormat": "snort",
                    "page": 1
                }

                response = requests.post(attributes_url, headers=headers, json=attributes_data, verify=VERIFY_CERT)

                if response.status_code == 200:
                    snort_rules = response.text
                    rules = [line for line in snort_rules.splitlines() if line and not line.startswith('#')]
                    rule_count = len(rules)

                    if rule_count > 0:
                        output_dir = os.path.join(ruleset_dir, 'misp-result')
                        if not os.path.exists(output_dir):
                            os.makedirs(output_dir)

                        # Write to categorized rules file
                        cate_file_name = f"{event_category}.rules"
                        file_path = os.path.join(output_dir, cate_file_name)
                        with open(file_path, 'a') as file:
                            file.write("\n".join(rules) + "\n")

                        # If high threat, also write to ips.rules with "drop"
                        ips_file_name = None
                        if is_high_threat:
                            ips_file_name = "ips.rules"
                            ips_file_path = os.path.join(output_dir, ips_file_name)
                            drop_rules = [line.replace("alert", "drop", 1) for line in rules]
                            with open(ips_file_path, 'a') as file:
                                file.write("\n".join(drop_rules) + "\n")

                        # Get the tag ID for 'exported'
                        tag_id = os.getenv('EXPORTED_TAG_ID')
                        if not tag_id:
                            return JsonResponse({'error': 'Failed to find tag ID for "exported"'}, status=500)

                        # Tag the event as exported
                        tag_url = f"{MISP_URL}/events/addTag/{event_id}/{tag_id}/local:1"
                        tag_response = requests.post(tag_url, headers=headers, verify=VERIFY_CERT)
                        if tag_response.status_code != 200:
                            return JsonResponse({'error': f"Failed to tag event as exported: {tag_response.status_code} - {tag_response.text}"}, status=tag_response.status_code)
                        if ips_file_name is None:
                            return JsonResponse({
                                'message': f'{rule_count} Snort rules from event ID {event_id} (Threat level: {threat_level_dict[str(threat_level)]}) appended to file {cate_file_name}',
                                'file_path': file_path
                            }, status=200)
                        else:
                            return JsonResponse({
                            'message': f'{rule_count} Snort rules from event ID {event_id} (Threat level: {threat_level_dict[str(threat_level)]}) appended to file {cate_file_name} and {ips_file_name}' ,
                            'file_path': file_path
                        }, status=200)
                    else:
                        # Get the tag ID for 'exported'
                        tag_id = os.getenv('EXPORTED_TAG_ID')
                        if not tag_id:
                            return JsonResponse({'error': 'Failed to find tag ID for "exported"'}, status=500)

                        # Tag the event as exported
                        tag_url = f"{MISP_URL}/events/addTag/{event_id}/{tag_id}/local:1"
                        tag_response = requests.post(tag_url, headers=headers, verify=VERIFY_CERT)
                        if tag_response.status_code != 200:
                            return JsonResponse({'error': f"Failed to tag event as exported: {tag_response.status_code} - {tag_response.text}"}, status=tag_response.status_code)
                        return JsonResponse({'message': f'No valid Snort rules from event ID {event_id} to append'}, status=200)
                else:
                    return JsonResponse({'error': f"Error exporting event: {response.status_code} - {response.text}"}, status=response.status_code)
            else:
                return JsonResponse({'error': "'Event' key not found in the response data"}, status=400)
        else:
            return JsonResponse({'error': f"Error fetching event: {event_response.status_code} - {event_response.text}"}, status=event_response.status_code)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Define the categories and their priorities
categories = {
    'spyware-adware': ['spyware', 'adware'],
    'phishing': ['phishing'],
    'exploit': ['exploit'],
    'ransomware': ['ransomware', 'ransom'],
    'malware': ['malware'],
    'apt': ['apt', 'apt-', 'apt0', 'apt1', 'apt2', 'apt3', 'apt4', 'apt5', 'apt6', 'apt7', 'apt8', 'apt9']
}

def classify_tags(tags):
    for category, keywords in categories.items():
        for tag in tags:
            tag_lower = tag.lower()
            if any(keyword in tag_lower for keyword in keywords):
                return category
    return 'unclassified'

######################################################################
def get_rule_count(file_path):
    try:
        with open(file_path, 'r') as f:
            # Count lines that aren't empty or comments
            return sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
    except Exception:
        return 0
    
@require_http_methods(["GET"])
def get_ruleset_status(request):
    global ruleset_dir
    try:
        rules_info = []
        # Check both main rules directory and misp-rules directory
        directories = [
            ruleset_dir, #/rules/
            os.path.join(ruleset_dir, 'misp-result') # .../rules/misp-result
        ]
        
        for directory in directories:
            if os.path.exists(directory):
                for file_name in os.listdir(directory):
                    if file_name.endswith('.rules'):
                        file_path = os.path.join(directory, file_name)
                        # Check if file is enabled (not commented out in snort.lua)
                        status = check_rule_status(file_path) # true for enable and false for disable
                        count = get_rule_count(file_path)
                        
                        rules_info.append({
                            'name': file_name,
                            'status': status,
                            'count': count
                        })
        
        return JsonResponse(rules_info, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def check_rule_status(file_path):
    global ruleset_dir
    global snort_conf_path
    try:
        
        with open(snort_conf_path, 'r') as f:
            content = f.read()
            # Check if the include line for this rule is commented out
            rule_include = f'include = "{file_path}"' 
            return rule_include in content and not f'    -- {rule_include}' in content
    except Exception:
        return False

@csrf_exempt
@require_http_methods(["POST"])
def toggle_rule_status(request):
    global ruleset_dir
    global snort_conf_path
    try:
        data = json.loads(request.body)
        rule_name = data.get('rule_name')
        if not rule_name:
            return JsonResponse({'error': 'Rule name is required'}, status=400)
        
        
        with open(snort_conf_path, 'r') as f:
            lines = f.readlines()
        
        # Find and toggle the rule's include line
        for i, line in enumerate(lines):
            if rule_name in line:
                if line.strip().startswith('--'):
                    # Uncomment the line
                    lines[i] = '    ' + line[7:]
                else:
                    # Comment out the line
                    lines[i] = line[:4] + '-- ' + line[4:]
                    print(lines[i])
                
                # Write changes back to file
                with open(snort_conf_path, 'w') as f:
                    f.writelines(lines)
                
                return JsonResponse({'success': True})
        
        return JsonResponse({'error': 'Rule not found in configuration'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)