from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import json
import os
import signal
import subprocess
import time, threading
from datetime import datetime
from django.views.decorators.http import require_http_methods
import asyncio
from channels.layers import get_channel_layer
from django.views.decorators.csrf import csrf_exempt
import os
from pathlib import Path

base_dir = Path(__file__).resolve().parent.parent.parent
# define global variables
global_hours = 0
global_interface = None 
global_config_file = None
global_capture_type = None
global_action = None
global_daq_module = "afpacket"

def homepage(request):
    return render(request, 'dashboard/homepage.html')

def generate_rules(request):
    return render(request, 'dashboard/gen_rules.html')

def run_ids_ips(request):
    return render(request, 'dashboard/run_ids_ips.html')

def open_log_analyzer(request):
    return render(request, 'dashboard/log_analyzer.html')

@csrf_exempt
def save_rule(request):
    if request.method == 'POST':
        try:
            rule = request.POST.get('rule', '')
            if rule:
                # Define the path to the WSL file
                file_path = '/etc/snort/rules/local.rules'
                
                # Prepare the command to append to the file
                command = f'echo "{rule}" | sudo tee -a {file_path} > /dev/null'
                
                # Execute the command
                subprocess.run(command, shell=True, check=True, executable='/bin/bash')

                return JsonResponse({'message': f'Rule saved: {rule}', 'ok': True})
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
    command = ['sudo', 'snort']  # Add sudo
    # print(f"Capture type: {global_capture_type}") 
    if global_capture_type == "IDS":
        command.extend([
                '-i', global_interface,
                '-c', global_config_file,
                '-l', alert_path,
                '-A', 'alert_fast',  
                '-k', 'none',
                '-y',
            ])
    elif global_capture_type =="IPS":
        command.extend([
            '--daq', global_daq_module,
            '--daq-mode', 'inline',
            '-i', global_interface,
            '-c', global_config_file,
            '-l', alert_path,
            '-A', 'alert_fast',
            '-k', 'none',
            '-y',
        ])
    else:
        return JsonResponse({'error': f'Invalid Capture type'}, status=400)
    return command

@require_http_methods(["POST"])
def run_ids(request):
    global global_hours
    global global_interface
    global global_config_file
    global global_capture_type
    global global_action
    # Create specific directories
    # user = os.environ.get('USER')
    base_path = f"log"
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
        # command = ['snort']
        # Debug info
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

            # Start Snort with output capture
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Check immediate errors
            time.sleep(2)
            if process.poll() is not None:
                # Process failed to start or terminated
                stdout, stderr = process.communicate()
                error_msg = f"Snort failed to start.\nStdout: {stdout}\nStderr: {stderr}"
                print("DEBUG: " + error_msg)
                return JsonResponse({'error': error_msg}, status=500)

            pid = process.pid
            request.session['snort_pid'] = pid
            request.session['log_file'] = log_file_path

            # Start output monitoring thread
            def monitor_output():
                channel_layer = get_channel_layer()
                while not os.path.exists(log_file_path):
                    time.sleep(1)
                
                with open(log_file_path, 'r') as f:
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue
                        print(f"Alert: {line.strip()}")
                        # Send alert through WebSocket
                        asyncio.run(channel_layer.group_send(
                            "snort_console",
                            {
                                "type": "send_console_output",
                                "output": line.strip()
                            }
                        ))

            monitor_thread = threading.Thread(target=monitor_output, daemon=True)
            monitor_thread.start()

            # Start timer thread
            timer_thread = threading.Thread(
                target=stop_snort_after_hours,
                args=(pid, global_hours),
                daemon=True
            )
            timer_thread.start()
            return JsonResponse({
                'message': f'Snort started successfully in {global_capture_type} mode and will run for {global_hours} hours. Logging to {log_file_path}',
                'pid': pid,
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
    try:
        # Retrieve current running Snort PID
        pid = request.session.get('snort_pid')
        if not pid:
            return JsonResponse({'error': 'No running Snort process found'}, status=404)

        # Stop the existing IDS process
        print(f"Stopping existing IDS process with PID: {pid}")
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            return JsonResponse({'error': f'Failed to stop IDS process: {str(e)}'}, status=500)

        # Wait for the process to terminate
        time.sleep(2)  # Adjust this wait time if necessary
        
        # Get the base alert path, not the full file path
        alert_path = "log/alert_fast"  # Use the directory path only
        
        global_capture_type = "IPS"
        command = gen_command_line(alert_path)
        
        print(f"Restarting Snort in IPS mode with command: {' '.join(command)}")

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
        new_pid = process.pid
        request.session['snort_pid'] = new_pid

        return JsonResponse({
            'message': f'Snort successfully switched to IPS mode. New PID: {new_pid}',
            'pid': new_pid,
            'log_file': os.path.join(alert_path, "alert_fast.txt")
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
@require_http_methods(["POST"])
def stop_ids(request):
    try:
        pid = request.session.get('snort_pid')
        #print(pid)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                del request.session['snort_pid']
                return JsonResponse({
                    'message': 'Snort process stopped successfully',
                    'pid': pid
                })
            except ProcessLookupError:
                del request.session['snort_pid']
                return JsonResponse({
                    'message': 'Snort process was already terminated',
                    'pid': pid
                })
        else:
            return JsonResponse({
                'error': 'No running Snort process found'
            }, status=404)
            
    except Exception as e:
        return JsonResponse({
            'error': f'Error stopping Snort: {str(e)}'
        }, status=500)
    
def check_snort_status(request):
    pid = request.session.get('snort_pid')
    if pid:
        try:
            # Check if process is running
            os.kill(pid, 0)  # This doesn't kill the process, just checks if it exists
            return JsonResponse({'running': True, 'pid': pid})
        except OSError:
            # Process not found
            del request.session['snort_pid']
            return JsonResponse({'running': False})
    return JsonResponse({'running': False})