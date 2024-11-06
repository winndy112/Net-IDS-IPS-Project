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

def stop_snort_after_hours(pid, hours):
    """Helper function to stop Snort after specified hours"""
    time.sleep(hours * 3600)  # Convert hours to seconds
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # Process already terminated
@require_http_methods(["POST"])
def run_ids(request):
    # Create specific directories
    user = os.environ.get('USER')
    base_path = f"/home/{user}/Net-IDS-IPS-Project/Log"
    alert_path = os.path.join(base_path, "alert_fast")
    
    # Create directories with proper permissions
    os.makedirs(alert_path, mode=0o755, exist_ok=True)
    os.chmod(alert_path, 0o755)

    try:
        data = json.loads(request.body)
        hours = float(data.get('hours', 0))
        interface = data.get('interface') 
        config_file = data.get('config_file')
        capture_type = data.get('capture_type')
        action = data.get('action')

        # Generate timestamped log filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"alert_{timestamp}.txt"
        log_file_path = os.path.join(alert_path, log_filename)

        os.environ['SNORT_LOG_FILE'] = log_filename

        # Modified Snort command
        command = ['sudo', 'snort']  # Add sudo
        command.extend([
            '-i', interface,
            '-c', config_file,
            '-l', alert_path,
            '-A', 'alert_fast',  
            '-k', 'none',
            '-y',
        ])

        # Debug info
        print(f"Alert directory: {alert_path}")
        print(f"Command: {' '.join(command)}")

        # Add debug logging
        print(f"Received parameters: hours={hours}, interface={interface}, config={config_file}, type={capture_type}, action={action}")


        # Print the full command for debugging
        print(f"Executing command: {' '.join(command)}")
       
        if action == 'start':
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
            print(pid)
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

            monitor_thread = threading.Thread(target=monitor_output, daemon=True)
            monitor_thread.start()

            # Start timer thread
            timer_thread = threading.Thread(
                target=stop_snort_after_hours,
                args=(pid, hours),
                daemon=True
            )
            timer_thread.start()
            return JsonResponse({
                'message': f'Snort started successfully and will run for {hours} hours. Logging to {log_file_path}',
                'pid': pid,
                'log_file': log_file_path
            }, status=200)
        else:
            
            return JsonResponse({'error': 'No running Snort process found'}, status=404)
    except ValueError as e:
        return JsonResponse({'error': 'Invalid hours format'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@require_http_methods(["POST"])
def stop_ids(request):
    try:
        pid = request.session.get('snort_pid')
        print(pid)
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