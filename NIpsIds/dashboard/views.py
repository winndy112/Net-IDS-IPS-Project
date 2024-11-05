from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import json
import os
import signal
import subprocess
import time, threading
from datetime import datetime
from django.views.decorators.http import require_http_methods

def homepage(request):
    return render(request, 'dashboard/homepage.html')

def generate_rules(request):
    return render(request, 'dashboard/gen_rules.html')

def run_ids_ips(request):
    return render(request, 'dashboard/run_ids_ips.html')

def open_log_analyzer(request):
    return render(request, 'dashboard/log_analyzer.html')

def stop_snort_after_hours(pid, hours):
    """Helper function to stop Snort after specified hours"""
    time.sleep(hours * 3600)  # Convert hours to seconds
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # Process already terminated
@require_http_methods(["POST"])
def run_ids(request):
    path_log = "Sample/"
    os.makedirs(path_log, exist_ok=True)
    
    # Generate filename with current datetime
    filename = f"alert_log.{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    full_path = os.path.join(path_log, filename)
    try:
        data = json.loads(request.body)
        hours = float(data.get('hours', 0))
        interface = data.get('interface') 
        config_file = data.get('config_file')
        capture_type = data.get('capture_type')
        action = data.get('action')

        # Add debug logging
        print(f"Received parameters: hours={hours}, interface={interface}, config={config_file}, type={capture_type}, action={action}")

        # ... existing code ...

        # Build Snort command based on parameters
        command = ['snort']
        
        command.extend([
            '-i', interface,
            '-c', config_file,
            '-l', os.path.abspath(path_log),  # Use absolute path
            '-A', 'fast',
            #'-K', 'csv',
            '-y',
            '-L', filename
        ])

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
            request.session['snort_pid'] = pid
            request.session['log_file'] = full_path

            # Start output monitoring thread
            def monitor_output():
                while True:
                    stderr_line = process.stderr.readline()
                    stdout_line = process.stdout.readline()
                    if stdout_line:
                        print(f"Snort stdout: {stdout_line.strip()}")
                    if stderr_line:
                        print(f"Snort stderr: {stderr_line.strip()}")
                    if process.poll() is not None:
                        break

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
                'message': f'Snort started successfully and will run for {hours} hours. Logging to {filename}',
                'pid': pid,
                'log_file': filename
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