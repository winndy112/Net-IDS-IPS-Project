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
        hours = float(data.get('hours', 0))  # Convert to float to handle decimal hours
        interface = data.get('interface') 
        config_file = data.get('config_file')
        capture_type = data.get('capture_type')
        action = data.get('action')

        # Validate inputs
        if not all([hours, interface, config_file, capture_type, action]):
            return JsonResponse({'error': 'Missing required parameters'}, status=400)

        if capture_type not in ['ids', 'ips']:
            return JsonResponse({'error': 'Invalid capture type'}, status=400)

        if action not in ['start', 'stop']:
            return JsonResponse({'error': 'Invalid action'}, status=400)

        if hours <= 0:
            return JsonResponse({'error': 'Hours must be greater than 0'}, status=400)

        # Build Snort command based on parameters
        command = ['snort']
        
        command.extend([
            '-i', interface,
            '-c', config_file,
            '-l', path_log,  # Change log directory to Sample/
            '-A', 'fast',    # Use fast alert output
            '-K', 'csv',     # Output in CSV format
            '-y',            # Include year in timestamp
            '-L', filename   # Specific log filename
        ])


        # Start Snort process
        if action == 'start':
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Store process ID for later termination
            pid = process.pid
            request.session['snort_pid'] = pid
            request.session['log_file'] = full_path
            # Start a timer thread to stop Snort after specified hours
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
            })
        else:
            # Stop Snort process
            pid = request.session.get('snort_pid')
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                    log_file = request.session.get('log_file')
                    del request.session['snort_pid']
                    del request.session['log_file']
                    return JsonResponse({
                        'message': 'Snort stopped successfully',
                        'log_file': log_file
                    })
                except ProcessLookupError:
                    del request.session['snort_pid']
                    del request.session['log_file']
                    return JsonResponse({'message': 'Snort process already terminated'})
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