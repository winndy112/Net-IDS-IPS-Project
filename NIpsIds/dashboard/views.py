from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
import subprocess
from django.views.decorators.csrf import csrf_exempt

def homepage(request):
    return render(request, 'dashboard/homepage.html')

def generate_rules(request):
    return render(request, 'dashboard/gen_rules.html')

def run_ids(request):
    return render(request, 'dashboard/run_ids.html')

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