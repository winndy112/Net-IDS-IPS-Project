from django.shortcuts import render
from django.http import HttpResponse

def homepage(request):
    return render(request, 'dashboard/homepage.html')

def generate_rules(request):
    return render(request, 'dashboard/gen_rules.html')

def run_ids(request):
    return render(request, 'dashboard/run_ids.html')

def open_log_analyzer(request):
    return render(request, 'dashboard/log_analyzer.html')