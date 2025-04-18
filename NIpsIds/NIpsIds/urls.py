"""
URL configuration for NIpsIds project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from dashboard import views
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.homepage, name='homepage'),
    path('generate-rules/', views.generate_rules, name='generate_rules'),
    path('save-rule/', views.save_rule, name='save_rule'),

    path('run-ids-ips/', views.run_ids_ips, name='run_ids_ips'),
    path('run-snort/', views.run_snort, name='run_snort'),
    path('stop-ids/', views.stop_ids, name='stop_ids'),
    path('stop-ips/', views.stop_ips, name='stop_ips'),
    path('switch-to-ips/', views.switch_ids_to_ips, name='switch-to-ips'),
    
    path('open-log-analyzer/', views.open_log_analyzer, name='open_log_analyzer'),
    path('check-snort-status/', views.check_snort_status, name='check-snort-status'),
    path('misp-extension/', views.misp_extension, name='misp_extension'),
    path('start-schedule-misp/', views.start_schedule_misp, name='start_schedule_misp'),
    path('export-event/', views.export_event, name='export_event'),
    path('get-ruleset-status/', views.get_ruleset_status, name='get_ruleset_status'),
    path('toggle-rule-status/', views.toggle_rule_status, name='toggle_rule_status'),
    path('get-interfaces/', views.get_interfaces_list, name='get_interfaces'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)