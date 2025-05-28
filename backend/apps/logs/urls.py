from django.urls import path
from . import views

urlpatterns = [
    path('', views.get_logs, name='logs_list'),
    path('dashboard/stats/', views.get_log_stats, name='dashboard_stats'),
    path('alerts/', views.get_alerts, name='alerts_list'),
    path('alerts/<str:alert_id>/', views.update_alert, name='update_alert'),
    path('alert-rules/', views.get_alert_rules, name='alert_rules_list'),
    path('alert-rules/create/', views.create_alert_rule, name='create_alert_rule'),
    path('test-db/', views.test_db_connection, name='test-db-connection'),
    path('analytics/alerts-by-agent/', views.alerts_by_agent, name='alerts-by-agent'),
    path('analytics/alerts-evolution/', views.alerts_evolution, name='alerts-evolution'),
    path('analytics/mitre-attack/', views.mitre_attack, name='mitre-attack'),
    path('computer-names/', views.get_computer_names, name='computer_names'),
    path('analytics/critical-logs-by-device', views.get_critical_logs_by_device, name='critical_logs_by_device'),
    path('<str:log_id>/', views.get_log_detail, name='log_detail'),
    path('analytics/os-severity-distribution/', views.os_severity_distribution, name='os-severity-distribution'),
    path('analytics/critical-alerts/', views.critical_alerts, name='critical-alerts'),
]