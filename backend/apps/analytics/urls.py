from django.urls import path
from . import views

urlpatterns = [
    path('security-trends/', views.get_security_trends, name='security_trends'),
    path('geographic-data/', views.get_geographic_data, name='geographic_data'),
    path('realtime-activity/', views.get_realtime_activity, name='realtime_activity'),
]