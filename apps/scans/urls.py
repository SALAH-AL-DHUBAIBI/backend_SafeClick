# apps/scans/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('scan/', views.ScanLinkView.as_view(), name='scan-link'),
    path('history/', views.ScanHistoryView.as_view(), name='scan-history'),
]