# apps/scans/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('scan/', views.ScanLinkView.as_view(), name='scan-link'),
    path('history/', views.ScanHistoryView.as_view(), name='scan-history'),
    path('history/<uuid:pk>/delete/', views.DeleteScanSoftView.as_view(), name='scan-delete-soft'),
    path('history/clear-all/', views.DeleteAllScansSoftView.as_view(), name='scan-clear-all-soft'),
]