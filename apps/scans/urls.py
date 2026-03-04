# apps/scans/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('scan/', views.ScanLinkView.as_view(), name='scan-link'),
    path('history/', views.ScanHistoryView.as_view(), name='scan-history'),
    path('history/<uuid:pk>/', views.ScanDetailView.as_view(), name='scan-detail'),
    path('history/<uuid:pk>/delete/', views.DeleteScanView.as_view(), name='delete-scan'),
    path('history/clear/', views.ClearHistoryView.as_view(), name='clear-history'),
    path('stats/', views.StatsView.as_view(), name='scan-stats'),
    path('export/', views.ExportHistoryView.as_view(), name='export-history'),
    path('blacklist/', views.BlacklistView.as_view(), name='blacklist'),
]