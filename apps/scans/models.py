# apps/scans/models.py
from django.db import models
from django.conf import settings
import uuid

class ScanResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scan_results',
        null=True,
        blank=True
    )
    
    link = models.URLField(max_length=2000)
    domain = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    safe = models.BooleanField(null=True)
    score = models.IntegerField(default=0)
    
    details = models.JSONField(default=list)
    threats_found = models.JSONField(default=list)
    threats_count = models.IntegerField(default=0)
    
    response_time = models.FloatField(default=0)
    server_info = models.CharField(max_length=255, null=True, blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'نتيجة فحص'
        verbose_name_plural = 'نتائج الفحوصات'
    
    def __str__(self):
        status = 'آمن' if self.safe == True else 'خطير' if self.safe == False else 'مشبوه'
        return f"{self.link[:50]} - {status} ({self.score}%)"
    
class Blacklist(models.Model):
    """قائمة الروابط المحظورة"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    link = models.URLField(max_length=2000)
    domain = models.CharField(max_length=255)
    threat_type = models.CharField(max_length=100)
    severity = models.IntegerField(default=3)
    source = models.CharField(max_length=100, default='system')
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'رابط محظور'
        verbose_name_plural = 'الروابط المحظورة'
    
    def __str__(self):
        return f"{self.domain} - {self.threat_type}"