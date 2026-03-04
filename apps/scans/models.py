# apps/scans/models.py
import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone

class ScanResult(models.Model):
    """نتائج فحص الرابط"""
    SAFETY_CHOICES = [
        ('safe', 'آمن'),
        ('suspicious', 'مشبوه'),
        ('dangerous', 'خطير'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scan_results',
        null=True,
        blank=True
    )
    
    # معلومات الرابط
    link = models.URLField(max_length=2000, verbose_name='الرابط')
    domain = models.CharField(max_length=255, verbose_name='النطاق', null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name='عنوان IP')
    
    # نتائج الفحص
    safe = models.BooleanField(null=True, verbose_name='آمن')
    safety_status = models.CharField(
        max_length=20,
        choices=SAFETY_CHOICES,
        default='suspicious',
        verbose_name='حالة الأمان'
    )
    score = models.IntegerField(default=0, verbose_name='نسبة الأمان')  # 0-100
    
    # تفاصيل الفحص
    details = models.JSONField(default=list, verbose_name='تفاصيل الفحص')
    threats_found = models.JSONField(default=list, verbose_name='التهديدات المكتشفة')
    threats_count = models.IntegerField(default=0, verbose_name='عدد التهديدات')
    
    # معلومات تقنية
    response_time = models.FloatField(default=0, verbose_name='زمن الاستجابة')
    server_info = models.CharField(max_length=255, null=True, blank=True, verbose_name='معلومات السيرفر')
    
    # تواريخ
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الفحص')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')
    
    class Meta:
        verbose_name = 'نتيجة فحص'
        verbose_name_plural = 'نتائج الفحوصات'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['safe']),
        ]
    
    def __str__(self):
        return f"{self.domain or self.link} - {self.get_safety_status_display()}"
    
    def save(self, *args, **kwargs):
        # تحديث حالة الأمان بناءً على النتيجة
        if self.safe is True:
            self.safety_status = 'safe'
        elif self.safe is False:
            self.safety_status = 'dangerous'
        else:
            self.safety_status = 'suspicious'
        
        super().save(*args, **kwargs)
        
        # تحديث إحصائيات المستخدم إذا كان مستخدم مسجل
        if self.user:
            self.user.update_stats()

class ScanQueue(models.Model):
    """قائمة انتظار الفحوصات للمعالجة الغير متزامنة"""
    STATUS_CHOICES = [
        ('pending', 'في الانتظار'),
        ('processing', 'قيد المعالجة'),
        ('completed', 'مكتمل'),
        ('failed', 'فشل'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scan_queues',
        null=True,
        blank=True
    )
    
    link = models.URLField(max_length=2000)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # النتيجة بعد المعالجة
    result = models.ForeignKey(ScanResult, on_delete=models.SET_NULL, null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    
    # تواريخ
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'قائمة انتظار الفحص'
        verbose_name_plural = 'قوائم انتظار الفحوصات'
        ordering = ['-created_at']

class Blacklist(models.Model):
    """قائمة الروابط المحظورة"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    link = models.URLField(max_length=2000, unique=True)
    domain = models.CharField(max_length=255)
    
    # معلومات التهديد
    threat_type = models.CharField(max_length=100, verbose_name='نوع التهديد')
    severity = models.IntegerField(default=3, verbose_name='درجة الخطورة')  # 1-5
    description = models.TextField(null=True, blank=True, verbose_name='الوصف')
    
    # مصدر الحظر
    source = models.CharField(max_length=100, default='system', verbose_name='المصدر')
    
    # تواريخ
    added_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإضافة')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')
    
    class Meta:
        verbose_name = 'رابط محظور'
        verbose_name_plural = 'الروابط المحظورة'
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['threat_type']),
        ]
    
    def __str__(self):
        return f"{self.domain} - {self.threat_type}"