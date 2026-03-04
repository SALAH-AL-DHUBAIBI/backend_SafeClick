# apps/scans/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import ScanResult, Blacklist

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = [
        'id_short',
        'link_short',
        'status_colored',
        'score_colored',
        'user_email',
        'timestamp_display',
        'threats_badge'
    ]
    
    list_filter = ['safe', 'timestamp', 'user']
    search_fields = ['link', 'domain', 'user__email']
    list_per_page = 25
    ordering = ['-timestamp']
    
    def id_short(self, obj):
        return str(obj.id)[:8] + '...'
    id_short.short_description = 'المعرف'
    
    def link_short(self, obj):
        return obj.link[:50] + '...' if len(obj.link) > 50 else obj.link
    link_short.short_description = 'الرابط'
    
    def status_colored(self, obj):
        if obj.safe == True:
            return format_html('<span style="color: green; font-weight: bold;">✅ آمن</span>')
        elif obj.safe == False:
            return format_html('<span style="color: red; font-weight: bold;">🔴 خطير</span>')
        else:
            return format_html('<span style="color: orange; font-weight: bold;">⚠️ مشبوه</span>')
    status_colored.short_description = 'الحالة'
    
    def score_colored(self, obj):
        color = 'green' if obj.score >= 70 else 'orange' if obj.score >= 40 else 'red'
        return format_html('<span style="color: {}; font-weight: bold;">{}%</span>', color, obj.score)
    score_colored.short_description = 'النتيجة'
    
    def user_email(self, obj):
        return obj.user.email if obj.user else 'غير مسجل'
    user_email.short_description = 'المستخدم'
    
    def timestamp_display(self, obj):
        return obj.timestamp.strftime('%Y-%m-%d %H:%M')
    timestamp_display.short_description = 'التاريخ'
    
    def threats_badge(self, obj):
        if obj.threats_count > 0:
            return format_html('<span style="background: #ff4444; color: white; padding: 3px 8px; border-radius: 10px;">⚠️ {}</span>', obj.threats_count)
        return '✅'
    threats_badge.short_description = 'التهديدات'
    
    readonly_fields = ['id', 'timestamp', 'updated_at']


@admin.register(Blacklist)
class BlacklistAdmin(admin.ModelAdmin):
    list_display = ['domain', 'threat_type', 'severity', 'source', 'added_at']
    list_filter = ['threat_type', 'severity']
    search_fields = ['domain', 'link']