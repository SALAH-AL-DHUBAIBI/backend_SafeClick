# apps/scans/serializers.py
from rest_framework import serializers
from .models import ScanResult

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = [
            'id', 'link', 'domain', 'ip_address',
            'safe', 'score', 'details', 'threats_found',
            'threats_count', 'response_time', 'server_info', 'timestamp'
        ]
    
    def to_representation(self, instance):
        """تنسيق البيانات للعرض"""
        data = super().to_representation(instance)
        
        # تنسيق التفاصيل كنصوص
        if isinstance(data.get('details'), list):
            data['details'] = [str(d) for d in data['details']]
        
        # إضافة الحالة النصية
        if data['safe'] == True:
            data['status_text'] = 'آمن'
            data['status_icon'] = '✅'
        elif data['safe'] == False:
            data['status_text'] = 'خطير'
            data['status_icon'] = '🔴'
        else:
            data['status_text'] = 'مشبوه'
            data['status_icon'] = '⚠️'
        
        return data


class ScanLinkSerializer(serializers.Serializer):
    link = serializers.URLField(required=True)
    
    def validate_link(self, value):
        if not value.startswith(('http://', 'https://')):
            value = 'https://' + value
        return value