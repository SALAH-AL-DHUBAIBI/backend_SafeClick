# apps/scans/serializers.py
from rest_framework import serializers
from .models import ScanResult, ScanQueue, Blacklist
import re

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = [
            'id', 'link', 'domain', 'ip_address',
            'safe', 'safety_status', 'score',
            'details', 'threats_found', 'threats_count',
            'response_time', 'server_info',
            'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']

class ScanResultDetailSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)
    
    class Meta:
        model = ScanResult
        fields = '__all__'

class ScanQueueSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanQueue
        fields = ['id', 'link', 'status', 'created_at', 'completed_at']
        read_only_fields = ['id', 'status', 'created_at', 'completed_at']

class ScanLinkSerializer(serializers.Serializer):
    link = serializers.URLField(required=True, max_length=2000)
    
    def validate_link(self, value):
        # التحقق من صحة الرابط
        url_pattern = re.compile(
            r'^(https?:\/\/)?'  # بروتوكول اختياري
            r'([\da-z\.-]+)\.([a-z\.]{2,6})'  # النطاق
            r'([\/\w \.-]*)*\/?$'  # المسار
        )
        
        if not url_pattern.match(value):
            raise serializers.ValidationError('الرابط غير صحيح')
        
        return value

class BlacklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blacklist
        fields = ['id', 'link', 'domain', 'threat_type', 'severity', 'description', 'added_at']
        read_only_fields = ['id', 'added_at']