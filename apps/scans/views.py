# apps/scans/views.py
import json
import logging
from django.utils import timezone
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.shortcuts import get_object_or_404

from .models import ScanResult, ScanQueue, Blacklist
from .serializers import (
    ScanResultSerializer, ScanResultDetailSerializer,
    ScanQueueSerializer, ScanLinkSerializer, BlacklistSerializer
)
from .threat_detection import ThreatDetector

logger = logging.getLogger(__name__)

class ScanLinkView(APIView):
    """فحص رابط جديد"""
    
    def post(self, request):
        serializer = ScanLinkSerializer(data=request.data)
        if serializer.is_valid():
            link = serializer.validated_data['link']
            
            # بدء الفحص
            detector = ThreatDetector()
            result = detector.detect(link)
            
            # حفظ النتيجة في قاعدة البيانات
            scan_result = ScanResult(
                user=request.user if request.user.is_authenticated else None,
                link=link,
                domain=result.get('domain'),
                ip_address=result.get('ip_address'),
                safe=result.get('safe'),
                score=result.get('score', 0),
                details=result.get('details', []),
                threats_found=result.get('threats_found', []),
                threats_count=result.get('threats_count', 0),
                response_time=result.get('response_time', 0),
                server_info=result.get('server_info')
            )
            scan_result.save()
            
            # إرجاع النتيجة
            return Response({
                'success': True,
                'result': ScanResultSerializer(scan_result).data
            })
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ScanHistoryView(generics.ListAPIView):
    """عرض سجل الفحوصات"""
    serializer_class = ScanResultSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return ScanResult.objects.filter(user=self.request.user).order_by('-timestamp')
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # إحصائيات إضافية
        stats = {
            'total': queryset.count(),
            'safe': queryset.filter(safe=True).count(),
            'dangerous': queryset.filter(safe=False).count(),
            'suspicious': queryset.filter(safe__isnull=True).count(),
        }
        
        if stats['total'] > 0:
            stats['safe_percentage'] = (stats['safe'] / stats['total']) * 100
            stats['dangerous_percentage'] = (stats['dangerous'] / stats['total']) * 100
        else:
            stats['safe_percentage'] = 0
            stats['dangerous_percentage'] = 0
        
        return Response({
            'success': True,
            'stats': stats,
            'history': serializer.data
        })

class ScanDetailView(generics.RetrieveAPIView):
    """عرض تفاصيل فحص محدد"""
    serializer_class = ScanResultDetailSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return ScanResult.objects.filter(user=self.request.user)
    
    def get_object(self):
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, pk=self.kwargs['pk'])
        return obj

class DeleteScanView(APIView):
    """حذف فحص محدد"""
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, pk):
        try:
            scan = ScanResult.objects.get(pk=pk, user=request.user)
            scan.delete()
            return Response({
                'success': True,
                'message': 'تم حذف الفحص بنجاح'
            })
        except ScanResult.DoesNotExist:
            return Response({
                'success': False,
                'message': 'الفحص غير موجود'
            }, status=status.HTTP_404_NOT_FOUND)

class ClearHistoryView(APIView):
    """مسح جميع سجل الفحوصات"""
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        count = ScanResult.objects.filter(user=request.user).delete()[0]
        return Response({
            'success': True,
            'message': f'تم مسح {count} فحص بنجاح'
        })

class StatsView(APIView):
    """إحصائيات متقدمة للفحوصات"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        queryset = ScanResult.objects.filter(user=request.user)
        
        # إحصائيات أساسية
        total = queryset.count()
        safe = queryset.filter(safe=True).count()
        dangerous = queryset.filter(safe=False).count()
        suspicious = queryset.filter(safe__isnull=True).count()
        
        # متوسط النتيجة
        avg_score = queryset.aggregate(avg=models.Avg('score'))['avg'] or 0
        
        # أكثر الأيام نشاطاً
        from django.db.models import Count
        from django.db.models.functions import TruncDate
        
        daily_stats = queryset.annotate(
            date=TruncDate('timestamp')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        # إحصائيات حسب نوع التهديد
        threat_types = {}
        for scan in queryset.exclude(threats_found=[]):
            for threat in scan.threats_found:
                threat_type = threat.get('type', 'unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return Response({
            'success': True,
            'stats': {
                'total': total,
                'safe': safe,
                'dangerous': dangerous,
                'suspicious': suspicious,
                'safe_percentage': (safe / total * 100) if total > 0 else 0,
                'dangerous_percentage': (dangerous / total * 100) if total > 0 else 0,
                'average_score': round(avg_score, 2),
                'most_active_days': list(daily_stats),
                'threats_by_type': threat_types,
            }
        })

class ExportHistoryView(APIView):
    """تصدير سجل الفحوصات"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        queryset = ScanResult.objects.filter(user=request.user).order_by('-timestamp')
        serializer = ScanResultSerializer(queryset, many=True)
        
        return Response({
            'success': True,
            'data': serializer.data,
            'count': queryset.count(),
            'exported_at': timezone.now().isoformat()
        })

class BlacklistView(generics.ListAPIView):
    """عرض القائمة السوداء (للمشرفين)"""
    serializer_class = BlacklistSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # يمكن للمشرفين فقط رؤية كل القائمة
        if self.request.user.is_staff:
            return Blacklist.objects.all()
        return Blacklist.objects.none()