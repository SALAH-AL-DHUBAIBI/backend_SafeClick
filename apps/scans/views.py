# apps/scans/views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import ScanResult
from .serializers import ScanResultSerializer, ScanLinkSerializer
from .threat_detection import ThreatDetector
import logging

logger = logging.getLogger(__name__)

class ScanLinkView(APIView):
    """فحص رابط جديد"""
    permission_classes = [AllowAny]  # مؤقتاً للتطوير
    
    def post(self, request):
        print("\n" + "="*60)
        print("🔵 [SCAN] طلب فحص رابط جديد")
        print("="*60)
        
        serializer = ScanLinkSerializer(data=request.data)
        
        if serializer.is_valid():
            link = serializer.validated_data['link']
            print(f"🔗 الرابط: {link}")
            print(f"👤 المستخدم: {request.user.email if request.user.is_authenticated else 'غير مسجل'}")
            
            try:
                # فحص الرابط
                print("🔄 جاري فحص الرابط...")
                detector = ThreatDetector()
                result = detector.detect(link)
                
                print(f"✅ نتيجة الفحص: {result.get('score')}% - {result.get('final_status')}")
                
                # حفظ النتيجة
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
                print(f"💾 تم الحفظ برقم: {scan_result.id}")
                
                # تجهيز الرد
                response_data = ScanResultSerializer(scan_result).data
                response_data['final_status'] = result.get('final_status')
                response_data['final_message'] = result.get('final_message')
                
                return Response({
                    'success': True,
                    'result': response_data
                })
                
            except Exception as e:
                logger.error(f"خطأ في الفحص: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'حدث خطأ أثناء الفحص'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class ScanHistoryView(APIView):
    """عرض سجل الفحوصات"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        scans = ScanResult.objects.filter(user=request.user).order_by('-timestamp')
        serializer = ScanResultSerializer(scans, many=True)
        
        return Response({
            'success': True,
            'history': serializer.data,
            'count': scans.count()
        })