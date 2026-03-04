# apps/accounts/views.py
import uuid
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
import logging

from .models import User, PasswordResetToken
from .serializers import (
    UserSerializer, UserProfileSerializer, RegisterSerializer,
    LoginSerializer, ChangePasswordSerializer, ForgotPasswordSerializer,
    ResetPasswordSerializer, UpdateSettingsSerializer
)

logger = logging.getLogger(__name__)

class RegisterView(APIView):
    """تسجيل مستخدم جديد"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # إنشاء رمز التحقق من البريد الإلكتروني
            user.email_verification_token = str(uuid.uuid4())
            user.save(update_fields=['email_verification_token'])
            
            # إرسال بريد التحقق
            self._send_verification_email(user)
            
            # إنشاء التوكن
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'success': True,
                'message': 'تم التسجيل بنجاح. يرجى تفعيل البريد الإلكتروني',
                'user': UserSerializer(user).data,
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def _send_verification_email(self, user):
        """إرسال بريد التحقق"""
        verification_link = f"{settings.FRONTEND_URL}/verify-email?token={user.email_verification_token}"
        
        subject = 'تفعيل حسابك في SafeClick'
        message = f'''
        مرحباً {user.name},
        
        شكراً لتسجيلك في SafeClick. يرجى النقر على الرابط التالي لتفعيل حسابك:
        
        {verification_link}
        
        إذا لم تقم بالتسجيل، يرجى تجاهل هذا البريد.
        
        مع تحيات,
        فريق SafeClick
        '''
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Error sending verification email: {e}")

class LoginView(APIView):
    """تسجيل الدخول"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            user = authenticate(request, username=email, password=password)
            
            if user:
                if not user.is_active:
                    return Response({
                        'success': False,
                        'message': 'الحساب غير نشط'
                    }, status=status.HTTP_401_UNAUTHORIZED)
                
                # تحديث آخر دخول
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                
                # إنشاء التوكن
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'success': True,
                    'message': 'تم تسجيل الدخول بنجاح',
                    'user': UserSerializer(user).data,
                    'tokens': {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh),
                    }
                })
            
            return Response({
                'success': False,
                'message': 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """تسجيل الخروج"""
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            return Response({
                'success': True,
                'message': 'تم تسجيل الخروج بنجاح'
            })
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return Response({
                'success': False,
                'message': 'حدث خطأ أثناء تسجيل الخروج'
            }, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(generics.RetrieveUpdateAPIView):
    """عرض وتحديث الملف الشخصي"""
    serializer_class = UserProfileSerializer
    parser_classes = [MultiPartParser, FormParser]
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        
        # تحديث الاسم إذا تم إرساله
        if 'name' in request.data:
            user.name = request.data['name']
        
        # تحديث الصورة إذا تم إرسالها
        if 'profile_image' in request.FILES:
            user.profile_image = request.FILES['profile_image']
        
        user.save()
        
        return Response({
            'success': True,
            'message': 'تم تحديث الملف الشخصي بنجاح',
            'user': UserProfileSerializer(user).data
        })

class ChangePasswordView(APIView):
    """تغيير كلمة المرور"""
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            
            # التحقق من كلمة المرور القديمة
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({
                    'success': False,
                    'message': 'كلمة المرور القديمة غير صحيحة'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # تعيين كلمة المرور الجديدة
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            return Response({
                'success': True,
                'message': 'تم تغيير كلمة المرور بنجاح'
            })
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(APIView):
    """نسيت كلمة المرور"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                
                # إنشاء رمز جديد
                token = str(uuid.uuid4())
                expires_at = timezone.now() + timezone.timedelta(hours=24)
                
                PasswordResetToken.objects.create(
                    user=user,
                    token=token,
                    expires_at=expires_at
                )
                
                # إرسال البريد
                reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
                
                subject = 'إعادة تعيين كلمة المرور - SafeClick'
                message = f'''
                مرحباً {user.name},
                
                لقد تلقينا طلباً لإعادة تعيين كلمة المرور الخاصة بحسابك في SafeClick.
                
                يرجى النقر على الرابط التالي لإعادة تعيين كلمة المرور:
                
                {reset_link}
                
                هذا الرابط صالح لمدة 24 ساعة.
                
                إذا لم تقم بطلب إعادة تعيين كلمة المرور، يرجى تجاهل هذا البريد.
                
                مع تحيات,
                فريق SafeClick
                '''
                
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                
                return Response({
                    'success': True,
                    'message': 'تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني'
                })
                
            except User.DoesNotExist:
                # لا نريد إعطاء معلومات عن وجود البريد أو عدمه
                return Response({
                    'success': True,
                    'message': 'إذا كان البريد الإلكتروني مسجلاً، ستتلقى رابط إعادة التعيين'
                })
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    """إعادة تعيين كلمة المرور باستخدام الرمز"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            
            try:
                reset_token = PasswordResetToken.objects.get(
                    token=token,
                    is_used=False,
                    expires_at__gt=timezone.now()
                )
                
                user = reset_token.user
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                
                # تعطيل الرمز
                reset_token.is_used = True
                reset_token.save()
                
                return Response({
                    'success': True,
                    'message': 'تم إعادة تعيين كلمة المرور بنجاح'
                })
                
            except PasswordResetToken.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'الرمز غير صالح أو منتهي الصلاحية'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    """تفعيل البريد الإلكتروني"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        token = request.query_params.get('token')
        
        if not token:
            return Response({
                'success': False,
                'message': 'الرمز غير موجود'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email_verification_token=token)
            
            user.is_email_verified = True
            user.email_verification_token = None
            user.save()
            
            return Response({
                'success': True,
                'message': 'تم تفعيل البريد الإلكتروني بنجاح'
            })
            
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': 'الرمز غير صالح'
            }, status=status.HTTP_400_BAD_REQUEST)

class SettingsView(APIView):
    """إدارة إعدادات المستخدم"""
    
    def get(self, request):
        """الحصول على الإعدادات"""
        return Response({
            'success': True,
            'settings': request.user.settings
        })
    
    def put(self, request):
        """تحديث الإعدادات"""
        serializer = UpdateSettingsSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            
            # تحديث الإعدادات
            for key, value in serializer.validated_data.items():
                user.settings[key] = value
            
            user.save(update_fields=['settings'])
            
            return Response({
                'success': True,
                'message': 'تم تحديث الإعدادات بنجاح',
                'settings': user.settings
            })
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request):
        """إعادة تعيين الإعدادات إلى الافتراضي"""
        user = request.user
        user.settings = user.get_default_settings()
        user.save(update_fields=['settings'])
        
        return Response({
            'success': True,
            'message': 'تم إعادة تعيين الإعدادات إلى الافتراضي',
            'settings': user.settings
        })