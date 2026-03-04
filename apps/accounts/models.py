# apps/accounts/models.py
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
import os

class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError('يجب إدخال البريد الإلكتروني')
        if not name:
            raise ValueError('يجب إدخال الاسم')
        
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        return self.create_user(email, name, password, **extra_fields)

def user_profile_image_path(instance, filename):
    """توليد مسار فريد لصورة المستخدم"""
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('profile_images', filename)

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, verbose_name='البريد الإلكتروني')
    name = models.CharField(max_length=255, verbose_name='الاسم الكامل')
    profile_image = models.ImageField(
        upload_to=user_profile_image_path,
        null=True,
        blank=True,
        verbose_name='الصورة الشخصية'
    )
    
    # إحصائيات المستخدم
    scanned_links = models.IntegerField(default=0, verbose_name='الروابط الممسوحة')
    detected_threats = models.IntegerField(default=0, verbose_name='التهديدات المكتشفة')
    accuracy_rate = models.FloatField(default=0.0, verbose_name='نسبة الدقة')
    
    # حالة البريد الإلكتروني
    is_email_verified = models.BooleanField(default=False, verbose_name='البريد الإلكتروني موثق')
    email_verification_token = models.CharField(max_length=255, null=True, blank=True)
    
    # تواريخ مهمة
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإنشاء')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')
    last_login = models.DateTimeField(null=True, blank=True, verbose_name='آخر دخول')
    
    # صلاحيات
    is_active = models.BooleanField(default=True, verbose_name='نشط')
    is_staff = models.BooleanField(default=False, verbose_name='موظف')
    
    # إعدادات المستخدم (JSON field)
    settings = models.JSONField(default=dict, verbose_name='الإعدادات')
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    
    class Meta:
        verbose_name = 'مستخدم'
        verbose_name_plural = 'المستخدمين'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name
    
    def update_stats(self):
        """تحديث إحصائيات المستخدم"""
        from apps.scans.models import ScanResult
        
        scans = ScanResult.objects.filter(user=self)
        self.scanned_links = scans.count()
        self.detected_threats = scans.filter(safe=False).count()
        
        if self.scanned_links > 0:
            self.accuracy_rate = (self.scanned_links - self.detected_threats) / self.scanned_links * 100
        else:
            self.accuracy_rate = 0
            
        self.save(update_fields=['scanned_links', 'detected_threats', 'accuracy_rate'])
    
    def get_default_settings(self):
        """الحصول على الإعدادات الافتراضية"""
        return {
            'notifications': True,
            'auto_scan': False,
            'save_history': True,
            'safe_browsing': True,
            'auto_update': True,
            'dark_mode': False,
            'scan_timeout': 30,
            'scan_level': 'standard',
            'language': 'ar',
        }
    
    def save(self, *args, **kwargs):
        if not self.settings:
            self.settings = self.get_default_settings()
        super().save(*args, **kwargs)

class PasswordResetToken(models.Model):
    """نموذج رمز إعادة تعيين كلمة المرور"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = 'رمز إعادة تعيين كلمة المرور'
        verbose_name_plural = 'رموز إعادة تعيين كلمة المرور'
    
    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()