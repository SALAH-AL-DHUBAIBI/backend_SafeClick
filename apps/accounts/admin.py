# apps/accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'name', 'scanned_links', 'detected_threats', 'is_active', 'is_staff', 'created_at']
    list_filter = ['is_active', 'is_staff', 'is_email_verified']
    search_fields = ['email', 'name']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('معلومات شخصية', {'fields': ('name', 'profile_image')}),
        ('إحصائيات', {'fields': ('scanned_links', 'detected_threats', 'accuracy_rate')}),
        ('الصلاحيات', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_email_verified')}),
        ('تواريخ', {'fields': ('last_login', 'created_at')}),
    )
    
    readonly_fields = ['created_at', 'last_login']