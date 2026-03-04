# apps/accounts/serializers.py
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User
import re

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'email', 'name', 'profile_image',
            'scanned_links', 'detected_threats', 'accuracy_rate',
            'is_email_verified', 'created_at', 'last_login',
            'settings'
        ]
        read_only_fields = ['id', 'scanned_links', 'detected_threats', 
                           'accuracy_rate', 'created_at', 'last_login']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'profile_image', 
                 'scanned_links', 'detected_threats', 'accuracy_rate',
                 'is_email_verified', 'created_at']
        read_only_fields = ['id', 'email', 'scanned_links', 
                           'detected_threats', 'accuracy_rate',
                           'is_email_verified', 'created_at']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password_confirm']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "كلمة المرور غير متطابقة"})
        
        # التحقق من قوة كلمة المرور
        password = attrs['password']
        if len(password) < 8:
            raise serializers.ValidationError({"password": "كلمة المرور يجب أن تكون 8 أحرف على الأقل"})
        
        if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
            raise serializers.ValidationError(
                {"password": "كلمة المرور يجب أن تحتوي على حروف وأرقام"}
            )
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password_confirm = serializers.CharField(required=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password_confirm": "كلمة المرور غير متطابقة"})
        return attrs

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password_confirm = serializers.CharField(required=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password_confirm": "كلمة المرور غير متطابقة"})
        return attrs

class UpdateSettingsSerializer(serializers.Serializer):
    notifications = serializers.BooleanField(required=False)
    auto_scan = serializers.BooleanField(required=False)
    save_history = serializers.BooleanField(required=False)
    safe_browsing = serializers.BooleanField(required=False)
    auto_update = serializers.BooleanField(required=False)
    dark_mode = serializers.BooleanField(required=False)
    scan_timeout = serializers.IntegerField(required=False, min_value=10, max_value=60)
    scan_level = serializers.ChoiceField(required=False, choices=['basic', 'standard', 'deep'])
    language = serializers.ChoiceField(required=False, choices=['ar', 'en'])