# apps/accounts/serializers.py
from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'email', 'name', 'profile_image', 
            'scanned_links', 'detected_threats', 'accuracy_rate',
            'is_email_verified', 'created_at', 'last_login'
        ]

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password_confirm']
    
    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("كلمة المرور غير متطابقة")
        if len(data['password']) < 6:
            raise serializers.ValidationError("كلمة المرور يجب أن تكون 6 أحرف على الأقل")
        return data
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class SendOTPSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True, required=False)
    
    def validate(self, data):
        if 'password_confirm' in data and data['password'] != data['password_confirm']:
            raise serializers.ValidationError("كلمة المرور غير متطابقة")
        if len(data['password']) < 6:
            raise serializers.ValidationError("كلمة المرور يجب أن تكون 6 أحرف على الأقل")
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("البريد الإلكتروني مستخدم بالفعل")
        # Also check if another user has the same name since we login by name now
        if User.objects.filter(name=data['name']).exists():
            raise serializers.ValidationError("اسم المستخدم مستخدم بالفعل")
        return data

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()