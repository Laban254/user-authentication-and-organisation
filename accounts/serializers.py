from rest_framework import serializers
from .models import User, Organisation

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password

class UserSerializer(serializers.Serializer):
    userId = serializers.IntegerField()
    firstName = serializers.CharField(max_length=30)
    lastName = serializers.CharField(max_length=30)
    email = serializers.EmailField()
    phone = serializers.CharField(max_length=15, allow_blank=True)

class OrganisationSerializer(serializers.Serializer):
    org_id = serializers.IntegerField()
    name = serializers.CharField(max_length=255)
    description = serializers.CharField()

class RegistrationSerializer(serializers.Serializer):
    firstName = serializers.CharField(max_length=30)
    lastName = serializers.CharField(max_length=30)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    phone = serializers.CharField(max_length=15, allow_blank=True)



class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()