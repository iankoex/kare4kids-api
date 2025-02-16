from rest_framework import serializers
from .models import Sitter, CustomUser

class SitterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sitter
        fields = '__all__'
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email']  # Include only necessary fields
