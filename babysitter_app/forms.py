from django import forms
from .models import Sitter, Parent, CustomUser
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser  # Import the correct model

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser  # ✅ Use the custom model
        fields = ("username", "email", "password1", "password2", "user_type")

class LoginAPIView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)
        
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "username": user.username,
                "role": user.profile.user_type if hasattr(user, 'profile') else 'unknown',
            })
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class UserRegistrationForm(UserCreationForm):
    user_type = forms.ChoiceField(choices=CustomUser.USER_TYPES, required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2', 'user_type']

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, required=True, widget=forms.TextInput(attrs={
        'placeholder': 'Enter your username'
    }))
    password = forms.CharField(required=True, widget=forms.PasswordInput(attrs={
        'placeholder': 'Enter your password'
    }))


class SitterForm(forms.ModelForm):
    class Meta:
        model = Sitter
        fields = ['name', 'bio', 'hourly_rate', 'experience', 'location']
        
class ParentForm(forms.ModelForm):
    class Meta:
        model = Parent
        fields = ['name', 'location']  # Added 'location' for better functionality

