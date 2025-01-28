from django.urls import path
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
from .views import SitterList, LoginAPIView, UserListView

urlpatterns = [
    path('', views.home, name='home'), 
    path('register/', views.register, name='register'), 
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='home'), name='logout'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/login/', LoginAPIView.as_view(), name='api-login'),
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('sitters/', views.sitter_list, name='sitter_list'), 
    path('sitters/create/', views.create_update_sitter, name='create_sitter'),
    path('sitters/update/<int:pk>/', views.update_sitter, name='update_sitter'),
    path('sitters/delete/<int:pk>/', views.delete_sitter, name='delete_sitter'),
    path('sitters/<int:sitter_id>/', views.sitter_detail, name='sitter_detail'),
    path('sitters/search/', views.search_sitters, name='search_sitters'), 
    path('api/sitters/', SitterList.as_view(), name='sitter_list_api'), 
    path('parents/', views.parent_list, name='parent_list'), 
    path('parents/create/', views.create_or_update_parent, name='create_parent'),
    path('parents/update/<int:pk>/', views.create_or_update_parent, name='update_parent'),
    path('parents/delete/<int:pk>/', views.delete_parent, name='delete_parent'), 
]
