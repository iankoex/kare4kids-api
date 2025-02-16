from django.urls import path
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
from .views import SitterList, SitterDetail, RegisterAPIView, LoginAPIView, UserListView, CreateSitterView, UpdateSitterView, ParentCreateView, ParentUpdateView, ParentDeleteView

urlpatterns = [
    path('', views.home, name='home'),
    path("api/register/", RegisterAPIView.as_view(), name="api-register"),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path("api/register/", RegisterAPIView.as_view(), name="register"),
    path('logout/', auth_views.LogoutView.as_view(next_page='home'), name='logout'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/login/', LoginAPIView.as_view(), name='api-login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('sitters/', views.sitter_list, name='sitter_list'),
    path('sitters/create/', CreateSitterView.as_view(), name='create_sitter'),
    path('sitters/update/<int:pk>/', UpdateSitterView.as_view(), name='update_sitter'),
    path('sitters/delete/<int:pk>/', views.delete_sitter, name='delete_sitter'),
    path('api/sitters/<int:pk>/', SitterDetail.as_view(), name='sitter_detail'),
    path('sitters/search/', views.search_sitters, name='search_sitters'), 
    path('api/sitters/', SitterList.as_view(), name='sitter_list_api'), 
    path('parents/', views.parent_list, name='parent_list'), 
    path('parents/create/', ParentCreateView.as_view(), name='create_parent'),
    path('parents/update/<int:pk>/', ParentUpdateView.as_view(), name='update_parent'),
    path('parents/delete/<int:pk>/', ParentDeleteView.as_view(), name='delete_parent'),
]
