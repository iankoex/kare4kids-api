from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from babysitter_app.views import mpesa_callback


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('babysitter_app.urls')),
    path('api/mpesa-callback/', mpesa_callback, name='mpesa_callback'),
    ]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

