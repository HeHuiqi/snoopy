"""AssetRadar URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path, re_path
from . import views
from system.views import loginPage

from django.views import static     ##新增
from django.conf import settings    ##新增

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('system.urls')),

    path('system/', include('system.urls')),
    path('ruleroam/', include('ruleroam.urls')),
    path('mdeditor/', include('ruleroam.urls')),
    path('accounts/login/', loginPage, name='login'),


    # # 以下是新增
    # 没有这一步 你添加的图片并不会显示出来
    re_path(r'^static/(?P<path>.*)$', static.serve, {'document_root': settings.STATIC_ROOT}, name='static'),
    re_path(r'^media/images/(?P<path>.*)$', static.serve, {'document_root': settings.MD_IMAGES_ROOT}, name='media'),


]
handler403 = views.forbidden
handler404 = views.notFount
handler500 = views.serverError
