"""
URL configuration for ActiveDefense project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.urls import path, re_path
from Login.views import login_request as login, logout_request as logout
from django.views.static import serve
from Syslog import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path ('admin/', admin.site.urls),
    path ('login/', login, name = 'login'),
    path ('logout/', logout, name = 'logout'),
    path ('logfile/register', views.register_logfile, name = 'register_logfile'),
    path ('logfile/', views.list_logfile, name = 'list_logfile'),
    path ('', views.view_logs, name = 'view_logs'),
    path ('logfile/list', views.list_logfile, name = 'list_logfile'),
    path ('logfile/remove/<int:pk>', views.remove_logfile, name = 'remove_logfile'),
    re_path (r'^files/(?P<path>.*)$',serve,{'document_root': settings.MEDIA_ROOT}),
    path ('view_logs/', views.view_logs, name = 'view_logs'),
    path ('view_logs/<int:log_pk>/<str:srcIP_>', views.view_logs, name = 'view_logs_pk_srcIP'),
    path ('view_blacklist/', views.view_blacklist, name = 'view_blacklist'),
    path ('view_blacklist/<int:pk>', views.view_blacklist, name = 'view_blacklist_pk'),
    path ('remove_blacklisted_ip/<int:pk>', views.remove_blacklisted_ip, name = 'remove_blacklisted_ip'),
    path ('add_to_blacklist/', views.add_to_blacklist, name = 'add_to_blacklist'),
    path ('add_to_blacklist/<str:srcIP>', views.add_to_blacklist, name = 'add_to_blacklist_srcIP'),
    path ('system/', views.system_on_off, name = 'system'),
    path ('system/<str:action>', views.system_on_off, name = 'system_on_off'),
    path ('view_recipients/', views.list_recipient, name = 'list_recipient'),
    path ('add_recipient/', views.add_recipient, name = 'add_recipient'),
    path ('view_recipients/<int:pk>', views.list_recipient, name = 'list_recipient_pk'),
    path ('remove_recipient/<int:pk>', views.remove_recipient, name = 'remove_recipient_pk'),
    path ('smtp_setting/', views.smtp_setting, name = 'smtp_setting'),
    path ('smtp_setting/<int:pk>', views.smtp_setting, name = 'update_smtp_setting_pk'),
    path ('defense_setting/', views.defense_setting, name = 'defense_setting'),
    path ('defense_setting/<str:case>', views.defense_setting, name = 'update_defense_setting'),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])