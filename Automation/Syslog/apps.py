from django.apps import AppConfig
from django.conf import settings



class SyslogConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Syslog'

    def ready(self):
        from django.utils import timezone
        settings.TIME_Zone = 'Australia/Sydney'
        timezone.activate(settings.TIME_Zone)
        # define default defense setting values
        from .models import DefenseSetting
        if DefenseSetting.objects.filter(name = 'Port_Scan1_x_min').count() == 0:
            DefenseSetting.objects.create(name = 'Port_Scan1_x_min', value = 10)
        if DefenseSetting.objects.filter(name = 'Port_Scan1_x_dstPort').count() == 0:
            DefenseSetting.objects.create(name = 'Port_Scan1_x_dstPort', value = 10)
        if DefenseSetting.objects.filter(name = 'Port_Scan2_x_min').count() == 0:
            DefenseSetting.objects.create(name = 'Port_Scan2_x_min', value = 10)
        if DefenseSetting.objects.filter(name = 'Port_Scan2_x_dstIP').count() == 0:
            DefenseSetting.objects.create(name = 'Port_Scan2_x_dstIP', value = 10)
        if DefenseSetting.objects.filter(name = 'Vul_Scan1_x_severity').count() == 0:
            DefenseSetting.objects.create(name = 'Vul_Scan1_x_severity', value = 1)
        if DefenseSetting.objects.filter(name = 'x_month_logs').count() == 0:
            DefenseSetting.objects.create(name = 'x_month_logs', value = 6)
        if DefenseSetting.objects.filter(name = 'x_month_inactive_blacklist').count() == 0:
            DefenseSetting.objects.create(name = 'x_month_inactive_blacklist', value = 1)
        # define email default settings
        from .models import EmailSetting
        email_setting, created = EmailSetting.objects.get_or_create(id=1)
        settings.EMAIL_HOST = email_setting.EMAIL_HOST
        settings.EMAIL_USE_TLS = email_setting.EMAIL_USE_TLS
        settings.EMAIL_PORT = email_setting.EMAIL_PORT
        settings.EMAIL_HOST_USER = email_setting.EMAIL_HOST_USER
        if email_setting.EMAIL_HOST_PASSWORD is not None:
            settings.EMAIL_HOST_PASSWORD = email_setting.EMAIL_HOST_PASSWORD
        #setup allowed server IP address
        import netifaces
        settings.ALLOWED_HOSTS=[]
        for interface in netifaces.interfaces():
            interface_info = netifaces.ifaddresses(interface)
            settings.ALLOWED_HOSTS.append(interface_info.get(netifaces.AF_INET)[0]['addr'])
