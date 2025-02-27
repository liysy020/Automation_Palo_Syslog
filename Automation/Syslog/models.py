from django.db import models
from django.utils import timezone

class Logfile (models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    path = models.CharField(max_length=100)
    type = models.CharField(max_length=10, default=('Firewall', 'Firewall'), choices=[('Firewall', 'Firewall'),('Router', 'Router'),('Switch', 'Switch')])
    def __str__(self):
        return self.name

class PATrafficLog (models.Model):
    id = models.AutoField(primary_key=True)
    logfile = models.ForeignKey(Logfile, on_delete=models.CASCADE)
    Hostname = models.CharField(max_length=100)
    SrcLocation = models.CharField(max_length=100)
    SrcIP = models.CharField(max_length=100)
    SrcPort = models.CharField(max_length=100)
    SrcUser = models.CharField(max_length=100, default = '-')
    DstLocation = models.CharField(max_length=100)
    DstIP = models.CharField(max_length=100)
    DstPort = models.CharField(max_length=100)
    Action = models.CharField(max_length=100)
    RuleName = models.CharField(max_length=100)
    RuleID = models.CharField(max_length=100)
    TimeReceived = models.CharField(max_length=100) # Traffic log data. The time of a traffic was logged
    ThreatName = models.CharField(max_length=100, default = '-')
    ThreatID = models.CharField(max_length=100, default = '-')
    Severity = models.CharField(max_length=100, default = '-')
    Subtype = models.CharField(max_length=100, default = '-')
    LogType = models.CharField(max_length=100, default = 'TRAFFIC')
    Created_at = models.DateTimeField(auto_now_add=True, null=True) #database record created at

    def __str__(self):
        return self.Hostname
    
class JobLock(models.Model):
    id = models.AutoField(primary_key=True)
    is_running = models.BooleanField(default=False)
    job_name = models.CharField(max_length=100, unique=True)
    last_run = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.job_name
    
class Blacklist(models.Model):
    id = models.AutoField(primary_key=True)
    Alert = models.CharField(max_length=100)
    IP = models.CharField(max_length=100)
    LastSeen = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.Alert

class Recipient (models.Model):
    id = models.AutoField(primary_key=True)
    Email = models.CharField(max_length=100)
    Created_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.Email

class EmailSetting(models.Model):
    id = models.AutoField(primary_key=True)
    EMAIL_HOST = models.CharField(max_length=255,default = 'smtp.example.com')
    EMAIL_USE_TLS = models.BooleanField(default=False)
    EMAIL_PORT = models.IntegerField(default = 25)
    EMAIL_HOST_USER = models.CharField(max_length=255,default = 'user@example.com')
    EMAIL_HOST_PASSWORD = models.CharField(max_length=255, null = True)
    def __str__(self):
        return 'SMTP server settings for '+ EMAIL_HOST

class DefenseSetting(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    value = models.IntegerField(default = 0)
    def __str__(self):
        return self.name