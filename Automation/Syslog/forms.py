from django import forms
from django.forms import modelformset_factory
from .models import Logfile, Blacklist, Recipient, EmailSetting, DefenseSetting

class LogfileForm (forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(LogfileForm,self).__init__(*args, **kwargs)
        self.fields['name'] = forms.CharField(widget=forms.TextInput(attrs={'size':'30'}))
        self.fields['path'] = forms.CharField(widget=forms.TextInput(attrs={'size':'30'}))
    class Meta:
        model = Logfile
        fields = ['name','path','type']

class SearchPATrafficLogForm (forms.Form):
    DATARANGE_CHOICES = [('Last 24 hrs','Last 24 hrs'),('Pass 3 days', 'Pass 3 days'), ('Pass 7 days', 'Pass 7 days'), ('All','All')]
    ACTION_CHOICES = [
        ('any', 'Any'),
        ('allow', 'Allow'),
        ('drop', 'Drop'),
        ('reset', 'Reset')
    ]
    THREAT_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('alert', 'Alert'),
        ('informational', 'Informational'),
        ('-', '---')
    ]
    LOGTYPE_CHOICES = [('any', 'Any'),('Traffic', 'Traffic'),('Threat', 'Threat')]

    logfile = forms.ModelChoiceField(Logfile.objects.all(), empty_label ='All files', required= False, widget=forms.Select(attrs={'class': 'dropdown-field'}))
    DataRange = forms.ChoiceField(label = 'Data Range', choices=DATARANGE_CHOICES, initial='Last 24 hrs', required = False, widget=forms.Select(attrs={'class': 'dropdown-field'}))
    SrcLocation = forms.CharField(label = 'Source Country', required = False)
    SrcIP = forms.CharField(label = 'Source IP', required = False)
    SrcPort = forms.CharField(label = 'Source Port', required = False)
    SrcUser = forms.CharField(label = 'Source User', required = False)
    DstLocation = forms.CharField(label = 'Destination Country', required = False)
    DstIP = forms.CharField(label = 'Destination IP', required = False)
    DstPort = forms.CharField(label = 'Destination Port', required = False)
    Threat = forms.ChoiceField(label = 'Threat Level', choices=THREAT_CHOICES, initial='-', required = False, widget=forms.Select(attrs={'class': 'dropdown-field'}))
    Action = forms.ChoiceField(label = 'Action', choices=ACTION_CHOICES, initial='any', required = False, widget=forms.Select(attrs={'class': 'dropdown-field'}))
    RuleName = forms.CharField(label = 'Rule Name', required = False)
    LogType = forms.ChoiceField(label = 'Traffic Type', choices=LOGTYPE_CHOICES, initial='any', required = False, widget=forms.Select(attrs={'class': 'dropdown-field'}))

class SeachBlacklistForm (forms.Form):
    ALERT_CHOICES = [
        ('all', 'All'),
        ('Port Scan Attack v1', 'Port Scan'),
        ('Port Scan Attack v2', 'IP Scan'),
        ('Vulnerability','Vulnerability Attack'),
        ('User Added', 'User Added')
    ]
    Alert = forms.ChoiceField(label = 'Blocked by', choices = ALERT_CHOICES, initial='all', required = False, widget=forms.Select(attrs={'class': 'dropdown-field'}))
    IP = forms.CharField(label = 'Blocked IP', required = False)

class AddToBlacklistForm (forms.ModelForm):
    class Meta:
        model = Blacklist
        fields = ['IP']

class AddEmailRecipientForm(forms.ModelForm):
    class Meta:
        model = Recipient
        fields = ['Email']

class UpdateSMTPForm(forms.ModelForm):
    class Meta:
        model = EmailSetting
        fields = ('EMAIL_HOST', 'EMAIL_USE_TLS', 'EMAIL_PORT', 'EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD')
    def __init__ (self, *args, **kwargs):
        super(UpdateSMTPForm, self).__init__(*args, **kwargs)
        self.fields['EMAIL_HOST'] = forms.CharField(label='SMTP Server Address')
        self.fields['EMAIL_USE_TLS'] = forms.BooleanField(label='Use TLS', required = False)
        self.fields['EMAIL_PORT'] = forms.IntegerField(label='SMTP Port')
        self.fields['EMAIL_HOST_USER'] = forms.CharField(label='Sender Address')
        self.fields['EMAIL_HOST_PASSWORD'] = forms.CharField(label='Password', required = False, widget = forms.PasswordInput)
        
class UpdateDefenseSettingForm(forms.ModelForm):
    class Meta:
        model = DefenseSetting
        fields = ['name', 'value']
    def __init__ (self, *args, **kwargs):
        super(UpdateDefenseSettingForm, self).__init__(*args, **kwargs)
        self.fields['name'] = forms.CharField(widget=forms.HiddenInput())
        self.fields['value'].widget.attrs.update({'style':'width: 40px;'})
DefenseSettingFormSet = modelformset_factory(DefenseSetting, form=UpdateDefenseSettingForm, extra=0)