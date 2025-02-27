from django.shortcuts import render, redirect
from django.conf import settings
import os, ipaddress, time
from .models import Logfile, PATrafficLog, Blacklist, JobLock, Recipient, EmailSetting, DefenseSetting
from .forms import LogfileForm, SearchPATrafficLogForm, SeachBlacklistForm, AddToBlacklistForm, AddEmailRecipientForm, UpdateSMTPForm, UpdateDefenseSettingForm, DefenseSettingFormSet
from Syslog import scheduler
from django.utils import timezone
from datetime import timedelta, datetime
import pytz

def register_logfile(request):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/logfile/list')
	if request.method == 'POST':
		form = LogfileForm(request.POST)
		if form.is_valid():
			name = form.cleaned_data['name']
			path = form.cleaned_data['path']
			type = form.cleaned_data['type']
			if os.path.isfile (path):
				for log in Logfile.objects.all():
					if path == log.path:
						return render (request, 'logfiles.html',{'error': 'The log file '+ name +' is already exist!', 'user_auth': True})
				form.save()
			else:
				return render (request, 'logfiles.html',{'error': 'The file from location'+ path +' is not exist!', 'user_auth': True})
			return redirect ('/logfile/list',{'user_auth': True})
	else:
		register_form = LogfileForm()
		return render(request, 'logfiles.html',{'register_form': register_form,'user_auth': True})

def remove_logfile(request, pk=0):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/logfile/list')
	if request.method == 'POST':
		if pk != 0:
			try:
				logfile = Logfile.objects.get(id=pk)
				logfile.delete()
			except Exception as e:
				return render (request, 'logfiles.html',{'error': 'Exception occurred: '+ e, 'user_auth': True})
		return redirect ('/logfile/list',{'user_auth': True})

def list_logfile(request):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/logfile/')
	if Logfile.objects.all().count() == 0:
		return render(request, 'logfiles.html',{'new': True,'user_auth': True})
	return render(request, 'logfiles.html',{'Logfiles': Logfile.objects.all().order_by('name'),'user_auth': True})
	
def view_logs(request, log_pk=0, srcIP_='None'):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_logs')
	if request.method == 'POST':
		form = SearchPATrafficLogForm(request.POST)
		if form.is_valid():
			logfile = form.cleaned_data['logfile']
			DataRange = form.cleaned_data['DataRange']
			SrcLocation = form.cleaned_data['SrcLocation'] or ''
			SrcIP = form.cleaned_data['SrcIP'] or ''
			SrcPort = form.cleaned_data['SrcPort'] or ''
			SrcUser = form.cleaned_data['SrcUser'] or ''
			DstLocation = form.cleaned_data['DstLocation'] or ''
			DstIP = form.cleaned_data['DstIP'] or ''
			DstPort = form.cleaned_data['DstPort'] or ''
			Threat = form.cleaned_data['Threat'] or '-'
			Action = form.cleaned_data['Action']
			RuleName = form.cleaned_data['RuleName'] or ''
			LogType = form.cleaned_data['LogType']
			query_results = PATrafficLog.objects.all().order_by('-TimeReceived')
			if logfile != None:
				query_results = query_results.filter(logfile__name__contains = logfile)
			if DataRange == 'Last 24 hrs':
				query_results = query_results.filter(Created_at__gte = timezone.now() - timedelta(hours = 24))
			elif DataRange == 'Pass 3 days':
				query_results = query_results.filter(Created_at_gte = timezone.now() - timedelta(days = 3))
			elif DataRange == 'Pass 7 days':
				query_results = query_results.filter(Created_at__gte = timezone.now() - timedelta(days = 7))			
			if SrcLocation != '':
				query_results = query_results.filter(SrcLocation__contains = SrcLocation)
			if SrcIP != '':
				query_results = query_results.filter(SrcIP__exact = SrcIP)
			if SrcPort != '':
				query_results = query_results.filter(SrcPort__exact = SrcPort)
			if SrcUser != '':
				query_results = query_results.filter(SrcUser__contains = SrcUser)
			if DstLocation != '':
				query_results = query_results.filter(DstLocation__contains = DstLocation)
			if DstIP != '':
				query_results = query_results.filter(DstIP__exact = DstIP)
			if DstPort != '':
				query_results = query_results.filter(DstPort__exact = DstIP)
			if Threat != '-' :
				query_results = query_results.filter(Severity__exact = Threat)
			if Action != 'any':
				query_results = query_results.filter(Action__contains = Action)
			if RuleName != '':
				query_results = query_results.filter(RuleName__contains = RuleName)
			if LogType != 'any':
				query_results = query_results.filter(LogType__contains = LogType)
			return render (request, 'view_logs.html',{'logs': query_results, 'user_auth': True})
	else:
		if log_pk == 0 and srcIP_ == 'None':
			return render (request,'view_logs.html', {'form': SearchPATrafficLogForm(), 'user_auth': True})
		elif log_pk != 0 and srcIP_ == 'None':
			return render (request,'view_logs.html', {'log': PATrafficLog.objects.get(id=log_pk), 'user_auth': True})
		elif log_pk == 0 and srcIP_ != 'None':
			return render (request,'view_logs.html', {'logs': PATrafficLog.objects.all().order_by('-TimeReceived').filter(SrcIP=srcIP_), 'user_auth': True})
		
def view_blacklist(request,pk=0):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_blacklist')
	if request.method == 'POST':
		form = SeachBlacklistForm(request.POST)
		if form.is_valid():
			alert = form.cleaned_data['Alert']
			ip = form.cleaned_data['IP'] or ''
			query_results = Blacklist.objects.all().order_by('-LastSeen')
			if alert != 'all':
				query_results = query_results.filter(Alert__contains = alert)
			if ip != '':
				query_results = query_results.filter(IP__contains = ip)
			return render (request, 'view_blacklist.html',{'blacklists': query_results, 'user_auth': True})
	else:
		if pk == 0:
			return render (request,'view_blacklist.html', {'form': SeachBlacklistForm(), 'total': [('Total Blacklist count: '+ str(Blacklist.objects.all().count()))], 'user_auth': True})
		else:
			return render (request,'view_blacklist.html', {'blacklist': Blacklist.objects.get(id=pk), 'user_auth': True})
	
def remove_blacklisted_ip(request, pk):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_blacklist')
	if request.method == 'POST':
		if pk != 0:
			try:
				blacklist = Blacklist.objects.get(id=pk)
				blacklist.delete()
			except Exception as e:
				return render (request, 'view_blacklist.html',{'error': 'Exception occurred: '+ e, 'user_auth': True})
		return redirect ('/view_blacklist',{'user_auth': True})
	
def is_ipv4(address):
	try:
		ip = ipaddress.ip_address(address)
		return isinstance(ip, ipaddress.IPv4Address)
	except:
		return False
def is_subnet(subnet):
	try:
		network = ipaddress.ip_network(subnet)
		return isinstance(network, ipaddress.IPv4Network)
	except:
		return False
def add_to_blacklist(request, srcIP = 'None'):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_blacklist')
	if request.method == 'POST':
		form = AddToBlacklistForm(request.POST)
		if form.is_valid():
			alert = 'User Added'
			ip = form.cleaned_data['IP']
			if is_ipv4(ip) or is_subnet(ip):
				blacklist = Blacklist.objects.create(Alert = alert, IP = ip)
				return render (request,'view_blacklist.html', {'blacklist': blacklist, 'user_auth': True})
			else:
				return render (request,'view_blacklist.html', {'error': ip + ' is not a vaild address. Failed to add!', 'user_auth': True})
	elif request.method == 'GET' and srcIP == 'None':
		return render (request,'view_blacklist.html', {'AddToBlacklist': AddToBlacklistForm(), 'user_auth': True})
	elif request.method == 'GET' and srcIP != 'None':
		if is_ipv4(srcIP) or is_subnet(srcIP):
			if not Blacklist.objects.filter(IP=srcIP).exists():
				blacklist = Blacklist.objects.create(Alert = 'User Added', IP = srcIP)
				return render (request,'view_blacklist.html', {'blacklist': blacklist, 'user_auth': True})
			else:
				return render (request,'view_blacklist.html', {'error': [(srcIP + ' already in the blacklist!')], 'user_auth': True})

def system_on_off(request,action = 'None'):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/system')
	job_lock, created = JobLock.objects.get_or_create(job_name='System_ON_OFF')
	if action == 'start':
		if job_lock.is_running == False:
			scheduler.run()
			return render (request,'system_on_off.html', {'status_on': True, 'user_auth': True})
		else:
			return render (request,'system_on_off.html', {'error': [("System is running already! go to parth:'/system/reset' to reset")], 'user_auth': True})
	elif action == 'reset':
		if job_lock.is_running == True:
			scheduler.remove_old_jobs()
			return render (request,'system_on_off.html', {'status_on': False, 'user_auth': True})
		else:
			return render (request,'system_on_off.html', {'error': [("System is currently OFF! go to parth:'/system/start' to start it")], 'user_auth': True})
	else:
		if job_lock.is_running:
			return render (request,'system_on_off.html', {'status_on': True, 'user_auth': True})
		else:
			return render (request,'system_on_off.html', {'status_on': False, 'user_auth': True})

def list_recipient(request, pk = 0):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_recipients')
	if Recipient.objects.all().count() == 0:
		return render (request, 'recipient.html',{'new': True, 'user_auth': True})
	if request.method == 'GET' and pk == 0:
		query_results = Recipient.objects.all().order_by('Email')
		return render (request, 'recipient.html',{'Recipients': query_results, 'user_auth': True})
	elif request.method == 'GET' and pk != 0:
		return render (request,'recipient.html', {'Recipient': Recipient.objects.get(id=pk), 'user_auth': True})

def add_recipient(request):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_recipients')
	if request.method == 'POST':
		form = AddEmailRecipientForm(request.POST)
		if form.is_valid():
			form.save()
		return redirect ('/view_recipients',{'user_auth': True})
	else:
		form = AddEmailRecipientForm()
		return render(request, 'recipient.html',{'AddNew': form,'user_auth': True})
		
def remove_recipient(request, pk):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/view_recipients')
	if request.method == 'POST':
		if pk != 0:
			try:
				recipient = Recipient.objects.get(id=pk)
				recipient.delete()
			except Exception as e:
				return render (request, 'recipient.html',{'error': 'Exception occurred: '+ e, 'user_auth': True})
		return redirect ('/view_recipients',{'user_auth': True})

def smtp_setting (request, pk=0):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/smtp_setting')
	if request.method == 'GET' and pk == 0:
		return render (request, 'smtp_setting.html',{'Setting': EmailSetting.objects.get(id=1), 'user_auth': True})
	elif request.method == 'GET' and pk != 0:
		smtp_setting = EmailSetting.objects.get(id=1)
		update = UpdateSMTPForm(request.POST or None, instance = smtp_setting)
		return render (request, 'smtp_setting.html',{'update': update, 'user_auth': True})
	elif request.method == 'POST':
		smtp_setting = EmailSetting.objects.get(id=1)
		update  = UpdateSMTPForm(request.POST, instance = smtp_setting)
		if update.is_valid():
			update.save()
			new_setting = EmailSetting.objects.get(id=1)
			settings.EMAIL_HOST = new_setting.EMAIL_HOST
			settings.EMAIL_USE_TLS = new_setting.EMAIL_USE_TLS
			settings.EMAIL_PORT = new_setting.EMAIL_PORT
			settings.EMAIL_HOST_USER = new_setting.EMAIL_HOST_USER
			if new_setting.EMAIL_HOST_PASSWORD is not None:
				settings.EMAIL_HOST_PASSWORD = new_setting.EMAIL_HOST_PASSWORD
			return redirect ('/smtp_setting',{'user_auth': True})
	return render (request, 'smtp_setting.html',{'error': [('Update SMTP setting failed!')], 'user_auth': True})

def defense_setting(request,case='None'):
	if request.user.is_authenticated != True:
		return redirect ('/login/?next=/defense_setting')
	if request.method == 'GET' and case == 'None':
		port_scan1_settings = DefenseSetting.objects.filter(name__contains='Port_Scan1')
		port_scan2_settings = DefenseSetting.objects.filter(name__contains='Port_Scan2')
		Vul_Scan1_settings = DefenseSetting.objects.filter(name__contains='Vul_Scan1')
		month_logs_settings = DefenseSetting.objects.filter(name__contains='x_month_logs')
		month_blacklist_settings = DefenseSetting.objects.filter(name__contains='x_month_inactive_blacklist')
		return render (request, 'defense_setting.html', 
			{'port_scan1_settings': port_scan1_settings,
			'port_scan2_settings': port_scan2_settings,
			'Vul_Scan1_settings': Vul_Scan1_settings,
			'month_logs_settings': month_logs_settings,
			'month_blacklist_settings': month_blacklist_settings,
			})
	elif request.method == 'GET' and case != 'None':
		if case == 'case1':
			port_scan1_settings = DefenseSetting.objects.filter(name__contains='Port_Scan1')
			port_scan1_settings_formset = DefenseSettingFormSet(queryset=port_scan1_settings)
			return render (request, 'defense_setting.html', {'port_scan1_settings_formset':port_scan1_settings_formset})
		if case == 'case2':
			port_scan2_settings = DefenseSetting.objects.filter(name__contains='Port_Scan2')
			port_scan2_settings_formset = DefenseSettingFormSet(queryset=port_scan2_settings)
			return render (request, 'defense_setting.html', {'port_scan2_settings_formset':port_scan2_settings_formset})
		if case == 'case3':
			vul_scan1_settings = DefenseSetting.objects.filter(name__contains='Vul_Scan1')
			vul_scan1_settings_formset = DefenseSettingFormSet(queryset=vul_scan1_settings)
			return render (request, 'defense_setting.html', {'vul_scan1_settings_formset':vul_scan1_settings_formset})
		if case == 'month_logs':
			month_logs_settings = DefenseSetting.objects.filter(name__contains='x_month_logs')
			month_logs_settings_formset = DefenseSettingFormSet(queryset=month_logs_settings)
			return render (request, 'defense_setting.html', {'month_logs_settings_formset':month_logs_settings_formset})
		if case == 'month_blacklist':
			month_blacklist_settings = DefenseSetting.objects.filter(name__contains='x_month_inactive_blacklist')
			month_blacklist_settings_formset = DefenseSettingFormSet(queryset=month_blacklist_settings)
			return render (request, 'defense_setting.html', {'month_blacklist_settings_formset':month_blacklist_settings_formset})
	elif request.method == 'POST':
		setting_forms = DefenseSettingFormSet(request.POST)
		if setting_forms.is_valid():
			if 'case1_save' in request.POST or 'case2_save' in request.POST:
				for form in setting_forms:
					value = form.cleaned_data['value']
					if value < 0:
						return render (request, 'defense_setting.html', {'error':"Invaid input value!"})
			elif 'case3_save' in request.POST:
				for form in setting_forms:
					value = form.cleaned_data['value']
					if value>=3 or value<0:
						return render (request, 'defense_setting.html', {'error':"Invaid input value!"})
			elif 'month_logs_save' or 'month_blacklist_save' in request.POST:
				for form in setting_forms:
					value = form.cleaned_data['value']
					if value < 1 :
						return render (request, 'defense_setting.html', {'error':"Invaid input value!"})
			setting_forms.save()
			return redirect('defense_setting')
	return render (request, 'defense_setting.html', {'error':"Invaid form returned"})
		