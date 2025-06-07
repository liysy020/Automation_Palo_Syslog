from Syslog.models import PATrafficLog, Blacklist, JobLock, Recipient, DefenseSetting, EmailSetting
from django.conf import settings
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from dateutil import parser
import re, time, os, logging
from pathlib import Path

logger = logging.getLogger('defenseLog')

def contains_number(s):
	return bool(re.search(r'\d', s))

# case1 Port Scan Attack:
# If an external public IP trying reach the same company owned public IP on multiple destination ports (more than 10) within 10mins
# This external public IP will be add to Blacklist database
def port_scan1():
	x_min = DefenseSetting.objects.get(name = 'Port_Scan1_x_min')
	if x_min.value == 0:
		logger.debug ('Port scan case 1 has been disabled!')
		return
	x_dstPort = DefenseSetting.objects.get(name = 'Port_Scan1_x_dstPort')
	ten_minutes_ago = timezone.localtime(timezone.now()) - timedelta(minutes=x_min.value)
	last_10min_logs = []
	for log in PATrafficLog.objects.filter(LogType='TRAFFIC',Created_at__gte = ten_minutes_ago): #filter the last x mins saved logs
		try:
			time_received = parser.parse(log.TimeReceived)
		except:
			continue
		if time_received.tzinfo is None:
			time_received = timezone.make_aware(time_received, timezone.get_current_timezone())
		if time_received >= ten_minutes_ago: #filter the last x mins of logs
			last_10min_logs.append(log)
	srcIP = ''
	dstIP = ''
	dstPorts = []
	total_blacklist = ''
	for log in last_10min_logs: #comparing source IP and destination IPs if they are the same
		if not contains_number(log.SrcLocation): #public IP only
			if srcIP == '':
				srcIP = log.SrcIP
				dstIP = log.DstIP
				continue
			elif not Blacklist.objects.filter(IP=srcIP).exists():
				for compare in last_10min_logs:
					if srcIP == compare.SrcIP and dstIP == compare.DstIP and compare.DstPort not in dstPorts:
						dstPorts.append(compare.DstPort)
				if len(dstPorts) >= x_dstPort.value:
					Blacklist.objects.create(Alert = 'Port Scan Attack v1', IP = srcIP) # create a blacklist record
					if Blacklist.objects.filter(IP = srcIP).exists():
						total_blacklist += srcIP + ' from '+ log.SrcLocation + '\n'
						logger.debug ('Defense port scan case 1 found '+ srcIP )
					else:
						logger.debug ('Defense port scan case 1 failed to add '+srcIP+' to Blacklist DB')
				srcIP = ''
				dstIP = ''
				dstPorts = []
			elif Blacklist.objects.filter(IP=srcIP).exists():
				Blacklist.objects.get(IP=srcIP).save() #update the autotime / last seen to now
				srcIP = ''
				dstIP = ''
				dstPorts = []
	if not total_blacklist =='':
		send_notification ('Defense Alert: Port scan alert','Port scan activity detected below list of public IPs and blacklisted:\n'+total_blacklist)
		logger.debug ('Port scan case 1: email notification sent!')
	logger.debug ('Port Scan case 1 completed successfully!')

# case2 Port Scan Attack:
# If an external public address tried to access a same dst port for more than 10 different company owned public IPs within 10mins.
# This external public IP will be added to Blacklist
def port_scan2():
	x_min = DefenseSetting.objects.get(name = 'Port_Scan2_x_min')
	if x_min.value == 0:
		logger.debug ('Port Scan case 2 has been disabled!')
		return
	x_dstIP = DefenseSetting.objects.get(name = 'Port_Scan2_x_dstIP')
	ten_minutes_ago = timezone.localtime(timezone.now()) - timedelta(minutes=x_min.value)
	last_10min_logs = []
	for log in PATrafficLog.objects.filter(LogType='TRAFFIC',Created_at__gte = ten_minutes_ago): #filter the last x mins saved logs
		try:
			time_received = parser.parse(log.TimeReceived)
		except:
			continue
		if time_received.tzinfo is None:
			time_received = timezone.make_aware(time_received, timezone.get_current_timezone())
		if time_received >= ten_minutes_ago: #filter last x mins of logs
			last_10min_logs.append(log)
	dstPort = ''
	srcIP = ''
	dstIPs = []
	total_blacklist = ''
	for log in last_10min_logs:
		if not contains_number(log.SrcLocation):#public IP only
			if srcIP == '':
				srcIP = log.SrcIP
				dstPort = log.DstPort
				continue
			elif not Blacklist.objects.filter(IP=srcIP).exists(): #new public IP that has not been seen
				for compare in last_10min_logs:
					if srcIP == compare.SrcIP and dstPort == compare.DstPort and compare.DstIP not in dstIPs:
						dstIPs.append(compare.DstIP)
				if len (dstIPs) >= x_dstIP.value:
					Blacklist.objects.create(Alert = 'Port Scan Attack v2', IP = srcIP)
					if Blacklist.objects.filter(IP = srcIP).exists():
						total_blacklist += srcIP+ ' from '+ log.SrcLocation +'\n'
						logger.debug ('Defense port scan case 2 found '+ srcIP)
					else:
						logger.debug ('Defense port scan case 2 failed to add '+srcIP+' to Blacklist DB')
				dstPort = ''
				srcIP = ''
				dstIPs = []
			elif Blacklist.objects.filter(IP=srcIP).exists(): #the public IP has been record in blacklist before
				bl = Blacklist.objects.get(IP=srcIP)
				bl.Alert = 'Port Scan Attack v2'
				bl.save()
				dstPort = ''
				srcIP = ''
				dstIPs = []
	if not total_blacklist =='':
		send_notification ('Defense Alert: IP scan alert','IP scan activity detected below list of public IPs and blacklisted:\n'+total_blacklist)
		logger.debug ('Port scan case 2: email notification sent!')
	logger.debug ('Port Scan case 2 completed successfully!')

#If the firewall reported a critical vulnerability event from an external public IP via any policy. This public IP will be blacklisted
def vul_scan1():
	ten_minutes_ago = timezone.now() - timedelta(minutes=10)
	x_severity = DefenseSetting.objects.get(name = 'Vul_Scan1_x_severity')
	if x_severity.value == 1:
		levels = ['critical']
	elif x_severity.value == 2:
		levels = ['critical','high']
	else:
		logger.debug ('Vulnerability Scan case disabled!')
		return
	total_blacklist = ''
	for log in PATrafficLog.objects.filter(Created_at__gte=ten_minutes_ago):
		for severity_level in levels:
			if not contains_number(log.SrcLocation) and log.Severity == severity_level and not Blacklist.objects.filter(IP=log.SrcIP).exists():
				Blacklist.objects.create(Alert = 'Vulnerability Scan v1', IP = log.SrcIP)
				if Blacklist.objects.filter(IP = log.SrcIP).exists():
					total_blacklist += log.SrcIP+ ' from '+ log.SrcLocation+'\n'
					logger.debug ('Defense vulnerability scan case 1 found '+ log.SrcIP + ' sent email notification!')
				else:
					logger.debug ('Defense vulnerability scan case 1 failed to add '+log.SrcIP+' to Blacklist DB')
			elif not contains_number(log.SrcLocation) and log.Severity == severity_level and Blacklist.objects.filter(IP=log.SrcIP).exists():
				Blacklist_IP = Blacklist.objects.get(IP=log.SrcIP)
				Blacklist_IP.Alert = 'Vulnerability Scan v1'
				Blacklist_IP.save()
	if not total_blacklist =='':
		send_notification ('Defense Alert: Vulnerability scan alert', 'Vulnerability scan activity detected below public IP and blacklisted:\n'+total_blacklist)
		logger.debug ('Vulerability scan: email notification sent!')
	logger.debug ('Vulnerability Scan case 1 completed!')

#not being implemented as auto run function. use for initial setup or when it needs.
#it read through the whole database to find critical vulnerability alerts. 
def vul_scan_alllogs():
	for log in PATrafficLog.objects.filter(LogType='THREAT'):
		if not contains_number(log.SrcLocation) and log.Severity == 'critical' and not Blacklist.objects.filter(IP=log.SrcIP).exists():
			Blacklist.objects.create(Alert = 'Vulnerability Attack v1', IP = log.SrcIP)
			logger.debug ('Full scan: create new Blacklist '+ log.SrcIP)
		elif not contains_number(log.SrcLocation) and log.Severity == 'critical' and Blacklist.objects.filter(IP=log.SrcIP).exists():
			Blacklist_IP = Blacklist.objects.get(IP=log.SrcIP)
			Blacklist_IP.Alert = 'Vulnerability Attack v1'
			Blacklist_IP.save()
			logger.debug ('Full scan updated '+ log.SrcIP)

def write_to_blacklist_file():
	blacklist_file = os.path.join (settings.STATICFILES_DIRS[0],'blacklist.txt')
	#Cisco_blacklist_file = os.path.join (settings.STATICFILES_DIRS[0],'Cisco_blacklist_acl.txt')
	open_file1 = open(blacklist_file,'w')
	#open_file2 = open(Cisco_blacklist_file,'w')
	for list in Blacklist.objects.all():
		open_file1.write (list.IP+'\n')
	#	open_file2.write ('deny ip host '+list.IP+' any log\n')
	#open_file2.write ('permit ip any any log\n')
	open_file1.close()
	#open_file2.close()

def run():
	logger.debug ('Defense jobs started!')
	attempt = 0
	while attempt < 3:
		try:
			port_scan1()
			port_scan2()
			vul_scan1()
			write_to_blacklist_file()
			break
		except Exception as e:
			time.sleep(30)
			attempt += 1
			logger.debug ('Defense job retry '+ str(attempt)+': '+str(e))
			if attempt == 3:
				logger.debug ('Defense job retried '+ str(attempt)+' and failed: '+str(e))
				return
	logger.debug ('Defense jobs have finished successfully!')

def send_notification(sub,msg):
	if EmailSetting.objects.get(id=1).EMAIL_HOST == 'smtp.example.com':
		return
	try:
		receipients = Recipient.objects.all()
		send_mail(sub, msg, settings.EMAIL_HOST_USER, receipients)
	except Exception as e:
		logger.debug('send_notification exception: '+str(e))
