from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from Syslog.models import Logfile, PATrafficLog, JobLock, Blacklist, DefenseSetting
from datetime import datetime, timedelta
from django.utils import timezone
from dateutil import parser
from Syslog import defense
import os, subprocess, time, re, logging

logger = logging.getLogger('mySchedulerLog')

jobstores = {'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')}
scheduler = BackgroundScheduler(jobstores=jobstores)
def SaveLogToDB ():
	for log in Logfile.objects.all():
		if log.type == 'Firewall':
			file = log.path
			try:
				open_file = open(file+'.tmp','r')
				for line in open_file.readlines():
					Hostname = log.name
					SrcLocation=re.search('SrcLocation=([^;]+)',line).group(1).strip()
					SrcIP = re.search('SrcIP=([^;]+)', line).group(1).strip()
					SrcPort = re.search('SrcPort=([^;]+)', line).group(1).strip()
					SrcUser = re.search('SrcUser=([^;]*)', line).group(1).strip() if re.search('SrcUser=([^;]*)', line) else '-'
					DstLocation = re.search ('DstLocation=([^;]+)', line).group(1).strip()
					DstIP = re.search ('DstIP=([^;]+)', line).group(1).strip()
					DstPort = re.search ('DstPort=([^;]+)', line).group(1).strip()
					Action = re.search ('Action=([^;]+)', line).group(1).strip()
					RuleName = re.search ('RuleName=([^;]+)', line).group(1).strip()
					RuleID = re.search ('RuleID=([^;]+)', line).group(1).strip()
					TimeReceived = re.search ('TimeReceived=([^;]+)', line).group(1).strip()
					ThreatName = re.search ('ThreatName=([^;]+)', line).group(1).strip() if re.search('ThreatName=([^;]*)', line) else '-'
					ThreatID = re.search ('ThreatID=([^;]+)', line).group(1).strip() if re.search('ThreatID=([^;]*)', line) else '-'
					Severity = re.search ('Severity=([^;]+)', line).group(1).strip() if re.search('Severity=([^;]*)', line) else '-'
					Subtype = re.search ('Subtype=([^;]+)', line).group(1).strip() if re.search('Subtype=([^;]*)', line) else '-'
					LogType = re.search ('Type=([^;]+)', line).group(1).strip() if re.search('Type=([^;]*)', line) else 'TRAFFIC'
					if '$' in ThreatName:
						ThreatName = '-'
					if '$' in ThreatID:
						ThreatID = '-'
					if '$' in Severity:
						Severity = '-'
					PATrafficLog.objects.create (
						logfile = log,
						Hostname = Hostname,
						SrcLocation = SrcLocation,
						SrcIP = SrcIP,
						SrcPort = SrcPort,
						SrcUser = SrcUser,
						DstLocation = DstLocation,
						DstIP = DstIP,
						DstPort = DstPort,
						Action = Action,
						RuleName = RuleName,
						RuleID = RuleID,
						TimeReceived = TimeReceived,
						ThreatName = ThreatName,
						ThreatID = ThreatID,
						Severity = Severity,
						Subtype = Subtype,
						LogType = LogType,
					)
				os.remove(file+'.tmp')
				logger.debug ('SaveLogToDB completed!')
			except Exception as e:
				job_lock = JobLock.objects.get(job_name='FletchLog')
				job_lock.is_running = False
				job_lock.save()
				logger.debug ('SaveLogToDB exception: '+str(e))
				return
def FletchLog():
	job_lock, created = JobLock.objects.get_or_create(job_name="FletchLog")
	if job_lock.is_running:
		return
	for logfile in Logfile.objects.all():
		try:
			if os.path.exists(logfile.path+'.tmp'):
				os.remove (logfile.path+'.tmp')
			if os.path.exists(logfile.path) and os.path.getsize(logfile.path) != 0:
				os.rename(logfile.path, logfile.path+'.tmp') # rename the file for converting to DB
				new = os.open(logfile.path, os.O_CREAT) #recreate the log file for Rsyslog to save on going logs
				os.close(new)
				subprocess.run(['chmod', '777', logfile.path])
				time.sleep(5)
				subprocess.run(['sudo', 'systemctl', 'restart', 'rsyslog.service']) #restart the rsyslog service to adapt the newly created file
		except OSError as e:
			logger.debug('Fletchlog exception: '+str(e))
	time.sleep(30)
	job_lock.is_running = True
	job_lock.save()
	logger.debug ('Fletch logs to DB started!')
	SaveLogToDB() #convert the logs into DB for analysing
	job_lock.is_running = False
	job_lock.save()
	logger.debug ('Successfully saved logs to DB!')

def remove_old_blacklist():
	x_month_inactive_blacklist = DefenseSetting.objects.get (name = 'x_month_inactive_blacklist')
	try:
		one_month_ago = timezone.now() - timedelta(days=x_month_inactive_blacklist.value * 30)
		old_entries = Blacklist.objects.filter(LastSeen__lt=one_month_ago).exclude(Alert__contains='user added')
		old_entries.delete()
	except Exception as e:
		logger.debug ('Remove_old_blacklist exception: '+str(e))

def delete_old_logs():
	x_month_logs = DefenseSetting.objects.get (name = 'x_month_logs')
	try:
		six_months_ago = timezone.now() - timedelta(days=x_month_logs.value * 30)
		PATrafficLog.objects.filter(Created_at__lt=six_months_ago).delete()
	except Exception as e:
		logger.debug ('Delete_old_logs exception: '+str(e))

def run():
	global scheduler
	if not job_exists('FletchLog_id01'):
		scheduler.add_job(FletchLog, 'interval', minutes = 5, max_instances = 1, misfire_grace_time=60, id = 'FletchLog_id01', replace_existing=True)
		time.sleep(30)
	if not job_exists('defense_id01'):
		scheduler.add_job(defense.run, 'interval', minutes = 5, max_instances = 1, misfire_grace_time=60, id = 'defense_id01', replace_existing=True)
	if not job_exists('remove_old_blacklist_id01'):
		scheduler.add_job(remove_old_blacklist, CronTrigger(hour = 0, minute = 0, timezone = 'Australia/Sydney'), max_instances = 1, misfire_grace_time=60, id = 'remove_old_blacklist_id01', replace_existing=True)
	if not job_exists('delete_old_logs_id01'):
		scheduler.add_job(delete_old_logs, CronTrigger(hour = 1, minute = 0, timezone = 'Australia/Sydney'), max_instances = 1, misfire_grace_time=60, id = 'delete_old_logs_id01', replace_existing=True)
	if not scheduler.running:
		scheduler.start()

def remove_old_jobs():
	global scheduler
	jobs = scheduler.get_jobs()
	for job in jobs:
		scheduler.remove_job(job.id) #clean up any old running jobs before it starts
		
def job_exists(job_id):
	global scheduler
	job = scheduler.get_job(job_id)
	if job:
		return True
	return False

def has_jobs():
	global scheduler
	if len(scheduler.get_jobs()) == 0:
		return False
	return True