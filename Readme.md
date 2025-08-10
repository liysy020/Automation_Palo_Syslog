# Contents {#contents .TOC-Heading}

[Introduce Active Defense Syslog
[1](#introduce-active-defense-syslog)](#introduce-active-defense-syslog)

[Install Active Defense Syslog System
[3](#install-active-defense-syslog-system)](#install-active-defense-syslog-system)

[Assume you have an Ubuntu server installed and enabled SSH with full
access
[3](#assume-you-have-an-ubuntu-server-installed-and-enabled-ssh-with-full-access)](#assume-you-have-an-ubuntu-server-installed-and-enabled-ssh-with-full-access)

[To make sure your server can utilize all disk space
[3](#to-make-sure-your-server-can-utilize-all-disk-space)](#to-make-sure-your-server-can-utilize-all-disk-space)

[Rsyslog application which is available out-of-box with Ubuntu server.
[3](#rsyslog-application-which-is-available-out-of-box-with-ubuntu-server.)](#rsyslog-application-which-is-available-out-of-box-with-ubuntu-server.)

[Install Django Framework
[4](#install-django-framework)](#install-django-framework)

[Create virtual environment and install Django
[4](#create-virtual-environment-and-install-django)](#create-virtual-environment-and-install-django)

[Create web applications and install dependent libraries
[5](#create-web-applications-and-install-dependent-libraries)](#create-web-applications-and-install-dependent-libraries)

[Copy the source code files and install the system
[5](#copy-the-source-code-files-and-install-the-system)](#copy-the-source-code-files-and-install-the-system)

[Start the application
[7](#start-the-application)](#start-the-application)

[Setup and configure the web server
[8](#setup-and-configure-the-web-server)](#setup-and-configure-the-web-server)

[Setup Palo Firewall and forward the logs
[9](#setup-palo-firewall-and-forward-the-logs)](#setup-palo-firewall-and-forward-the-logs)

[Setup syslog at Palo firewall
[9](#setup-syslog-at-palo-firewall)](#setup-syslog-at-palo-firewall)

[Create blacklist address object
[10](#create-blacklist-address-object)](#create-blacklist-address-object)

[Create the Active Defense policies
[11](#create-the-active-defense-policies)](#create-the-active-defense-policies)

[• The Fist policy needs to be at the top position
[11](#the-fist-policy-needs-to-be-at-the-top-position)](#the-fist-policy-needs-to-be-at-the-top-position)

[• The Second policy needs to be at the bottom position
[11](#_Toc203208858)](#_Toc203208858)

[• Apply the ActiveDefense syslog to all other Internet facing policy
such as the Globalprotect one as below
[12](#apply-the-activedefense-syslog-to-all-other-internet-facing-policy-such-as-the-globalprotect-one-as-below)](#apply-the-activedefense-syslog-to-all-other-internet-facing-policy-such-as-the-globalprotect-one-as-below)

[Setup Active Defense Syslog
[12](#setup-active-defense-syslog)](#setup-active-defense-syslog)

[Login to GUI and change password or create your own account
[12](#login-to-gui-and-change-password-or-create-your-own-account)](#login-to-gui-and-change-password-or-create-your-own-account)

[Setup SMTP server and recipients for notification. System will email
recipients if new IP address added to blacklist (optional)
[12](#setup-smtp-server-and-recipients-for-notification.-system-will-email-recipients-if-new-ip-address-added-to-blacklist-optional)](#setup-smtp-server-and-recipients-for-notification.-system-will-email-recipients-if-new-ip-address-added-to-blacklist-optional)

[Find and add the syslog file location
[12](#find-and-add-the-syslog-file-location)](#find-and-add-the-syslog-file-location)

[Tune the Active Defense settings to meet your need under mane
"ActiveDefense Settings"
[13](#tune-the-active-defense-settings-to-meet-your-need-under-mane-activedefense-settings)](#tune-the-active-defense-settings-to-meet-your-need-under-mane-activedefense-settings)

[Start the system and verify running
[13](#start-the-system-and-verify-running)](#start-the-system-and-verify-running)

[Limitation [15](#limitation)](#limitation)

# Introduce Active Defense Syslog

This Active Defense application is an Internet traffic forced syslog
system. It was built base on Palo Alto firewall and it mainly looks at
traffic coming from internet and find out any IP / port scanning and
vulnerability attack attempt activities and instructs the firewall to
perform an explicit block action.

An example of how policy configuration makes use of this Active Defense
system. The top policy to block IP addresses that match the Blacklist
address object which provided by Active Defense system. The bottom
policy will feed all un-matched / implicit blocked traffic, plus all
other public facing policies' logs to the system for data analysing
where a Blacklist-IP will be produced.

![](media/image1.png){width="6.268055555555556in"
height="0.8902777777777777in"}

An example of list of bad guys. And the detail of why they got
blacklisted. Firewall will block these public IPs by rule 1 above.

![](media/image2.png){width="3.1226246719160105in"
height="3.5196325459317586in"}

![](media/image3.png){width="4.197916666666667in"
height="3.0123982939632548in"}

![](media/image4.png){width="6.268055555555556in"
height="3.0819444444444444in"}

Finally, user can tune the settings of how Defense engine to run. Such
as the number of ports per certain mins to be defined as port scan
activity. Blacklist public IP that triggered Critical-level or
High-level vulnerability attempts. Keeping firewall logs for number of
months and remove blacklist IP after number of months without being
detected with any bad activity.

![](media/image5.png){width="4.884082458442695in"
height="3.9463331146106735in"}

# Install Active Defense Syslog System

## Assume you have an Ubuntu server installed and enabled SSH with full access

-   Ubuntu server. 24.04.02

## To make sure your server can utilize all disk space

> sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv\
> sudo resize2fs /dev/mapper/ubuntu\--vg-ubuntu\--lv

## Rsyslog application which is available out-of-box with Ubuntu server. 

-   Edit file "*sudo nano /etc/rsyslog.conf*"

    -   Find and un-hash below two line:\
        module(load=\"imudp\")

> input(type=\"imudp\" port=\"514\")

-   Add below 3 lines to the end of the file

> *\$template firewall,\"/var/log/Firewall/%HOSTNAME%.log\"*
>
> *if \$fromhost != \'Whatever-the-server-hostname-is\' then ?firewall*
>
> *& stop*

-   Create a folder for storing logs and give full access permission to
    all users

> *sudo mkdir /var/log/Firewall*
>
> *sudo chmod 777 /var/log/Firewall*

-   Give the application the ability to restart the Rsyslog service

    -   Edit file "sudo nano /etc/sudoers" add below line to the end of
        the file

> *ALL ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart rsyslog.service*

-   Restart and verify Rsyslog service.

> *sudo systemctl restart rsyslog.service*
>
> *systemctl status rsyslog.service*

![](media/image6.png){width="6.268055555555556in"
height="1.6270833333333334in"}

## Install Django Framework

> *sudo apt-get update*
>
> *sudo apt-get install python3-django*
>
> *sudo apt-get install python3-pip python3-venv*

## Create virtual environment and install Django

> *cd /*
>
> *sudo mkdir Automation*
>
> *sudo chmod 777 Automation*
>
> *python3 -m venv Automation*
>
> *cd Automation*
>
> *source bin/activate*
>
> *pip3 install Django*

![](media/image7.png){width="6.268055555555556in"
height="4.084722222222222in"}

## Create web applications and install dependent libraries

-   Perform below commands under directory /Automation within the
    virtual environment

> *django-admin startproject ActiveDefense .*
>
> *python3 manage.py startapp Login*
>
> *python3 manage.py startapp Syslog*
>
> *pip3 install pathlib netifaces datetime apscheduler sqlalchemy*
>
> *pip3 install python-dateutil gunicorn*

## Copy the source code files and install the system

We will use sftp to cory the source files into created directories from
above

If you are using windows computer you can use MoxaXterm free application
to do this. Linux user can perform this task natively using Terminal.

-   Start from the directory where you have downloaded source files.
    SFTP to the server. Copy and override everything into the remote
    server with below command

> *cd /\<the directory on your local computer where you downloaded the
> source code\>*
>
> *sftp user@\<server IP\>*
>
> *cd /Automation*
>
> *put -R \**
>
> *exit*

-   Install / create PostgreSQL database engine with below command

> sudo apt install postgresql postgresql-contrib libpq-dev
>
> source /Automation/bin/activate
>
> pip3 install psycopg2-binary

-   create Database

> sudo -u postgres psql
>
> SQL commands below:
>
> CREATE DATABASE activedefense;
>
> CREATE USER activedefenseuser WITH PASSWORD \'activedefensepassword;
>
> ALTER ROLE activedefenseuser SET client_encoding TO \'utf8\';
>
> ALTER ROLE activedefenseuser SET default_transaction_isolation TO
> \'read committed\';
>
> ALTER ROLE activedefenseuser SET timezone TO \'Australia/Sydney\';
>
> ALTER ROLE activedefenseuser WITH CREATEDB;
>
> GRANT ALL PRIVILEGES ON DATABASE activedefense TO activedefenseuser;
>
> ALTER DEFAULT PRIVILEGES IN SCHEMA public
>
> GRANT ALL PRIVILEGES ON TABLES TO activedefenseuser;
>
> \\q

-   Temporary rename the app.py file to avoid error during the database
    initial setup

> *cd /Automation/Syslog*
>
> *mv apps.py apps.py.tmp*
>
> *cd ..*

-   create Database

> *python3 manage.py makemigrations*

![](media/image8.png){width="6.268055555555556in"
height="1.7458333333333333in"}

> *python3 manage.py migrate*

![](media/image9.png){width="5.958333333333333in"
height="3.8541666666666665in"}

-   Create superuser

> *python3 manage.py createsuperuser*

![](media/image10.png){width="6.268055555555556in"
height="1.1416666666666666in"}

-   Rename the apps.py.tmp back to apps.py

> *cd /Automation/Syslog/*
>
> *mv apps.py.tmp apps.py*
>
> *cd ..*

## Start the application

-   Apply executable permissions to startup scripts

> *chmod +x /Automation/run.sh\**

-   Setup auto start \@reboot

> *sudo nano /etc/crontab*

-   add below line to the bottom and save / exit

> *\@reboot user /bin/bash -c \"/Automation/run.sh\"*

## Setup and configure the web server

-   Setup Nginx (Engine X) as front-end web server

    -   Install Nginx

> *sudo apt-get install nginx*

-   Setup web site in nginx by creating file "django" in
    /etc/nginx/sites-available/

> sudo nano /etc/nginx/sites-available/django

-   Copy below to the file, save and exit

> *server {*
>
> *listen 443 ssl;*
>
> *server_name \<server FQDN or IP Address\>;*
>
> *ssl_certificate /Automation/Cert/server.crt;*
>
> *ssl_certificate_key /Automation/Cert/server.key;*
>
> *location / {*
>
> *proxy_pass http://127.0.0.1:8000;*
>
> *proxy_set_header Host \$host;*
>
> *proxy_set_header X-Real-IP \$remote_addr;*
>
> *proxy_set_header X-Forwarded-For \$proxy_add_x\_forwarded_for;*
>
> *proxy_set_header X-Forwarded-Proto \$scheme;*
>
> *}*
>
> *location /static/ {*
>
> *alias /Automation/static/;*
>
> *}*
>
> *}*
>
> *server {*
>
> *listen 80;*
>
> *server_name your.domain.or.ip;*
>
> *return 301 https://\$host\$request_uri;*
>
> *}*

-   Start Nginx

> *sudo ln -s /etc/nginx/sites-available/django
> /etc/nginx/sites-enabled/*
>
> *sudo nginx -t\
> sudo systemctl restart nginx*

-   Set correct timezone before Rebooting the server.

> *sudo timedatectl set-timezone \<local timezone such as
> Australia/Sydney\>*
>
> *sudo reboot now*

-   The system will startup automatically. Access the application using:

> <https://server-ip-address>
>
> username password has been created as superuser above

# Setup Palo Firewall and forward the logs

## Setup syslog at Palo firewall

Device Server Profiles Syslog Add new

Add the IP address of the Defense system as syslog server. Copy below
log format string to both Thread and Traffic log type

*SrcLocation=\$srcloc; SrcIP=\$src; SrcPort=\$sport; SrcUser=\$srcuser;
DstLocation=\$dstloc; DstIP=\$dst; DstPort=\$dport; Action=\$action;
RuleName=\$rule; RuleID=\$rule_uuid; TimeReceived=\$time_received;
ThreatName=\$threat_name; ThreatID=\$threatid; Severity=\$severity;
Subtype=\$subtype; Type= \$type;*

![](media/image11.png){width="5.981701662292213in"
height="3.416979440069991in"}

Objects Log Forwarding Add new

![](media/image12.png){width="6.268055555555556in"
height="3.0708333333333333in"}

## Create blacklist address object

Objects External Dynamic Lists Add new

Type: [IP List]{.underline}

Source: [https://\<server-IP\>/files/blacklist.txt]{.underline}

Check for update: [Every 5 mins]{.underline}

![](media/image13.png){width="6.208333333333333in"
height="3.8854166666666665in"}

## Create the Active Defense policies

-   ### The Fist policy needs to be at the top position

Source Zone: Internet/Untrust

Source: address: \<ActiveDefense Blacklist created at above\>

Destination Zone: any

Destination Address: any

Action: Deny

Log forward: \<ActiveDefense Syslog\>

*Note: [best practice is to forward the blocked logs. System will know
if any known blacklisted IPs are still attacking you. System will reset
its time within the block-window (default 1 month). Otherwise, system
will remove it after block-window regardless. Eventually it will get
block again as a new IP]{.underline}*

![](media/image14.png){width="6.268055555555556in"
height="0.35555555555555557in"}

-   []{#_Toc203208858 .anchor}The Second policy needs to be at the
    bottom position.

This policy needs to be at the bottom whenever new policy adds in the
future. Basically, it captures all un-matched traffic and forward the
logs to the syslog.

Source Zone: Internet / Untrust

Source Address: any

Destination Zone: any

Action: Deny or reset

Log forward: \<ActiveDefense Syslog\>

*Note: [We need to forward all un-matched traffic that ActiveDefense can
tell if anyone trying to do port scanning on you. If you don't have this
catch-all rule. ActiveDefense can only block vulnerability detected
IP.]{.underline}*

![](media/image15.png){width="6.268055555555556in"
height="0.38055555555555554in"}

-   ### Apply the ActiveDefense syslog to all other Internet facing policy such as the Globalprotect one as below

![](media/image16.png){width="6.268055555555556in"
height="1.7055555555555555in"}

*Note: ActiveDefense will find out if anyone try to do vulnerability
attack to you and blacklist them. This type of policy usually has
security Profile attached such as Vulnerability Protection etc.*

Commit all above changes and firewall is completed.

# Setup Active Defense Syslog

## Login to GUI and change password or create your own account

> https://\<server-ip\>/admin

![](media/image17.png){width="6.268055555555556in"
height="1.5340277777777778in"}

## Setup SMTP server and recipients for notification. System will email recipients if new IP address added to blacklist (optional)

## Find and add the syslog file location

New log data will be saved at /var/log/Firewall/ directory before
converting into Database records. The log file name is the hostname of
the firewall with extension ".log"

You can SSH to the server with provided (above) and find out the log
files.

*Command: ls /var/log/Firewall/*

Register the log file and path to the system

![](media/image18.png){width="6.268055555555556in"
height="2.876388888888889in"}

## Tune the Active Defense settings to meet your need under mane "ActiveDefense Settings"

-   Defense case 1 -- port scanning (multiple ports)

> Default setting. It is targeting a single public IP being trying with
> more than 10 ports in the last 10mins window. You can relax it by
> increase number of ports or lower down the time. Such as 20+ ports or
> in 8 mins. Be aware that the defence engineer runs every 5 mins. If
> time set to lower than 5 mins. It will skip logs

-   Defense case 2 -- Port scanning (multiple IPs)

> Default setting: system will find out if someone try to find out open
> ports on all of your public IPs. Such as targeting https port (443) on
> all your public IPs. It set to 10 of your public IP being tried on
> single port in the last 10 mins. You can relax it by increase the
> number of public IPs or reduce time. If you don't own multiple public
> IPs. You can disable this by setting the time to 0.

-   Defense case 3 -- Vulnerability detection

> By default. It blacklists any external public IP who had triggered
> "Critical" vulnerability alerts. You can make it more aggressive to
> set the value to 2. It will also blacklist someone triggered "High"
> vulnerability alert. Set to 0 to disable this function if you don't
> have Threat protection on your firewall.

-   The other two settings are Database keeping.

> By default, it set to keep 3 month's log records and release the
> blacklisted IP if it has been doing bad thing in a month.

# Start the system and verify running

"System On Off" is to start or restart the scheduled jobs when need. If
you can see any new traffic logs in "Syslog Records". Do a "Reset" and
"start". It will restart the defense engine. The logs will aways be
received even the engine is not running. It will keep in
/var/log/Firewall. the log file will grow until the engine runes again.
Logs will convert into DB and the log file size gets reduce.

The engine will not auto start when you restart the server. You will
need to login to the GUI and start the defense system manually or "reset
/ start" it every time you rebooted the server.

![](media/image19.png){width="3.6009219160104986in"
height="1.6846883202099738in"}

To verify it's running. You can simply look at the last 24 hours logs.
confirm by the time of the record

Or SSH to the server and look at the log file size. A .tmp file will be
created when the system converts the logs into Database. Then the log
file will get reduced and the .tmp file should be gone after the
scheduled job completed. It runs every 5 mins.

![](media/image20.png){width="4.3192989938757655in"
height="2.9932666229221345in"}

![](media/image21.png){width="5.2671926946631675in"
height="3.11619750656168in"}

## Limitation

If you have large amount to logs and the server can not process it
within 5 mins. Then you need a faster system to keep up with the log
growing. Spead to multiple servers for multiple firewalls. Or external
the scheduling time to every 10mins for example. It will require edit to
the source code:

/Automation/Syslog/scheduler.py

![](media/image22.png){width="6.268055555555556in"
height="1.5680555555555555in"}

Note: the "sleep time" is the gap between two jobs. Database gets lock
every action. Job gets delay automatically when DB gets locked. Graceful
period of 1 mins before the job gives up and wait for next run.
