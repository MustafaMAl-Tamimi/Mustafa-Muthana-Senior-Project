This is the 2nd part of my SOC (Security Operations Center) Automation with Python Project. I've implemented an automated script that checks the /Var auth.log for any signs of brute for attacks.
The Auth.log file is an important file on Linux systems that provides the analyst with a treasure cove of telemetry and information regarding who tried to log in 
and to what and when. This script was created to automatically read through this log file and display all relevant information like failed and successful logins, from which IP 
and to which user, and any specific IP that exceeds the maximum number of valid logins, plus to detect if any of those using brute force have successfully logged in and to what account. 

~~Instructions~~

1- Install an SSH Service

sudo apt update
sudo apt install -y openssh-server rsyslog
sudo systemctl enable --now ssh
sudo systemctl enable --now rsyslog

2- Simulate Brute Force Logon

for i in {1..6}; do
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      testuser@<TARGET_IP> exit
done

3- Keep Entering Wrong Password Then Run The Script

sudo python3 p2-fin.py

*Make Sure to give it Sudo Privilages to Access the Auth.log File..

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
