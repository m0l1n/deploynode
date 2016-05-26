#!/usr/bin/python3
#-*- coding: utf-8 -*-

import paramiko
from subprocess import Popen,PIPE
import subprocess
from pexpect import pxssh

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
user = "root"
passd = "root"
ip = "10.0.0.5"

#key = paramiko.DSSKey.from_private_key_file('/root/.ssh/id_rsa.pub')
string = 'mamama \
mia'
remoteCmd = 'suricata | head -n1'
try :
    ssh.connect(ip,username='root')
   # sftp = ssh.open_sftp()
    #file = sftp.open('/etc/sysctl.conf')

    #ssh2 = pxssh.pxssh()
    #ssh2.login(ip, user)
    # ssh2.set_unique_prompt()
    # for l in sftp.listdir('/home/'):
    #     print (l)
    # try :
    #     sftp.chdir('/home')
    #     print('Directory already exist...')
    # except IOError:
    #     print('Directory no...')

    # ssh2.sendline('apt-get update && apt-get install -y logstash')
    # ssh2.prompt()
    print("go")
    #chan = ssh.get_transport().open_session()
    #stdin, stdout, stderr = ssh.exec_command('apt-get update')
    #print("exit:" + str(stdout.channel.recv_exit_status()))
    stdin,stdout,stderr = ssh.exec_command('DEBIAN_FRONTEND=noninteractive apt-get install -y logstash')
    print("exit:"+ str(stdout.channel.recv_exit_status()))
    print(stdout.read().decode('utf-8'))
    print(stderr.read().decode('utf-8'))
    print("done?")

    # stdin, stdout, stderr = ssh.exec_command(remoteCmd)
    # suriVersion = stdout.read()

    # print(suriVersion)
    # if 'Suricata' in str(suriVersion):
    #     print('haha')
    # try:
    #     with sftp.open('/etc/sysctl.conf') as f:
    #         if '#Ipv6 now Disabled' in f.read().decode("utf-8"):
    #             print('...Ipv6 is already disabled on the system')
    # finally:
    #     file.close()
    #sftp.put('./hihi','/home/debuser/lol')

except Exception as e:
    print('error:'+str(e))

#try:
    #subprocess.call(['ls','/root/.ssh/'])
 #   subprocess.call(['ssh-copy-id', '-i', '/root/.ssh/id_rsa.pub',id])
    #stdout = p.communicate()[0]
#except Exception as e:
 #   print('error',e)


# Commande cool pour mettre notre clé sur le serv :
# cat ~/.ssh/id_rsa.pub | ssh user@remote 'dd of=.ssh/authorized_key oflag=append conv=notrunc'

