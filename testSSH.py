#!/usr/bin/python3
#-*- coding: utf-8 -*-

import paramiko
from subprocess import Popen,PIPE
import subprocess
from pexpect import pxssh
import node

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
user = "root"
passd = "root"
ip = "10.0.0.5"

n = node.Node(1)
ssh = n.ssh_init(ip,user)
#key = paramiko.DSSKey.from_private_key_file('/root/.ssh/id_rsa.pub')
try :
    sftp = n.ssh.open_sftp()

    try:
        sftp.put('tmpFile', '/etc/default/logstash')
    except Exception as e:
        print('Error while pushing file on remote host :' + str(e))

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

