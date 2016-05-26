#!/usr/bin/python3
#-*- coding: utf-8 -*-

import paramiko
from subprocess import Popen,PIPE,STDOUT
import subprocess
import os
import pexpect
import node.py
#debuser à modifier par le user

def Remote(cmd,IP):
    passwd = ('root').encode('utf-8')
    comd = 'ssh root@'+IP+' '+cmd

    fname = '/home/debuser/tmp'
    fout = open(fname,'w')

    # proc = Popen(cmd.split(), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    # proc.stdin.write(passwd)
    # proc.communicate()[0]
    #proc.stdin.close()

    childssh = pexpect.spawn(comd, timeout=30)
    #childssh.logfile = open("/tmp/mylog", "w")
    childssh.expect(['password: '])
    childssh.sendline(passwd)
    childssh.logfile = fout

    childssh.expect(pexpect.EOF)
    childssh.close()
    fout.close()
    #launch = str(proc)
    #launch = '\n'.join(launch)
    fin = open(fname, 'r')
    stdout = fin.read()
    fin.close()

    return stdout

source = '127.0.0.1'
destination = '10.0.0.5'
getkey = 'cat /root/.ssh/id_rsa.pub'
getauth = 'cat /root/.ssh/authorized_keys'
getTest = 'cat /home/debuser/Test'
#sourcekey = Remote(getkey, source)
#sourcekey = sourcekey.replace('\n','').strip()
#authkeys = Remote(getauth, destination).replace('\n','').strip()
myTest = Remote(getTest, destination)
print (myTest)

if True: #sourcekey not in authkeys :
    #keycmd = '''echo "%s" >>/root/.ssh/authorized_keys;
    #chmod 600 /root/.ssh/authorized_keys '''%(sourcekey)
    #Remote(keycmd,destination)
    print('clé a installé?')
    #Remote('touch /home/debuser/haha',destination)

else :
    print('la clé est déja dedans !\n')



