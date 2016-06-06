#!/usr/bin/python3
#-*- coding: utf-8 -*-


import paramiko
import node
import re
import argparse
from subprocess import Popen,PIPE,call
import os
import server
import socket


# parser = argparse.ArgumentParser(description='This is a test')
# parser.add_argument("-F","-f" , "--full", help="Launch the whole Installing process"
#                     , action="store_true")
# parser.add_argument("-s","--suricata",help="Launch Suricata Installer"
#                     ,action="store_true")
# parser.add_argument("-cs","--checksuricata",help="Launch Suricata Checker"
#                      ,action="store_true")
# parser.add_argument("-l", "--logstash", help="Launch Logstash Installer"
#                     ,action = "store_true")
# parser.add_argument("-cl", "--checklogstash", help="Launch Logstash Checker"
#                      , action="store_true")
# parser.add_argument("-pk","--pushkey", help="Push a key on a remote Host - "
#                         "Require a key in id_rsa,an User and A Password"
#                     ,action="store_true")
# args = parser.parse_args()


#Le test de configuration de fichier logstash
#Let keep it there cuz I m too lazy to remove ! :p

n = node.Node(1)
n.ssh_init('10.0.0.5','root')
serv = server.Server()

# validIP = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" \
#           "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
# ipAdmin, ipAlert = False, False
# print('\nStarting Network interface configuration...(/etc/network/interfaces)')
# while not ipAdmin:
#     admIP = input("Please enter server ip for administration (and remote access) : \n")
#     if re.search(validIP,admIP):
#         print('Updating ip address')
#         serv.up_ipad(admIP)
#         ipAdmin = True
#     else:
#         print('Adress ip not ok ...')
#
# while not ipAlert:
#     alIP = input('Please enter server ip for alerting (can be the same than administration\'s one) : ')
#     if re.search(validIP, alIP):
#         print('updating ip address')
#         serv.up_ipal(alIP)
#         ipAlert = True
#     else:
#         print('Adress ip not ok ...')
#
# ######################## Conf /etc/network/interfaces
# print('Updating /etc/network/interfaces...')
# QueryAl = '#AddressPutAlerteRe'
# QueryAdm = '#AddressPutAdministration'
# QueryGateway = 'Ici quand on aura le gateway on le changera :p et le dnsserver aussi tiens'
# try:
#     stdin = Popen(['touch', 'confInterfaces'], stdout=PIPE)
#     stdout = stdin.communicate()[0]
#     with open('confInterfaces', 'w') as fileToWrite:
#         with open('oldConfInterfaces', 'r') as fileToRead:
#             # On modifie le fichier, il y a encore le
#             # netmask a modifier aussi
#             #le gateway
#             #le dns server
#             if serv.ipadministration == serv.ipalerte :
#                 fileData = fileToRead.read()
#                 fileData = fileData.replace(QueryAl, 'address ' + serv.ipalerte)
#                 fileData = fileData.replace('auto eth1\niface eth1 inet static\n','')
#             else :
#                 fileData = fileToRead.read()
#                 fileData = fileData.replace(QueryAl, 'address ' + serv.ipalerte)
#                 fileData = fileData.replace(QueryAdm, 'address ' + serv.ipadministration)
#             # print(m)
#             fileToWrite.write(fileData)
# except Exception as e:
#     print("error while updating file", e)
#
# try:
#     stdin = Popen(['cp', 'confInterfaces', '/etc/network/interfacesTestScript'], stdout=PIPE)
#     stdout = stdin.communicate()[0]
# except Exception as e:
#     print("error while modifying file (cp conf /etc/network/interfaces", e)

# print('\nSet Proxy in elasticsearch.conf...')
# QueryAl = '#MyIPAlert'
# try:
#     stdin = Popen(['touch', 'confProxy'], stdout=PIPE)
#     stdout = stdin.communicate()[0]
#     with open('confProxy', 'w') as fileToWrite:
#         with open('oldConfProxy', 'r') as fileToRead:
#             fileData = fileToRead.read()
#             fileData = fileData.replace(QueryAl, serv.ipalerte)
#             # print(m)
#             fileToWrite.write(fileData)
# except Exception as e:
#     print("error while updating file", e)
#
#

sftp = n.ssh.open_sftp()
try:
    stdin = Popen(['touch','tmpFile'],stdout = PIPE)
    stdout = stdin.communicate()[0]
    if stdin.returncode != 0 :
        print('error on touch tmpFile')
    tmp = open('tmpFile','w')
    with sftp.open('/etc/default/logstash', 'r') as f:
        for line in f:
            if '#KILL_ON_STOP_TIMEOUT=0' in line :
                tmp.write('KILL_ON_STOP_TIMEOUT=1\n')
            else :
                tmp.write(line)
    # tmp.close()
    # stdin = Popen(['rm', 'tmp'], stdout=PIPE)
    # stdout = stdin.communicate()[0]
    tmp.close()
except Exception as e:
    print('error',e)

try:
    sftp.put('tmpFile', '/etc/default/logstash')
except Exception as e:
    print('Error while pushing file on remote host :' + str(e))

stdin = Popen(['rm', 'tmpFile'], stdout=PIPE)
stdout = stdin.communicate()[0]

# remoteCmd = 'suricata | head -n1'
# try:
#     stdin = Popen(['echo','$HOSTNAME'],stdout = PIPE)
#     stdout = stdin.communicate()[0]
#     print(stdout.decode())
#     if stdin.returncode != 0 :
#         print ('oups')
# except Exception as e :
#     print('that error :',e)
#
# print(socket.gethostbyaddr(socket.gethostname())[0])
#
#
# n.ssh_init('10.0.0.5', 'root')
# stdin,stdout,stderr = n.ssh.exec_command('echo $HOSTNAME')
# print(stdout.read().decode())
# if True:
#     ipv6Conf = '/etc/sysctl.conf'
#     Cmd = 'tail -n1 /etc/sysctl.conf'
#     ipv6IsDis = '#Ipv6 now Disabled\n'
#
#     # ATTENTION TODO : FAIRE LE DISABLE POUR CHAQUE CARTE ETHERNET A TERME
#     DisIpv6 = ['net.ipv6.conf.all.disable_ipv6=1\n',
#                'net.ipv6.conf.default.disable_ipv6=1\n',
#                'net.ipv6.conf.lo.disable_ipv6=1\n',
#                'net.ipv6.conf.eth0.disable_ipv6=1\n',
#                'net.ipv6.conf.eth1.disable_ipv6=1\n']
#
#     print('\nDisabling Ipv6 Support on local')
#     DisIpv6.append(ipv6IsDis)
#     try:
#         with open(ipv6Conf) as f:
#             tmp = f.read()
#             if ipv6IsDis in tmp:
#                 print('...Ipv6 is already disabled on the system')
#             else:
#                 with open(ipv6Conf, 'ab+') as file :
#                     for line in DisIpv6:
#                         file.write(line.encode('utf-8'))
#                     print('IPv6 Successfully Disabled on local')
#     except Exception as e:
#         print('Error while disabling ipv6 on local :' + str(e))
#
#     stdin = Popen(['sysctl', '-p'], stdout=PIPE)
#     stdout = stdin.communicate()[0]
#     if stdin.returncode != 0:
#         raise Exception('Problem on executing sysctl -p')
# localpath = n.certlocalpath
# if True :
#     print('Generating certificate on localhost..')
#     print('Create directory :'+localpath)
#     cmd = []
#     cmd.append(['openssl','req','-nodes','-new','-x509','-keyout','server.key',
#                         '-out','server.pem','-days','365','-config','openssl.cnf'])
#
#     #On utiliseras ça après plus propre:
#
#     if os.path.isdir(localpath):
#         print("Directory "+localpath+"already exist.")
#     else :
#         try:
#             stdin = Popen(['mkdir', localpath], stdout=PIPE)
#             stdout = stdin.communicate()[0]
#             if stdin.returncode != 0:
#                 raise Exception("Problem on creating directory")
#         except Exception as e:
#             print("...Failed to create " + localpath + " : Directory (probably) already exist")
#     print('Removing default ssl certificate if present...\n')
#     try :
#         stdin = Popen(['rm','/etc/nginx/ssl/server.key','/etc/nginx/ssl/server.pem'],stdout = PIPE)
#         stdout = stdin.communicate()[0]
#         #print (stdout)
#         if stdin.returncode != 0:
#             raise Exception("Problem on removing default ssl certificate")
#     except Exception as e:
#         print("Error on removing server : ",e)
#
#     print("Creating all stuff\n")
#     try:
#         stdin = Popen(['openssl','req','-nodes','-new','-x509','-keyout','server.key',
#                         '-out','server.pem','-days','365','-config','openssl.cnf']
#                        ,cwd='CertTest/' , stdout=PIPE)
#         stdout = stdin.communicate()[0]
#         if stdin.returncode != 0:
#             raise Exception("Problem on Doing the creating/Etc certificate")
#     except Exception as e:
#         print("Error on creating stuff : ", e)
#
#     # openssl
#     # req - new - x509 - keyout
#     # server.key - out
#     # server.pem - days
#     # 365 - config. / openssl.cnf
#     print('Copy file in /etc/nginx/ssl to be ready to use...\n')
#     try:
#         stdin = Popen(['cp','server.key', 'server.pem', '/etc/nginx/ssl/'],cwd='CertTest/', stdout=PIPE)
#         stdout = stdin.communicate()[0]
#         if stdin.returncode != 0:
#             raise Exception("Problem on copying file")
#     except Exception as e:
#         print("Error on copying file : ", e)

# QueryType = '#type => sondeNameToReplace'
# QueryName = '#user => UserNameToReplace'
# QueryPassword = '#password => PasswordToReplace'
# try:
#     stdin = Popen(['touch','logstash.conf'],stdout = PIPE)
#     stdout = stdin.communicate()[0]
#     with open('logstash.conf','w') as fileToWrite:
#         with open('oldlogstash.conf','r') as fileToRead :
#         #Ici disctuter de la méthode la plus propre enbtre faire un re.match et re.remplace
#         # ou parcourir le fichier line by line, et modifier en fonction :p
#         #oldfile = file.read()
#             fileData = fileToRead.read()
#             if QueryPassword in fileData :
#                 print('match')
#             fileData = fileData.replace(QueryPassword, '#password => NewPasswordToReplace')
#             fileData = fileData.replace(QueryName,'#user => NewUSerNameToReplace')
#             fileData = fileData.replace(QueryType,'#type => NewTypeToReplace')
#             #print(m)
#             fileToWrite.write(fileData)
#
#
#
#         # line = file.readline()
#         # while line:
#         #     if QueryPassword in line:
#         #         print ("match :"+line)
#         #
#         #     line = file.readline()
#
#         #file.close()
#         #re.remplace("NomSondeReplaceInput","type => \"sonde0x-XXXX\"")
#     try:
#         n.ssh_init('10.0.0.5', 'root')
#         try:
#             sftp = n.ssh.open_sftp()
#             try:
#                 sftp.put('logstash.conf', '/etc/logstash/conf.d/logstash.conf')
#             except Exception as e:
#                 print('Error while pushing file on remote host :' + str(e))
#         except Exception as e:
#             print('Failed to connect to remote host while pushing File : ' + str(e))
#     except Exception as e:
#         print('error', e)
#         print('\nProblem while connecting')
# except Exception as e:
#         print("error",e)

# if args.full:
#     print( 'Launch all')
# if args.suricata :
#     print ('Launch Suricata Install')
# if args.checksuricata :
#     print ('Launch Suricata check install')
# if args.logstash:
#     print ('Launch logstash install')
# if args.checklogstash:
#     print('Launch logstash check install')
# if args.pushkey:
#     print('Launch pushing key on remote host (First_Con do the job)')

# class stuff():
#     def __init__(self):
#         print("nothing")
#
#     def real_init(self, ip, usr, mdp):
#         self.ssh = paramiko.SSHClient()
#         self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         self.ssh.connect(ip,username = usr, password = mdp)
#
# s = stuff()
# # Executing command
# n = node.Node(1)
#
# try:
#     n.ssh_init('10.0.0.5','root')
# except Exception as e:
#     print('error', e)
#     print('\nProblem while connecting')
#
# try:
#     stdin, stdout, stderr = n.ssh.exec_command('echo "haha" >> haha.txt')
# except Exception as e:
#     print('error',e)


# namefile = input('\nEnter file name on remote host: (empty for server.pem)')
# print (namefile)
# if re.match(' this | that', namefile):
#     namefile = 'server.pem'
# #'^\s*$',
# print (namefile)


