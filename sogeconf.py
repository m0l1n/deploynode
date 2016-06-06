#!/usr/bin/python3
#-*- coding: utf-8 -*-
"""
This script goal is to configure our IDS probe easily and help
setting our environment in an user-friendly way.

It test and tell you when something goes wrong

"""


import os
import paramiko
from subprocess import Popen, PIPE
import getpass
from pexpect import pxssh
# import pexpect
# from time import sleep
import sys
# import select
# import tty
# import termios
import re
import argparse
# import socket
# import time

#CLass
import node
import server


'''
Définition des différents modules :

Q_key_gen :
    -Création de clé RSA en locale

Q_creation_node :
    -Script d'affichage en console pour récupération
        des informations de créations des nodes

Q_first_con :
    -créations/initialisations des nodes avec infos récupérés dans Q_creation_node

Q_test_con_SSH :
    -Test de connexion SSH, si c'est la première connexion :
        - appel Q_push_key pour mettre la clé publique sur le serveur

Q_push_key :
    -Pousse la clé publique sur le node si elle n'y est pas.

Q_Prepping_System :
    -Installe les packages sur la machine

Q_Recup_Packages :
    -Récupère les packages à installer dans "package.txt"

Q_Install_Suricata :
    -Installe Suricata à partir du repo ajouter(fais aussi dans la fonction)

Q_Check_Suricata :
    -Vérification d'install de Suricata

Q_Update :
    - Update et Upgrade sur la machine (on peut demander à l'utilisateur si il veut le faire)

Q_Remote_Command :
    - Execute une commande donné en argument sur le node donné en argument

Q_Push_File :
    - Pousse un fichier local sur le remote host

Q_Disable_Ipv6 :
    - Désactive IPv6 sur le serveur distant (la sonde)

Q_Disable_Service_Local :
    -Désactive logstash et suricata sur le serveur local (selks)

Q_Install_Logstash:
    -Installe logstash

Q_Check_Logstash:
    -Check si logstash est installé et sa version

Q_Push_Certificate:
    -Push le certificat du serveur (pour l'histoire du tls )
'''

def Q_Key_Gen(path) :
    '''
    Création de clé RSA si pas présente sur la machine
    path : chemin de la création de la clé
    '''

    print("\n-----Generating RSA Key for SSH connexion------ \n")

    if os.path.isfile(path) : #Si le fichier de clé existe déja.
        print("SSH key is already created in /root/.ssh/id_rsa \n")
        return ("SSH Key already exist")
    else :
        keyGen = Popen(['ssh-keygen','-t','rsa','-N','','-f' ,path],stdout=PIPE)
        stdout = keyGen.communicate()[0]

        if keyGen.returncode != 0 :
            raise Exception("Problem on RSA key generator")

        return stdout.strip()



def Q_Creation_Node():
    '''
    Recuperation de node avec gestion d'erreur
    '''
    print(" \n------Initalizing node creation------ \n")
    nodeOk = False
    nombreNode = 0
    while not nodeOk:
        nombreNode = input("How many node to configure ?\n")
        try :
            int(nombreNode)
            print("\nNumber of node to configure: " + str(nombreNode))
            yes = input("Are you sure ?  y(es): ")
            if yes.lower() in ('y','yes','o','oui') :
                nodeOk = True
                print("\nConfiguring " + str(nombreNode)+" nodes...")
        except ValueError:
            print('Number of node need to be an integer\n')
    return int(nombreNode)


def Q_First_Con(i,node,full):
    '''
    full == true  : pousse la clé ssh sur le serveur
    Création de node
    i : notre numéro de node
    node : notre node à initialiser
    '''
    validIP = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" \
              "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    print("\n----- Setting up node " + str(i) + " ----- \n")
    #Ajout du superutilisateur
    conOk = False
    while not conOk :
        #nodeUser = '\n'
        nodeIp ='\n'
        while nodeIp == '\n':
            nodeIp = input("IP address of node" + str(i) + " :\n")
            if re.search(validIP,nodeIp) :
                print('Adresse Ip Ok')
            else :
                print('Adress ip not ok ...')
                nodeIp = '\n'
        node.add_ip(nodeIp)

        nodeUser = input("SuperUser name on node"+str(i)+" :\n")
        node.add_user(nodeUser)

        #Le chemin ou se trouve notre clé publique
        nodePath = '/root/.ssh/id_rsa.pub'
        node.add_path(nodePath)
        #Ajout du password superutilisateur
        nodePasswd = getpass.getpass(prompt='Enter password for SuperUser :\n')
        node.add_passw(nodePasswd)

        print("Initializing SSH Connexion test... Please wait ...")
        if full:
            if Q_Test_Con_SSH(node.ip,nodeUser,nodePasswd,True,nodePath):
                conOk = True
                #node.add_ssh(node.ip,nodeUser,nodePasswd)
        else :
            if Q_Test_Con_SSH(node.ip, nodeUser, nodePasswd, False, nodePath):
                conOk = True
                # node.add_ssh(node.ip,nodeUser,nodePasswd)
        try:
            node.ssh_init(node.ip, node.user)
        except Exception as e:
            print('error', e)
            print('\nProblem while creating ssh object in node')
    #Le nombre de carte ethernet pour la configuration
    nodeEth = input(" Number of ethernet interface on node ? ")
    node.add_eth(nodeEth)
    #Rajouter le formulaire pour le nom de la sonde etc


    return conOk

def Q_Test_Con_SSH(ip, user, passwd, pushKey, nodePath):
    '''
    Test de la connexion SSH
    ip : ip de l'host
    user : utilisateur( avec permission root :p )
    passwd : le mot de passe
    pushKey : au lieu de s'amuser à ouvrir et fermer des connexions SSH
    on push la clé dans ce module si demander (dans le cas de la première connexion
    (initialisation)
    '''
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #sftp = ssh.open_sftp()
    #print("\nNumber of node to configure: " + str(nombreNode))
    try :
        ssh.connect(ip, username = user, password =passwd)
        print('connexion test at '+ip +' ... Check')
        #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('echo haha >> /home/debuser/haha')
        #haha = Popen(['touch', '/home/debuser', 'haha'], stdout=PIPE)
        if pushKey == True:
            print('Pushing SSHKey on Server...')
            Q_Push_Key(ip, user, passwd, ssh, nodePath)

        ssh.close()
        return True

    except Exception as e:
        print('error', e)
        print("\nBad IP/Username/Password Combination")
        return False



def Q_Push_Key(serv,user,passwd,ssh, nodePath):
    '''
    :Pousse la clé SSH sur le serveur.
    A voir pour faire un return True ou False selon la réussite :)
    '''
    isPresent = False
    port = 22

    #la commande lolilol voir si ça marche
    #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('echo hoho >> /home/debuser/haha')

    try :
        print('Establishing SSH connection to :',serv,port,'...')
        sftp = ssh.open_sftp()
        #sftp.get('/root/.ssh/authorized_keys.add','/root/.ssh/id_rsa.pub')
        fileRemote = sftp.open('/root/.ssh/authorized_keys','ab+')
        #Ici on va pousser la clé sur le serveur, en lisant le fichier, et en gérant bien les \n...
        with sftp.open('/root/.ssh/authorized_keys') as fileRemoteKey :
            with open(nodePath) as fileLocalKey:
                for lineL in fileLocalKey:
                    if lineL in fileRemoteKey and lineL != '\n':
                        print('...Public Key is already pushed on remote host')
                    else :
                        try :
                            if lineL != '\n':
                                print('Pushing Key to remote host...')
                                fileRemote.write(lineL + '\n')
                        except Exception as e:
                            print('error', e)
                            print("\n...Problem when writing pubkey on remote host")
        sftp.close()

    except Exception as e:
        print('error', e)
        print("\nProblem on pushing key")
        return False

    return True


def Q_Prepping_System(node) :
    '''
    Installe tout les paquets et modules nécessaires sur les sondes
    afin de pouvoir fonctionner
    La liste des packages se trouve dans package.txt

    -libpcre3  libpcre3-dbg libpcre3-dev build-essential autoconf automake
    / libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev
    / libcap-ng-dev libcap-ng0 make libmagic-dev libnetfilter-queue-dev
    / libnetfilter-queue1 libnfnetlink-dev libnfnetlink0
    -Suricata
    :return:
    '''
    #Recupération de la liste de package a installé et mise au format pour être passé en argument
    #sur une commande apt-get install
    argument = Q_Recup_Packages('package.txt')
    cmd = 'apt-get install -y '+argument
    #Suppression de oracle-jdk installé par défaut sur le système
    # et oracle-installer dans la liste de package
    #Toutes nos configurations modifications de fichier de base sur le serveur se feront ici
    try :
        #ssh2.login(node.ip,node.user)
        print('Connexion at  ' + node.ip + ' for package installation...')
        #INSTALL PACKAGE
        #Q_Install_Oracle(node)
        print("\nInstalling package on node, please wait...")
        try :
            #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
            ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmd)
            print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
            print("...Package succesfully installed")
        except Exception as e:
            print('error',e)
            print('\n...Problem while installing package')

    except Exception as e:
        print('error', e)
        print("\n...Problem while connecting to ssh for package installation")


#MODULES ORACLE INSTALLER OBSOLETE POUR LE MOMENT AVEC LOGSTASH ES 2.X
def Q_Install_Oracle(node) :
    pushOracleCmd = ['echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu precise main" | \
        tee /etc/apt/sources.list.d/webupd8team-java.list',
                     'echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu precise main" | \
        tee -a /etc/apt/sources.list.d/webupd8team-java.list',
                     'apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --rcv-keys EEA14886',
                     'apt-get update',
                     'apt-get install -y oracle-java8-installer libc6-dev']

    try :
        print('Installing oracle-java?-installer... Please Wait ...')
        for cmd in pushOracleCmd :
            ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmd)
            print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
        print('...oracle-java?-installer succesfully installed')
    except Exception as e:
        print('error', e)
        print("\nProblem while Installing oracle-java?-installer")

    # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
#MODULES ORACLE INSTALLER OBSOLETE POUR LE MOMENT AVEC LOGSTASH ES 2.X

def Q_Update(node):
    '''
    Fais un apt-get update sur le node donné en paramètre
    '''
    # commande pour ajouter le backport à Sources.list pour l'install sur debian
    cmd = 'apt-get update'
    cmd2 = 'apt-get upgrade -y'
    try:
        print('Updating at:  ' + node.ip)
        # Updating
        try:
            print("\nUpdating on node, please wait...")
            ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmd)
            print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
            print("...System up to date")
        except Exception as e:
            print('error', e)
            print('\nProblem while updating system')
        #Upgrading
        try:
            print("\nUpgrading on node, please wait...")
            ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmd2)
            print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
            print("...System upgraded\n")
        except Exception as e:
            print('error', e)
            print('\nProblem while upgrading system')

    except Exception as e:
        print('error', e)
        print("\nProblem while connecting to ssh for updating system")


def Q_Recup_Packages(fileName):
    '''
    :param fileName: Récupère les packages a installés sur la machine
    :return: renvoit sous une string à donner en ligne de commande
    '''
    listePackage = []
    arg = ''
    fileP = open(fileName, 'r')
    for line in fileP:
        listePackage.append((line.replace('\n', '')).replace(' ', ''))
    fileP.close()
    for line in listePackage:
        arg += line + ' '
    return arg

def Q_Install_Suricata(node):
    '''
    Installe Suricata sur la machine à partir du dépôt backend de debian
    :param node: node à configurer
    :return:
    '''
    #commande pour ajouter le backport à Sources.list pour l'install sur debian
    cmdaddbackport = 'echo "deb http://http.debian.net/debian jessie-backports main" >' \
                     ' /etc/apt/sources.list.d/backports.list && apt-get update'
    #commande pour install suricata à partir du repo jessie nouvellement ajouté
    cmdinstallfromrepo = 'apt-get install -y -t jessie-backports suricata'

    try:
        #ssh2.login(node.ip, node.user)
        print('\nConnexion at  ' + node.ip + ' for suricata installation...')
        isSet,suriIsIns = Q_Check_Suricata(node)
        # INSTALL Source Backports
        if isSet :
            print("Suricata is already installed...")
            print (suriIsIns)
        else :
            try:
                print("\nPushing backport in sources.list, please wait...")
                ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmdaddbackport)
                print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
                #ssh2.sendline(cmdaddbackport)
                #ssh2.prompt()
                print("...Done")
            except Exception as e:
                print('error', e)
                print('\nProblem while adding backport to sources.list')

            # INSTALL suricata from repo
            try:
                print("\nInstalling Suricata from repo, please wait...")
                ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmdinstallfromrepo)
                print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
                #ssh2.sendline(cmdinstallfromrepo)
                #ssh2.prompt()
                print("...Done")
            except Exception as e:
                print('error', e)
                print('\nProblem while installing suricata')
            isSet, suriIsIns = Q_Check_Suricata(node)
            print(suriIsIns)
    except Exception as e:
        print('error', e)
        print("\nProblem while connecting to ssh for package installation")
    #Vérification que Suricata est installé : On peut faire une gestion d'erreur si
    #l'install a échoué avec le isSet à True si réussi et False si non




def Q_Check_Suricata(node):
    '''
    Vérifie que Suricata est bien installé sur le serveur
    :param node: La node sur lequel on vérifie l'install
    :return: retourne True si suricata est installé
    '''
    remoteCmd = 'suricata | head -n1'
    try:
        stdin,stdout,stderr = node.ssh.exec_command(remoteCmd)
        suriVersion = stdout.read()
        if 'Suricata' in str(suriVersion):
            return True, 'Suricata... version : ' + suriVersion.decode("utf-8") + 'at ' + node.ip
        else:
            return False, 'Suricata isn\'t installed on system at ' + node.ip
    except Exception as e:
        print('Error while heading suricata version...' + str(e))
        return False, 'Bug on Suricata check'




def Q_Remote_Command(node,cmd):
    '''
    Exécute la commande cmd sur le node spécifié
    '''
    # commande pour ajouter le backport à Sources.list pour l'install sur debian
    try:
        print('Executing'+cmd+' at:  ' + node.ip)
        # Executing command
        try:
            print("\nDoing stuff, please wait...")
            ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmd)
            print("\n...Done")
        except Exception as e:
            print('error', e)
            print('\nProblem while executing'+cmd)

    except Exception as e:
        print('error', e)
        print("\nProblem while connecting to ssh for executing"+cmd)


def Q_Push_File(node,pathFileLocal,pathFileRemote):
    '''
    Pousse un fichier local sur le Remote
    :param node: La node sur laquelle on va poser le fichier
    :param pathFileLocal: Le chemin du fichier en local
    :param pathFileRemote: Le chemin ou poser le fichier : ATTENTION le nom du fichier doit
    appartaitre; exemple : /home/myuser/monfichier.txt
    '''
    try :
        sftp = node.ssh.open_sftp()
        try :
            sftp.put(pathFileLocal,pathFileRemote)
        except Exception as e :
            print('Error while pushing file on remote host :' + str(e))
    except Exception as e:
        print('Failed to connect to remote host while pushing File : '+ str(e))


def Q_Disable_Ipv6(node) :
    '''
    Disable Ipv6 support on system (To avoid socket's type conflict)
    :param node: Node on which, we disable ipv6 support
    '''
    ipv6Conf = '/etc/sysctl.conf'
    remoteCmd = 'tail -n1 /etc/sysctl.conf'
    ipv6IsDis = '#Ipv6 now Disabled'

    # ATTENTION TODO : FAIRE LE DISABLE POUR CHAQUE CARTE ETHERNET A TERME
    DisIpv6 = ['net.ipv6.conf.all.disable_ipv6=1',
               'net.ipv6.conf.default.disable_ipv6=1',
               'net.ipv6.conf.lo.disable_ipv6=1',
               'net.ipv6.conf.eth0.disable_ipv6=1',
               'net.ipv6.conf.eth1.disable_ipv6=1']
    try:
        sftp = node.ssh.open_sftp()
        print('\nDisabling Ipv6 Support on remote system at : '+node.ip)
        DisIpv6.append(ipv6IsDis)
        try:
            with sftp.open(ipv6Conf) as f:
                if ipv6IsDis in f.read().decode("utf-8"):
                        print('...Ipv6 is already disabled on the system')
                else :
                    file = sftp.open(ipv6Conf, 'ab+')
                    for line in DisIpv6 :
                        file.write(line + '\n')
                    print('IPv6 Successfully Disabled on : ' + node.ip)
        except Exception as e:
            print('Error while disabling ipv6 on remote host :' + str(e))

    except Exception as e:
        print('Failed to connect to remote host while disabling ipv6 : '+ str(e))
    node.ssh.exec_command('sysctl -p')




#TODO LOGSTASH C PAAAARRRTTTIII
def Q_Install_Logstash(node):
    '''
    :return:
    '''
    depot = "http://packages.elastic.co/logstash/2.3/debian stable main"
    cmdGetKey = 'wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -'
    cmdPushRepo = 'echo "deb http://packages.elastic.co/logstash/2.3/debian stable main" \
                   | sudo tee -a /etc/apt/sources.list'
    cmdInst = 'apt-get install -y logstash'
    cmdUpdate = 'apt-get update'

    try:
        #ssh2.login(node.ip, node.user)
        print('\nConnexion at  ' + node.ip + ' for logstash installation...')
        isSet, logstashIsIns = Q_Check_Logstash(node)
        if isSet:
            print("Logstash is already installed...")
            print(logstashIsIns)
        else :
            # RECUPERATING GPG KEY
            try:
                print("\nRecuperating GPG Key, please wait...")
                ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmdGetKey)
                print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
                #ssh2.sendline(cmdGetKey)
                #ssh2.prompt()
                print("...Done")
            except Exception as e:
                print('error', e)
                print('\nProblem while Recuperating key')
            # INSTALL Source Backports
            try:
                print("\nPushing Repository in sources.list, please wait...")
                try:
                    sftp = node.ssh.open_sftp()
                    try:
                        with sftp.open('/etc/apt/sources.list') as f:
                            if depot in f.read().decode("utf-8"):
                                print('...Repo already pushed in sources.list')
                            else:
                                ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command(cmdPushRepo)
                                print("Repo pushed in sources.list")
                                print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
                    except Exception as e:
                        print('Error while checking sources.list on remote host :' + str(e))

                except Exception as e:
                    print('Failed to connect to remote host while disabling ipv6 : ' + str(e))

                #ssh2.sendline(cmdPushRepo)
                #ssh2.prompt()
                print("...Done")
            except Exception as e:
                print('error', e)
                print('\nProblem while adding backport to sources.list')

            # INSTALL logstash from repo
            try:
                #ssh2.sendline('ls -l')
                print("Installing Logstash from repo, please wait...")

                #ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command('rm /var/lib/dpkg/lock')
                #print("exit:" + str(ssh_stdout.channel.recv_exit_status()))

                #ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command('rm /var/cache/apt/archives/lock')
                ssh_stdin, ssh_stdout, ssh_stderr = node.ssh.exec_command('apt-get update &&'+cmdInst)
                print("exit:" + str(ssh_stdout.channel.recv_exit_status()))
                #print(stdout.read().decode('utf-8'))
                print(ssh_stderr.read().decode('utf-8'))
                #ssh2.prompt()
                print("...Done")
            except Exception as e:
                print('error', e)
                print('\nProblem while installing Logstash')
            isSet, logstashIsIns = Q_Check_Logstash(node)
            print(logstashIsIns)

    except Exception as e:
        print('error', e)
        print("\nProblem while connecting to ssh for logstash installation")
    # Vérification que Logstash est installé : On peut faire une gestion d'erreur si
    # l'install a échoué avec le isSet à True si réussi et False si non
    #isSet, logstashInstall = Q_Check_Logstash()

def Q_Check_Logstash(node):
    '''
    Vérifie que Logstash est bien installé sur le serveur
    :param node: La node sur lequel on vérifie l'install
    :return: retourne True si Logstash est installé
    '''
    remoteCmd = '/opt/logstash/bin/logstash -V'
    try:
        print('Checking if logstash is already installed (can take some times with few RAM)...')
        stdin,stdout,stderr = node.ssh.exec_command(remoteCmd)
        print("exit:" + str(stdout.channel.recv_exit_status()))
        logstashVersion = stdout.read()
        if 'logstash' in str(logstashVersion):
            return True, 'Logstash... version : ' + logstashVersion.decode("utf-8") + 'at ' + node.ip
        else:
            return False, 'Logstash isn\'t installed on system at ' + node.ip
    except Exception as e:
        print('Error while heading Logstash version...' + str(e))
        return False, 'Bug on Logstash check'


def Q_Configuration_Logstash(node,serv):
    '''
    Ici on va push le fichier logstash.conf modifié pour chaque sonde sur notre serveur

    :param node:
    :return:
    '''
    QueryType = '#type => sondeNameToReplace'
    QueryName = '#user => UserNameToReplace'
    QueryPassword = '#password => PasswordToReplace'
    QueryNodeName = '#type => sondeNameToReplace'
    try:
        stdin = Popen(['touch', 'logstash.conf'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        with open('logstash.conf', 'w') as fileToWrite:
            with open('oldlogstash.conf', 'r') as fileToRead:
                # Ici disctuter de la méthode la plus propre enbtre faire un re.match et re.remplace
                # ou parcourir le fichier line by line, et modifier en fonction :p
                # oldfile = file.read()
                fileData = fileToRead.read()
                fileData = fileData.replace(QueryPassword, serv.htpass)
                fileData = fileData.replace(QueryName, serv.userHt)
                fileData = fileData.replace(QueryType, serv.nom)
                #node.get_hostname récupère le nom de la sonde sur le serveur
                fileData = fileData.replace(QueryNodeName, node.get_hostname())
                # print(m)
                fileToWrite.write(fileData)
        Q_Push_File(node, 'logstash.conf', '/etc/logstash/conf.d/logstash.conf' )
    except Exception as e:
        print("error", e)


#Oui tout ça pour changer une petite ligne dans /etc/default/logstash...
#J'en aurais presque honte ...
def Q_Opt_Reboot_Log(node):
    sftp = n.ssh.open_sftp()
    try:
        stdin = Popen(['touch', 'tmpFile'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        if stdin.returncode != 0:
            print('error on touch tmpFile')
        tmp = open('tmpFile', 'w')
        with sftp.open('/etc/default/logstash', 'r') as f:
            for line in f:
                if '#KILL_ON_STOP_TIMEOUT=0' in line:
                    tmp.write('KILL_ON_STOP_TIMEOUT=1\n')
                else:
                    tmp.write(line)
        tmp.close()
    except Exception as e:
        print('error', e)
    try:
        sftp.put('tmpFile', '/etc/default/logstash')
    except Exception as e:
        print('Error while pushing file on remote host :' + str(e))
    stdin = Popen(['rm', 'tmpFile'], stdout=PIPE)
    stdout = stdin.communicate()[0]

##########################ICI on a quasiment que les modules pour le serveur principal
def Q_Create_Certif(serv):
    '''
    Step : -Remove default certificate
    - Gen rsa key
    - Gen CSR
    - remove passphrase so nginx can use it
    - Gen selfsigned cert
    - Duplicate to pem format.
    :return:
    '''
    localpath = serv.certlocalpath

    print('Generating certificate on localhost...\n')
    print('Create directory :' + localpath)


    if os.path.isdir(localpath):
        print("Directory " + localpath + "already exist.")
    else:
        try:
            stdin = Popen(['mkdir', localpath], stdout=PIPE)
            stdout = stdin.communicate()[0]
            if stdin.returncode != 0:
                raise Exception("Problem on creating directory")
        except Exception as e:
            print("...Failed to create " + localpath + " : Directory (probably) already exist")
    print('Removing default ssl certificate if present...\n')
    try:
        stdin = Popen(['rm', '/etc/nginx/ssl/server.key', '/etc/nginx/ssl/server.pem'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        # print (stdout)
        if stdin.returncode != 0:
            raise Exception("Problem on removing default ssl certificate")
    except Exception as e:
        print("Error on removing server : ", e)

    print("Creating all stuff\n")
    try:
        stdin = Popen(['openssl', 'req', '-nodes', '-new', '-x509', '-keyout', 'server.key',
                       '-out', 'server.pem', '-days', '365', '-config', 'openssl.cnf']
                      , cwd='CertTest/', stdout=PIPE)
        stdout = stdin.communicate()[0]
        if stdin.returncode != 0:
            raise Exception("Problem on Doing the creating/Etc certificate")
    except Exception as e:
        print("Error on creating stuff : ", e)

    # openssl
    # req - new - x509 - keyout
    # server.key - out
    # server.pem - days
    # 365 - config. / openssl.cnf
    print('Copy file in /etc/nginx/ssl to be ready to use...\n')
    try:
        stdin = Popen(['cp', 'server.key', 'server.pem', '/etc/nginx/ssl/'], cwd='CertTest/', stdout=PIPE)
        stdout = stdin.communicate()[0]
        if stdin.returncode != 0:
            raise Exception("Problem on copying file")
    except Exception as e:
        print("Error on copying file : ", e)


def Q_Recup_Cert(node,serv):
    '''
    Récupère le certificat SSL du serveur central et l'installe.
    à voir si on utilise le module ou non
    :param node:
    :return:
    '''
    remotepath = node.certremotepath
    localpath = serv.certlocalpath
    certPushed = False
    putFile = False

    print('Pushing Certificate on remote host...')
    while not certPushed:
        try:
            sftp = node.ssh.open_sftp()
        except Exception as e:
            print('Error:' + str(e))
        print('\nCreating '+remotepath+'... at '+node.ip +'...')

        try :
            sftp.mkdir(remotepath)
        except Exception as e:
            print("...Failed to create "+remotepath+" : Directory (probably) already exist")

        print('\n Pushing file server.pem on remote host')
        namefile= 'server.pem'

        try :
            if os.path.isfile(localpath+'server.pem'):
                try:
                    if sftp.stat(remotepath+'server.pem'):
                        print('File already exist, Overriding it')
                except Exception as e:
                    print('File does not exist,pushing server.pem...')
                try:
                    sftp.put(localpath+'server.pem', remotepath + namefile)
                    print('...File succesfully pushed on remote host')
                    certPushed = True
                except Exception as e:
                    print('error', e)
                    print('Failed to put file on remote host')
            else :
                print('\n...No file found in : ' + localpath+'...')
                    #Rep3 = input('...Do you need to stop this step (Push certificate) ? (Y/n)')
        except Exception as e:
            print('error ',e)
            # Oui je sais la condition de la boucle sert à rien car j'ai fais des modifs
            # Mais j'ai la flemme de tout dé indenter le code si j'enlève le while...
            # j'ai déja enlevé 5 lignes là u_u
        certPushed = True
                    #Rep3 = input('Do you need to stop this step ? (Y/n)')
                    #stdin, stdout, stderr = Popen('ls -l ' + localpath)
                    #print(stdout.read().decode('utf-8'))
            # if Rep3.lower() in ('y', 'yes'):
            #     break






def Q_Conf_Net_Int(serv) :
    '''
    Modification du fichier /etc/network/interfaces à partir du fichier oldConfInterfaces
    :param serv:
    :return:
    '''
    validIP = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" \
              "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    ipAdmin, ipAlert = False, False
    print('\nStarting Network interface configuration...(/etc/network/interfaces)')
    while not ipAdmin:
        admIP = input("Please enter server ip for administration (and remote access) : \n")
        if re.search(validIP, admIP):
            print('Updating ip address')
            serv.up_ipad(admIP)
            ipAdmin = True
        else:
            print('Adress ip not ok ...')

    while not ipAlert:
        alIP = input('Please enter server ip for alerting (can be the same than administration\'s one) : ')
        if re.search(validIP, alIP):
            print('updating ip address')
            serv.up_ipal(alIP)
            ipAlert = True
        else:
            print('Adress ip not ok ...')

    ######################## Conf /etc/network/interfaces
    print('Updating /etc/network/interfaces...')
    QueryAl = '#AddressPutAlerteRe'
    QueryAdm = '#AddressPutAdministration'
    QueryGateway = 'Ici quand on aura le gateway on le changera :p et le dnsserver aussi tiens'
    try:
        stdin = Popen(['touch', 'confInterfaces'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        with open('confInterfaces', 'w') as fileToWrite:
            with open('oldConfInterfaces', 'r') as fileToRead:
                # On modifie le fichier, il y a encore le
                # netmask a modifier aussi
                # le gateway
                # le dns server
                if serv.ipadministration == serv.ipalerte:
                    fileData = fileToRead.read()
                    fileData = fileData.replace(QueryAl, 'address ' + serv.ipalerte)
                    fileData = fileData.replace('auto eth1\niface eth1 inet static\n', '')
                else:
                    fileData = fileToRead.read()
                    fileData = fileData.replace(QueryAl, 'address ' + serv.ipalerte)
                    fileData = fileData.replace(QueryAdm, 'address ' + serv.ipadministration)
                # print(m)
                fileToWrite.write(fileData)
    except Exception as e:
        print("error while updating file", e)

    try:
        stdin = Popen(['cp', 'confInterfaces', '/etc/network/interfacesTestScript'], stdout=PIPE)
        stdout = stdin.communicate()[0]
    except Exception as e:
        print("error while modifying file (cp conf /etc/network/interfaces", e)

#Todo : Modifier le fichier de configuration d'interface et le fichier hôte
def Q_Conf_Host_File(serv):
    print('\nHost file configuration...(/etc/hosts)')
    return 1


def Q_Disable_Service(serv):
    '''
        Désactive les services locaux dont on a pas besoin ( logstash et suricata )
        :return:

        Peut se transformer en code pour supprimer tout les services qu'on ne veut pas
        à partir d'un fichier "service.txt" (comme pour package)... A voir :)
    '''

    suitecmdS = ['service suricata stop'
                ,'update-rc.d suricata disable']
    suitecmdL = ['service logstash stop',
                 'update-rc.d logstash disable']
    print('\nDisable useless service on local server : Logstash,Suricata...')
    if os.path.isdir('/etc/logstash'):
        for cmd in suitecmdL:
            unservlog = Popen(cmd, stdout=PIPE)
            stdout = unservlog.communicate()[0]
            if unservlog.returncode != 0:
                print(' Error while stopping Service')
    remoteCmd = 'suricata | head -n1'
    try:
        stdin = Popen(remoteCmd,stdout = PIPE)
        stdout = stdin.communicate()[0]
        if stdin.returncode != 0:
            print('Error on checking suricata')
        else :
            for cmd in suitecmdS:
                unservlog = Popen(cmd, stdout=PIPE)
                stdout = unservlog.communicate()[0]
                if unservlog.returncode != 0:
                    print(' Error while stopping Service')
    except Exception as e :
        print('Suricata not installed on server')


def Q_Disable_Ipv6_local(serv):
        '''
        Disable Ipv6 support on system (To avoid socket's type conflict)
        :param node: Node on which, we disable ipv6 support
        '''
        ipv6Conf = '/etc/sysctl.conf'
        Cmd = 'tail -n1 /etc/sysctl.conf'
        ipv6IsDis = '#Ipv6 now Disabled\n'

        # ATTENTION TODO : FAIRE LE DISABLE POUR CHAQUE CARTE ETHERNET A TERME
        DisIpv6 = ['net.ipv6.conf.all.disable_ipv6=1\n',
                   'net.ipv6.conf.default.disable_ipv6=1\n',
                   'net.ipv6.conf.lo.disable_ipv6=1\n',
                   'net.ipv6.conf.eth0.disable_ipv6=1\n',
                   'net.ipv6.conf.eth1.disable_ipv6=1\n']

        print('\nDisabling Ipv6 Support on local')
        DisIpv6.append(ipv6IsDis)
        try:
            with open(ipv6Conf) as f:
                tmp = f.read()
                if ipv6IsDis in tmp:
                    print('...Ipv6 is already disabled on the system')
                else:
                    with open(ipv6Conf, 'ab+') as file:
                        for line in DisIpv6:
                            #Un petit encore sinon le script râle... à check...
                            file.write(line.encode('utf-8'))
                        print('IPv6 Successfully Disabled on local')
        except Exception as e:
            print('Error while disabling ipv6 on local :' + str(e))

        stdin = Popen(['sysctl', '-p'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        if stdin.returncode != 0:
            raise Exception('Problem on executing sysctl -p')

#Todo : Push le fichier nginx en local
def Q_Push_Nginx(server):
    return 1


#done :Création du fichier d'auth http
def Q_Push_AuthHTTP(serv):
    print('Authentification file creation...')
    print('Installing apache2'
          '-utils on the server...')
    #Installation d'apache2-utils
    try:
        stdin = Popen(['apt-get', 'install', 'apache2-utils'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        # print (stdout)
        if stdin.returncode != 0:
            raise Exception("Problem on installing apache2-utils")
    except Exception as e:
        print("Error on removing server : ", e)

    # Création mot de passe et push htpasswd
    serv.gen_pass()
    try:
        print('Htpass creation for node authentification')
        print(serv.htpass)
        stdin = Popen(['htpasswd', '-b', '-c', '/etc/nginx/sonde.htpasswd',
                        serv.userHt, serv.htpass], stdout=PIPE)
        stdout = stdin.communicate()[0]
        # print (stdout)
        if stdin.returncode != 0:
            raise Exception("Problem on using htpasswd")
    except Exception as e:
        print("Error on htpasswd use : ", e)

    try:
        print('Modification on htpasswd conf')
        stdin = Popen(['chmod', 'o-r', '/etc/nginx/sonde.htpasswd'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        # print (stdout)
        if stdin.returncode != 0:
            raise Exception("Problem on using chmod")
    except Exception as e:
        print("Error on chmod use : ", e)



# Todo : Mise en place du proxy
def Q_Set_Proxy(serv):
    print('\nSet Proxy in elasticsearch.conf...')
    QueryAl = '#MyIPAlert'
    try:
        stdin = Popen(['touch', 'confProxy'], stdout=PIPE)
        stdout = stdin.communicate()[0]
        with open('confProxy', 'w') as fileToWrite:
            with open('oldConfProxy', 'r') as fileToRead:
                fileData = fileToRead.read()
                fileData = fileData.replace(QueryAl, serv.ipalerte)
                # print(m)
                fileToWrite.write(fileData)
    except Exception as e:
        print("error while setting elasticsearch.conf", e)

    stdin = Popen(['cp', 'confProxy','/etc/nginx/sites-available/elasticsearch.conf'], stdout=PIPE)
    stdout = stdin.communicate()[0]
    if stdin.returncode != 0:
        raise Exception('Problem on executing copy')
    #On active la configuration et on redémarre Nginx
    stdin = Popen(['ln', '-s', '/etc/nginx/sites-available/elasticsearch.conf',
                   '/etc/nginx/sites-enabled'], stdout=PIPE)
    stdout = stdin.communicate()[0]
    if stdin.returncode != 0:
        raise Exception('Problem on enabling Nginx')

    stdin = Popen(['service', 'nginx', 'reload'], stdout=PIPE)
    stdout = stdin.communicate()[0]
    if stdin.returncode != 0:
        raise Exception('Problem on reloading Nginx')


def Q_Conf_Central(serv):
    '''
    Toutes les configurations à faire sur le serveur central répartis dans les différents modules
    :param serv:
    :return:
    '''
    print ("\n------Main Server Configuration------ ")
    #Q_Conf_Host_File(serv) A priori pas besoin ?
    noName = False
    while not noName:
        nom = input('Main server name : ')
        rep = input('Confirm main server name :'+nom+' (Y/n)')
        if rep.lower() in ('y','yes','o','oui'):
            serv.change_name(nom)
            noName = True
    #todo (need dns gateway etc...) Q_Conf_Net_Int() Mais sinon ya quasiment tout de fait :3
    #todo -> done : mettre un check sur logstash et suricata pour :
    Q_Disable_Service(serv)
    Q_Disable_Ipv6_local(serv)
    Q_Create_Certif(serv)
    #todo Q_Push_Nginx(serv)  c'est le fichier /etc/nginx/nginx.conf ajouter la ligne client
    # client_max_body_size ... a voir
    Q_Push_AuthHTTP(serv)
    Q_Set_Proxy(serv)
    #ADD PART 4.2.7 from nils docs

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='This is a Script to help in the process of '
                                                 'deploying node in an IDS/IPS environment')
    parser.add_argument("-F", "-f", "--full", help="Launch the whole Installing process"
                        , action="store_true")
    parser.add_argument("-s", "--suricata", help="Launch Suricata Installer"
                        , action="store_true")
    parser.add_argument("-cs", "--checksuricata", help="Launch Suricata Checker"
                        , action="store_true")
    parser.add_argument("-l", "--logstash", help="Launch Logstash Installer"
                        , action="store_true")
    parser.add_argument("-cl", "--checklogstash", help="Launch Logstash Checker"
                        , action="store_true")
    parser.add_argument("-pk", "--pushkey", help="Push a key on a remote Host - "
                                    "Require a key in id_rsa,an User and A Password"
                        , action="store_true")


    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    if args.full:
        nodeS = []
        serv = server.Server()
        print(" \n------IDS/IPS Solution Probe configuration Script------ \n")

        # Création du certificat ssh
        Pass = Q_Key_Gen('/root/.ssh/id_rsa')
        # Si jamais on veut imprimer la création de la random image supprimer le commentaire suivant
        # print (Pass)

        # Récupération du nombre de nodes à configurer
        nbNode = Q_Creation_Node()

        # Création de nos nodes
        for i in range(nbNode):
            # n.add_user(i)
            # print (n.user)
            n = node.Node(i)
            Q_First_Con(i, n, True)
            #stdin, stdout, stderr = n.ssh.exec_command('echo "haha" >> haha.txt')
            nodeS.append(n)

        Q_Conf_Central(serv)
        # Pour les sondes il y aussi la configuration de /etc/network/interfaces et du fichier host
        #à faire

        # Préparer le système sur nos nodes
        for i in range(len(nodeS)):
            Q_Prepping_System(nodeS[i])
            Q_Update(nodeS[i])
            Q_Disable_Ipv6(nodeS[i])
            Q_Install_Suricata(nodeS[i])
            Q_Install_Logstash(nodeS[i])
            Q_Recup_Cert(nodeS[i],serv)
            Q_Configuration_Logstash(nodeS[i],serv)
            Q_Opt_Reboot_Log(nodeS[i])
            #Peut être le service elasticsearch à désactiver (je crois pas l'avoir fait)
            #mais c'est deux commandes rapide

            ## Ligne de test voir si nos attributs de nodes sont bien enregistré
            # for i in range(len(nodeS)):
            #     ssh = paramiko.SSHClient()
            #     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            #     ssh.connect('10.0.0.5', username=nodeS[i].user, password=nodeS[i].passw)
            #     #print("connexion test... Check")
            #     ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('echo hihiiii >> /home/debuser/haha')
            #     #nodeS.append(node)


            # keygen = C_key_gen()
            # keygen.communicate()[0]
    if args.suricata:
        n = node.Node(1)
        Q_First_Con(1,n,False)
        Q_Update(n)
        Q_Install_Suricata(n)
        print('Launch Suricata Install')

    if args.checksuricata:
        n = node.Node(1)
        Q_First_Con(1, n, False)
        Q_Update(n)
        Q_Check_Suricata(n)
        print('Launch Suricata check install')

    if args.logstash:
        n = node.Node(1)
        Q_First_Con(1,n,False)
        Q_Update(n)
        Q_Install_Logstash(n)
        print('Launch logstash install')

    if args.checklogstash:
        n = node.Node(1)
        Q_First_Con(1,n,False)
        Q_Update(n)
        Q_Check_Logstash(n)
        print('Launch logstash check install')

    if args.pushkey:
        n= node.Node(1)
        Q_First_Con(1,n,True)
        print('Launch pushing key on remote host (First_Con do the job)')



