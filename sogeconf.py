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
# import sys
# import select
# import tty
# import termios
# import re
# import socket
# import time

#CLass
import node


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
            if yes.lower() in ('y','yes') :
                nodeOk = True
                print("\nConfiguring " + str(nombreNode)+" nodes...")
        except ValueError:
            print('Number of node need to be an integer\n')
    return int(nombreNode)


def Q_First_Con(i,node):
    '''
    Création de node
    i : notre numéro de node
    node : notre node à initialiser
    '''
    print("\n----- Setting up node " + str(i) + " ----- \n")
    #Ajout du superutilisateur
    conOk = False
    while not conOk :
        nodeUser = '\n'

        # while True:
        #     try:
        #         line = sys.stdin.readline()
        #         print('\n')
        #     except EOFError:
        #         print('EOF')
        #         break

        #Ajout du superutilisateur
        #La boucle est là pour faire du garbage collector sur les retour chario de l'user

        while nodeUser == '\n':
            nodeUser = input("SuperUser name on node"+str(i)+" :\n")
        node.add_user(nodeUser)
        #Le chemin ou se trouve notre clé publique
        nodePath = '/root/.ssh/id_rsa.pub'
        node.add_path(nodePath)
        #Ajout du password superutilisateur
        nodePasswd = getpass.getpass(prompt='Enter password for SuperUser :\n')
        node.add_passw(nodePasswd)

        print("Initializing SSH Connexion test... Please wait ...")
        if Q_Test_Con_SSH(node.ip,nodeUser,nodePasswd,True,nodePath):
            conOk = True

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
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('echo haha >> /home/debuser/haha')
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
    ssh2 = pxssh.pxssh()

    #Recupération de la liste de package a installé et mise au format pour être passé en argument
    #sur une commande apt-get install
    argument = Q_Recup_Packages('package.txt')
    cmd = 'apt-get install -y '+argument

    #Suppression de oracle-jdk installé par défaut sur le système
    # et oracle-installer dans la liste de package
    #Toutes nos configurations modifications de fichier de base sur le serveur se feront ici
    try :
        #ssh.connect(ip, username = node.user)
        ssh2.login(node.ip,node.user)
        print('Connexion at  ' + node.ip + ' for package installation...')
        #INSTALL PACKAGE
        #Q_Install_Oracle(ssh2)
        print("\nInstalling package on node, please wait...")
        try :
            #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
            ssh2.sendline(cmd)
            ssh2.prompt()
            print("...Package succesfully installed")
        except Exception as e:
            print('error',e)
            print('\n...Problem while installing package')

    except Exception as e:
        print('error', e)
        print("\n...Problem while connecting to ssh for package installation")


#MODULES ORACLE INSTALLER OBSOLETE POUR LE MOMENT AVEC LOGSTASH ES 2.X
def Q_Install_Oracle(ssh) :
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
            ssh.sendline(cmd)
            # prompt waiting for every command to end
            ssh.prompt()
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
    ssh2 = pxssh.pxssh()
    # commande pour ajouter le backport à Sources.list pour l'install sur debian
    cmd = 'apt-get update'
    cmd2 = 'apt-get upgrade -y'
    try:
        ssh2.login(node.ip, node.user)
        print('Updating at:  ' + node.ip)
        # Updating
        try:
            ssh2.sendline(cmd)
            print("\nUpdating on node, please wait...")
            ssh2.prompt()
            print("...System up to date")
        except Exception as e:
            print('error', e)
            print('\nProblem while updating system')
        #Upgrading
        try:
            ssh2.sendline(cmd2)
            print("\nUpgrading on node, please wait...")
            ssh2.prompt()
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
    ssh2 = pxssh.pxssh()
    try:
        # ssh.connect(ip, username = node.user)
        ssh2.login(node.ip, node.user)
        print('\nConnexion at  ' + node.ip + ' for suricata installation...')
        isSet,suriIsIns = Q_Check_Suricata(node)
        # INSTALL Source Backports
        if isSet :
            print("Suricata is already installed...")
            print (suriIsIns)
        else :
            try:
                # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
                ssh2.sendline(cmdaddbackport)
                print("\nPushing backport in sources.list, please wait...")
                ssh2.prompt()
                print("...Done")
            except Exception as e:
                print('error', e)
                print('\nProblem while adding backport to sources.list')

            # INSTALL suricata from repo
            try:
                # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
                ssh2.sendline(cmdinstallfromrepo)
                print("\nInstalling Suricata from repo, please wait...")
                ssh2.prompt()
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
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(node.ip, username=node.user)
            stdin,stdout,stderr = ssh.exec_command(remoteCmd)
            suriVersion = stdout.read()
            if 'Suricata' in str(suriVersion):
                return True, 'Suricata... version : ' + suriVersion.decode("utf-8") + 'at ' + node.ip
            else:
                return False, 'Suricata isn\'t installed on system at ' + node.ip
        except Exception as e:
            print('Error while heading suricata version...' + str(e))
            return False, 'Bug on Suricata check'
    except Exception as e :
        print("Failed to connect while checking Suricata "+ str(e))



def Q_Remote_Command(node,cmd):
    '''
    Exécute la commande cmd sur le node spécifié
    '''
    ssh2 = pxssh.pxssh()
    # commande pour ajouter le backport à Sources.list pour l'install sur debian
    try:
        ssh2.login(node.ip, node.user)
        print('Executing'+cmd+' at:  ' + node.ip)
        # Executing command
        try:
            ssh2.sendline(cmd)
            print("\nDoing stuff, please wait...")
            ssh2.prompt()
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
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try :
        ssh.connect(node.ip,username=node.user)
        sftp = ssh.open_sftp()
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

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(node.ip,username=node.user)
        sftp = ssh.open_sftp()
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
    ssh.exec_command('sysctl -p')



def Q_Disable_Service_Local() :
    '''
    Désactive les services locaux dont on a pas besoin ( logstash et suricata )
    :return:

    Peut se transformer en code pour supprimer tout les services qu'on ne veut pas
    à partir d'un fichier "service.txt" (comme pour package)... A voir :)
    '''
    suitecmd =['service logstash stop',
               'service suricata stop',
               'update-rc.d logstash disable',
               'update-rc.d suricata disable']
    for cmd in suitecmd:
        unservlog = Popen(cmd,stdout = PIPE)
        stdout = unservlog.communicate()[0]
        if unservlog.returncode != 0 :
            print(' Error while stopping Service')



#TODO LOGSTASH C PAAAARRRTTTIII
def Q_Install_Logstash():
    '''

    :return:
    '''
    cmdGetKey = 'wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -'
    cmdPushRepo = 'echo "deb http://packages.elastic.co/logstash/2.3/debian stable main" \
                   | sudo tee -a /etc/apt/sources.list'
    cmdInst = ' apt-get update && apt-get install -y elasticsearch'

    ssh2 = pxssh.pxssh()
    try:
        # ssh.connect(ip, username = node.user)
        ssh2.login(node.ip, node.user)
        print('\nConnexion at  ' + node.ip + ' for suricata installation...')
        #suriIsIns = Q_Check_Suricata(node, ssh2)
        # RECUPERATING GPG KEY

        # INSTALL Source Backports
        try:
            # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
            #ssh2.sendline(cmdaddbackport)
            print("\nPushing backport in sources.list, please wait...")
            ssh2.prompt()
            print("...Done")
        except Exception as e:
            print('error', e)
            print('\nProblem while adding backport to sources.list')

        # INSTALL suricata from repo
        try:
            # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
            #ssh2.sendline(cmdinstallfromrepo)
            print("\nInstalling Suricata from repo, please wait...")
            ssh2.prompt()
            print("...Done")
        except Exception as e:
            print('error', e)
            print('\nProblem while installing suricata')

    except Exception as e:
        print('error', e)
        print("\nProblem while connecting to ssh for package installation")
    # Vérification que Suricata est installé : On peut faire une gestion d'erreur si
    # l'install a échoué avec le isSet à True si réussi et False si non
    #isSet, suriInstall = Q_Check_Suricata()
    #print(suriInstall)

if __name__ == '__main__':

    nodeS = []
    print (" \n------IDS Probe configuration Script------ \n")

    #Création du certificat ssh
    Pass = Q_Key_Gen('/root/.ssh/id_rsa')
    #Si jamais on veut imprimer la création de la random image supprimer le commentaire suivant
    #print (Pass)

    #Récupération du nombre de nodes à configurer
    nbNode = Q_Creation_Node()

    #Création de nos nodes
    for i in range(nbNode) :
        #n.add_user(i)
        #print (n.user)
        n = node.Node(i)
        Q_First_Con(i,n)
        nodeS.append(n)

    #Préparer le système sur nos nodes (les paquets de base)
    for i in range(len(nodeS)):
        Q_Prepping_System(nodeS[i])
        Q_Update(nodeS[i])
        Q_Disable_Ipv6(nodeS[i])
        Q_Install_Suricata(nodeS[i])

    #Q_Preppin_System()

    ## Ligne de test voir si nos attributs de nodes sont bien enregistré
    # for i in range(len(nodeS)):
    #     ssh = paramiko.SSHClient()
    #     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #     ssh.connect('10.0.0.5', username=nodeS[i].user, password=nodeS[i].passw)
    #     #print("connexion test... Check")
    #     ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('echo hihiiii >> /home/debuser/haha')
    #     #nodeS.append(node)


    #keygen = C_key_gen()
    #keygen.communicate()[0]

