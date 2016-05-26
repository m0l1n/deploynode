#!/usr/bin/python3
#-*- coding: utf-8 -*-

import paramiko

class Node:
    """ Notre classe de création de Node à configurer"""

    def __init__(self,num):
        self.num = num #Notre numéro de node
        self.user =''
        self.ip = '10.0.0.5'
        self.passw =''
        self.nomsonde = 'MaSonde01'
        self.pathkey=''
        self.conf = False
        self.numEth = 1
        self.certlocalpath = './CertTest/'
        self.certremotepath = '/etc/logstash/cert/'
        self.nomServCentral = 'sond-cent'
        self.ipalerte = '10.200.0.20'
        self.ipadministration = '10.200.0.21'

    def add_user(self,user):
        self.user = user

    def add_path(self,path):
        self.path = path

    def add_passw(self,passw):
        self.passw = passw

    def change_conf(self,cf):
        self.conf = cf

    def add_ip(self,ip):
        self.ip = ip

    def add_eth(self,eth):
        self.eth = eth

    def ssh_init(self, ip, usr):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(ip, username=usr)

    def change_name(self,name):
        self.nomsonde = name

    def add_inputtype(self,type):
        self.type = type

    def add_hostname(self,hostname):
        self.hostname = hostname

    def add_outputuser(self,outputuser):
        self.outputuser = outputuser

    def add_outputpass(self,outputpass):
        self.outputpass = outputpass
