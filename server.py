#!/usr/bin/python3
#-*- coding: utf-8 -*-

import paramiko
import random
class Server:
    """ Notre classe de création de Node à configurer"""

    def __init__(self):
        self.user =''
        self.ip = '127.0.0.1'
        self.passw =''
        self.nom = 'sond-cent'
        self.pathkey=''
        self.certlocalpath = './CertTest/'
        self.ipalerte = '10.200.0.20'
        self.ipadministration = '10.200.0.21'
        self.userHt = 'selks-operator'
        self.htpass = ''


    def add_ip(self,ip):
        self.ip = ip

    def add_eth(self,eth):
        self.eth = eth

    def change_name(self,name):
        self.nom = name

    def add_hostname(self,hostname):
        self.hostname = hostname

    def add_outputuser(self,outputuser):
        self.outputuser = outputuser

    def add_outputpass(self,outputpass):
        self.outputpass = outputpass

    def up_ipal(self,ipal):
        self.ipalerte = ipal

    def up_ipad(self,ipad):
        self.ipadministration = ipad

    def gen_pass(self):
        element = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-*/~$%"
        for i in range(24): self.htpass = self.htpass + element[random.randint(0, len(element) - 1)]