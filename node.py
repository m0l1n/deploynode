#!/usr/bin/python3
#-*- coding: utf-8 -*-

class Node:
    """ Notre classe de création de Node à configurer"""

    def __init__(self,num):
        self.num = num #Notre numéro de node
        self.user =''
        self.ip = '10.0.0.5'
        self.passw =''
        self.pathkey=''
        self.conf = False

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