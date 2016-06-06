#!/bin/sh
#Install prerequite for python script
su -
apt-get update && apt-get upgrade
apt-get install python3
apt-get install python3-pip
pip install --upgrade pip
pip3 install paramiko  

