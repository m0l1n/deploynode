#!/bin/sh
#Install prerequite for python script
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python3 build-essential libffi-dev libssl-dev openssl
sudo apt-get install python3-pip
pip3 install --upgrade pip
pip3 install pexpect cryptopgraphy pycrypto crypto paramiko  

