#!/bin/bash

# Installing python 3.8.2
sudo yum -y update
sudo yum -y install yum-utils
sudo yum -y groupinstall develoment
sudo yum -y install https://repo.ius.io/ius-release-el7.rpm
sudo yum -y install wget
wget https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tgz
tar xf Python-3.8.2.tgz
cd Python-3.8.2
./configure
make
make test
sudo make install
sudo yum -y install zlib-devel
sudo yum -y install python3-pip
sudo yum -y install python3-devel

# Installing Requests
cd
pip3 install requests

# Installing Masscan
sudo yum -y install libpcap clang git gcc make
wget http://mirror.centos.org/centos/7/os/x86_64/Packages/libpcap-devel-1.5.3-12.el7.x86_64.rpm
sudo rpm -ivh libpcap-devel-1.5.3-12.el7.x86_64.rpm
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
make regress
mv masscan /opt/