#!/bin/bash


sudo yum install -y gcc openssl-devel bzip2-devel libffi-devel zlib-devel

cd /usr/src
sudo wget https://mirrors.huaweicloud.com/python/3.11.0/Python-3.11.0.tgz
sudo tar xzf Python-3.11.0.tgz
cd Python-3.11.0
sudo ./configure --enable-optimizations
sudo make altinstall
sudo ln -s /usr/local/bin/python3.11 /usr/bin/python3
python3 --version
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

