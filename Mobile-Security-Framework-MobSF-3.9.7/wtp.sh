#!/bin/bash

# 更新系统软件包
sudo yum update -y

# 安装依赖包
sudo yum install -y epel-release
sudo yum install -y xorg-x11-fonts-75dpi xorg-x11-fonts-Type1

# 下载并安装wkhtmltopdf
cd /usr/local/bin
sudo wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.centos8.x86_64.rpm
sudo rpm -Uvh wkhtmltox-0.12.6-1.centos8.x86_64.rpm

# 将wkhtmltopdf路径加入环境变量
echo 'export PATH=/usr/local/bin:$PATH' >> ~/.bashrc

# 重新加载环境变量
source ~/.bashrc

# 验证安装
wkhtmltopdf_version=$(wkhtmltopdf --version 2>&1)
if [[ $wkhtmltopdf_version == *"wkhtmltopdf 0.12.6"* ]]; then
    echo "wkhtmltopdf installed successfully."
else
    echo "Failed to install wkhtmltopdf."
    exit 1
fi

echo "wkhtmltopdf installation and configuration completed successfully."
