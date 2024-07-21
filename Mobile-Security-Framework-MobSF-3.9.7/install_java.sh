#!/bin/bash

# 安装OpenJDK 8
sudo yum install -y java-1.8.0-openjdk-devel

# 验证安装
java_version=$(java -version 2>&1)
if [[ $java_version == *"1.8.0"* ]]; then
    echo "Java 1.8.0 (OpenJDK 8) installed successfully."
else
    echo "Failed to install Java 1.8.0 (OpenJDK 8)."
    exit 1
fi

# 查找Java安装路径
JAVA_HOME=$(readlink -f /usr/bin/java | sed "s:bin/java::")

# 设置JAVA_HOME环境变量
echo "export JAVA_HOME=$JAVA_HOME" >> ~/.bashrc
echo "export PATH=\$JAVA_HOME/bin:\$PATH" >> ~/.bashrc

# 重新加载环境变量
source ~/.bashrc

# 验证环境变量设置
if [[ $JAVA_HOME == *"java-1.8.0"* ]]; then
    echo "JAVA_HOME environment variable set successfully."
else
    echo "Failed to set JAVA_HOME environment variable."
    exit 1
fi

echo "JDK 8 installation and configuration completed successfully."
