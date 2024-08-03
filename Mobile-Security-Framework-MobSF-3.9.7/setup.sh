#!/bin/bash

# 检查 Python3
unamestr=$(uname)
if ! command -v python3 &> /dev/null; then
    echo '[错误] 未安装 python3。' >&2
    exit 1
fi

# 检查 Python3 版本
python_version=$(python3 --version 2>&1 | awk '{print $2}')
py_major=$(echo "$python_version" | cut -d'.' -f1)
py_minor=$(echo "$python_version" | cut -d'.' -f2)
if [ "$py_major" -eq "3" ] && [ "$py_minor" -ge "10" ] && [ "$py_minor" -le "11" ]; then
    echo "[安装] 找到 Python ${python_version}"
else
    echo "[错误] MobSF 依赖需要 Python 3.10 - 3.11。您有 Python 版本 ${python_version} 或 python3 指向的 Python 版本是 ${python_version}。"
    exit 1
fi

# 检查并升级 Pip
if python3 -m pip -V &> /dev/null; then
    echo '[安装] 找到 pip'
    upgrade_command="python3 -m pip install --no-cache-dir --upgrade pip -i http://mirrors.aliyun.com/pypi/simple/"
    if [[ $unamestr != 'Darwin' ]]; then
        upgrade_command+=" --user"
    fi
    eval $upgrade_command
else
    echo '[错误] 未安装 python3-pip'
    exit 1
fi

# macOS 特定检查
if [[ $unamestr == 'Darwin' ]]; then
    if ! xcode-select -v &> /dev/null; then
        echo '请安装命令行工具'
        echo 'xcode-select --install'
        exit 1
    else
        echo '[安装] 找到 Xcode'
    fi
fi

echo '[安装] 安装必要组件'
python3 -m pip install --no-cache-dir wheel poetry==1.6.1 -i http://mirrors.aliyun.com/pypi/simple/
echo '[安装] poetry'
python3 -m poetry add pandas python-decouple openpyxl numpy joblib androguard scapy scikit-learn==1.5.0
echo '[安装] lock'
python3 -m poetry lock
echo '[安装] main'
python3 -m poetry install --no-root --only main --no-interaction --no-ansi

# 安装额外的Python依赖
# echo '[安装] 安装其他依赖'
# temp_pip_config="[global]\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple"
# mkdir -p ~/.pip
# echo -e $temp_pip_config > ~/.pip/pip.conf

# python3 -m poetry add pandas python-decouple openpyxl numpy joblib androguard

# # 移除临时pip配置
# rm -rf ~/.pip

# 创建目录并设置权限
mkdir -p /root/apply/download/screen
mkdir -p /root/apply/tmp
chmod -R 777 /root/apply

echo '[安装] 清理'
bash scripts/clean.sh y

echo '[安装] 数据库迁移'
export DJANGO_SUPERUSER_USERNAME=mobsf
export DJANGO_SUPERUSER_PASSWORD=mobsf
python3 -m poetry run python manage.py makemigrations
python3 -m poetry run python manage.py makemigrations StaticAnalyzer
python3 -m poetry run python manage.py migrate
python3 -m poetry run python manage.py createsuperuser --noinput --email ""
python3 -m poetry run python manage.py create_roles

if ! wkhtmltopdf -V &> /dev/null; then
    echo '下载并安装 wkhtmltopdf 以生成 PDF 报告 - https://wkhtmltopdf.org/downloads.html'
fi

echo '[安装] 安装完成'
