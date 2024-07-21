#!/bin/bash

# 定义变量
FRONTEND_DIST_PATH="/root/Desktop/dist"
NGINX_HTML_PATH="/usr/share/nginx/html"
NGINX_CONF_PATH="/etc/nginx/conf.d/rjb.conf"
FRONTEND_PORT=8001
BACKEND_URL="http://192.168.100.143:8000"
SERVER_IP="192.168.100.143"

# 安装Nginx
sudo yum install -y epel-release
sudo yum install -y nginx

# 启动并启用Nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# 复制dist文件到Nginx目录
sudo cp -r $FRONTEND_DIST_PATH $NGINX_HTML_PATH

# 创建Nginx配置文件
sudo bash -c "cat > $NGINX_CONF_PATH" <<EOL
server {
    listen $FRONTEND_PORT;
    server_name $SERVER_IP;
    client_max_body_size 100M;
    root $NGINX_HTML_PATH/dist;
     

    location / {
        try_files \$uri \$uri/ /index.html;
    	  add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    location /api/ {
        proxy_pass $BACKEND_URL;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        add_header Access-Control-Allow-Origin *;
	 add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
	 add_header Access-Control-Allow-Headers "Authorization, Content-Type";
	    if ($request_method = 'OPTIONS') {
	        return 204;
	    }
	 rewrite ^/api/(.*)$ /$1 break;
		
	 proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        # Logging all requests for debugging
        access_log /var/log/nginx/api_access.log;
        error_log /var/log/nginx/api_error.log debug;
    }
}
EOL

# 测试Nginx配置
sudo nginx -t

# 重新加载Nginx
sudo systemctl reload nginx

# 设置防火墙
sudo firewall-cmd --zone=public --add-port=$FRONTEND_PORT/tcp --permanent
sudo firewall-cmd --reload

echo "部署完成。您的Vue2应用应可以通过 http://$SERVER_IP:$FRONTEND_PORT 访问"
