# 使用 wget 下载 SQLite 源代码
wget https://www.sqlite.org/2022/sqlite-autoconf-3390400.tar.gz

# 解压缩文件
tar -xvf sqlite-autoconf-3390400.tar.gz

# 进入解压后的目录
cd sqlite-autoconf-3390400

# 配置、编译并安装 SQLite
./configure
make
sudo make install

# 验证安装
sqlite3 --version

