import os
import sqlite3
import pandas as pd
from decouple import config
from mobsf.MobSF.views.api.api_middleware import make_api_response
from django.http import JsonResponse
from django.core.files.storage import default_storage
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from mobsf.StaticAnalyzer.models import Whitelist, Blacklist


def load_whitelist(packageName=None, apkName=None, md5=None, result=None, page=1, size=10):
    filters = {}
    if packageName:
        filters['packageName'] = packageName
    if apkName:
        filters['apkName'] = apkName
    if md5:
        filters['md5'] = md5
    if result:
        filters['result'] = result

    data = Whitelist.objects.filter(**filters).order_by('md5').values('packageName', 'apkName', 'md5', 'result')
    paginator = Paginator(data, size)
    try:
        paginated_data = paginator.page(page)
    except PageNotAnInteger:
        paginated_data = paginator.page(1)
    except EmptyPage:
        paginated_data = paginator.page(paginator.num_pages)

    return list(paginated_data), paginator.count


def load_blacklist(packageName=None, apkName=None, md5=None, result=None, page=1, size=10):
    filters = {}
    if packageName:
        filters['packageName'] = packageName
    if apkName:
        filters['apkName'] = apkName
    if md5:
        filters['md5'] = md5
    if result:
        filters['result'] = result

    data = Blacklist.objects.filter(**filters).order_by('md5').values('packageName', 'apkName', 'md5', 'result')
    paginator = Paginator(data, size)
    try:
        paginated_data = paginator.page(page)
    except PageNotAnInteger:
        paginated_data = paginator.page(1)
    except EmptyPage:
        paginated_data = paginator.page(paginator.num_pages)

    return list(paginated_data), paginator.count

def save_whitelist(data):
    for item in data:
        Whitelist.objects.update_or_create(
            md5=item['md5'],
            defaults={
                'packageName': item['packageName'],
                'apkName': item['apkName'],
                'result': item.get('result', 'white')
            }
        )


def save_blacklist(data):
    for item in data:
        Blacklist.objects.update_or_create(
            md5=item['md5'],
            defaults={
                'packageName': item['packageName'],
                'apkName': item['apkName'],
                'result': item.get('result', 'black')
            }
        )

def delete_md5(md5):
    if Blacklist.objects.filter(md5=md5).exists():
        Blacklist.objects.filter(md5=md5).delete()
        return(f"从黑名单删除MD5:{md5}")
    elif Whitelist.objects.filter(md5=md5).exists():
        Whitelist.objects.filter(md5=md5).delete()
        return(f"从白名单删除MD5:{md5} ")
    else:
        return(f"不存在MD5{md5}")

def check_hash_exists(md5_hash):
    if Whitelist.objects.filter(md5=md5_hash).exists():
        return "白名单"
    elif Blacklist.objects.filter(md5=md5_hash).exists():
        return "黑名单"
    else:
        return "未知"


# DATABASE_FILE = config('DATABASE_FILE')

# def create_tables(request):
#     conn = sqlite3.connect(DATABASE_FILE)
#     cursor = conn.cursor()
#     cursor.execute('''
#     CREATE TABLE IF NOT EXISTS whitelist (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         packageName TEXT,
#         apkName TEXT,
#         md5 TEXT,
#         result TEXT
#     )
#     ''')
#     cursor.execute('''
#     CREATE TABLE IF NOT EXISTS blacklist (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         packageName TEXT,
#         apkName TEXT,
#         md5 TEXT,
#         result TEXT
#     )
#     ''')
#     conn.commit()
#     conn.close()
#     return make_api_response(
#             {'message': '建表成功'}, 200)

# def load_whitelist(packageName=None, apkName=None, md5=None, result=None):
#     conn = sqlite3.connect(DATABASE_FILE)
#     cursor = conn.cursor()
    
#     # 基础查询语句
#     query = 'SELECT packageName, apkName, md5, result FROM whitelist'
#     params = []
#     conditions = []

#     # 根据提供的参数添加条件
#     if packageName is not None:
#         conditions.append('packageName = ?')
#         params.append(packageName)
#     if apkName is not None:
#         conditions.append('apkName = ?')
#         params.append(apkName)
#     if md5 is not None:
#         conditions.append('md5 = ?')
#         params.append(md5)
#     if result is not None:
#         conditions.append('result = ?')
#         params.append(result)

#     # 如果有条件，则添加 WHERE 子句
#     if conditions:
#         query += ' WHERE ' + ' AND '.join(conditions)

#     cursor.execute(query, params)
#     data = cursor.fetchall()
#     conn.close()
    
#     return [dict(packageName=row[0], apkName=row[1], md5=row[2], result=row[3]) for row in data]

# def load_blacklist(packageName=None, apkName=None, md5=None, result=None):
#     conn = sqlite3.connect(DATABASE_FILE)
#     cursor = conn.cursor()
    
#     # 基础查询语句
#     query = 'SELECT packageName, apkName, md5, result FROM blacklist'
#     params = []
#     conditions = []

#     # 根据提供的参数添加条件
#     if packageName is not None:
#         conditions.append('packageName = ?')
#         params.append(packageName)
#     if apkName is not None:
#         conditions.append('apkName = ?')
#         params.append(apkName)
#     if md5 is not None:
#         conditions.append('md5 = ?')
#         params.append(md5)
#     if result is not None:
#         conditions.append('result = ?')
#         params.append(result)

#     # 如果有条件，则添加 WHERE 子句
#     if conditions:
#         query += ' WHERE ' + ' AND '.join(conditions)

#     cursor.execute(query, params)
#     data = cursor.fetchall()
#     conn.close()
    
#     return [dict(packageName=row[0], apkName=row[1], md5=row[2], result=row[3]) for row in data]

# def save_whitelist(data):
#     conn = sqlite3.connect(DATABASE_FILE)
#     cursor = conn.cursor()

#     check_query = 'SELECT 1 FROM whitelist WHERE md5 = ?'
    
#     insert_query = '''
#     INSERT INTO whitelist (packageName, apkName, md5, result)
#     VALUES (:packageName, :apkName, :md5, :result)
#     '''
    
#     for item in data:
#         md5_hash = item['md5']
        
#         cursor.execute(check_query, (md5_hash,))
#         exists = cursor.fetchone() is not None
        
#         if not exists:
#             cursor.execute(insert_query, item)
    
#     conn.commit()
#     conn.close()

# def save_blacklist(data):
#     conn = sqlite3.connect(DATABASE_FILE)
#     cursor = conn.cursor()

#     check_query = 'SELECT 1 FROM blacklist WHERE md5 = ?'
    
#     insert_query = '''
#     INSERT INTO blacklist (packageName, apkName, md5, result)
#     VALUES (:packageName, :apkName, :md5, :result)
#     '''
    
#     for item in data:
#         md5_hash = item['md5']
        
#         cursor.execute(check_query, (md5_hash,))
#         exists = cursor.fetchone() is not None
        
#         if not exists:
#             cursor.execute(insert_query, item)
    
#     conn.commit()
#     conn.close()


# def check_hash_exists(md5_hash):
#     conn = sqlite3.connect(DATABASE_FILE)
#     cursor = conn.cursor()
    
#     cursor.execute('SELECT 1 FROM whitelist WHERE md5 = ?', (md5_hash,))
#     whitelist_exists = cursor.fetchone() is not None
    
#     cursor.execute('SELECT 1 FROM blacklist WHERE md5 = ?', (md5_hash,))
#     blacklist_exists = cursor.fetchone() is not None
    
#     conn.close()
    
#     if whitelist_exists:
#         return "白名单"
#     elif blacklist_exists:
#         return "黑名单"
#     else:
#         return "未知"