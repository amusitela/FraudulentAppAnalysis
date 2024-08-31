# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
)
from mobsf.MobSF.utils import (
    is_md5,
)
from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.home import RecentScans, Upload, delete_scan
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.StaticAnalyzer.views.android import view_source
from mobsf.StaticAnalyzer.views.android.static_analyzer import static_analyzer
from mobsf.StaticAnalyzer.views.ios import view_source as ios_view_source
from mobsf.StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from mobsf.StaticAnalyzer.views.common.shared_func import compare_apps
from mobsf.StaticAnalyzer.views.common.suppression import (
    delete_suppression,
    list_suppressions,
    suppress_by_files,
    suppress_by_rule_id,
)
from mobsf.MobSF.views.DAO import (
    load_whitelist,
    save_whitelist,
    load_blacklist,
    save_blacklist,
    delete_md5,
)
from mobsf.StaticAnalyzer.views.common.pdf import pdf
from mobsf.StaticAnalyzer.views.common.appsec import appsec_dashboard
from mobsf.StaticAnalyzer.views.windows import windows

import os
import sqlite3
import pandas as pd
from decouple import config
from django.http import JsonResponse
from django.core.files.storage import default_storage

@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - 上传 API。"""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)

@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - 获取最近扫描。"""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - 扫描 API。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    checksum = request.POST['hash']
    if not is_md5(checksum):
        return make_api_response(
            {'error': '无效的校验和'}, 500)
    robj = RecentScansDB.objects.filter(MD5=checksum)
    if not robj.exists():
        return make_api_response(
            {'error': '文件未上传/不可用'}, 500)
    scan_type = robj[0].SCAN_TYPE
    # APK, 源代码 (Android/iOS) ZIP, SO, JAR, AAR
    if scan_type in {'xapk', 'apk', 'apks', 'zip', 'so', 'jar', 'aar'}:
        resp = static_analyzer(request, checksum, True)
        if 'type' in resp:
            resp = static_analyzer_ios(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    # IPA
    elif scan_type in {'ipa', 'dylib', 'a'}:
        resp = static_analyzer_ios(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    # APPX
    elif scan_type == 'appx':
        resp = windows.staticanalyzer_windows(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - 删除扫描。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = delete_scan(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """生成并下载 PDF 报告。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True)
    if 'error' in resp:
        if resp.get('error') == '无效的扫描哈希':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'pdf_dat' in resp:
        response = HttpResponse(
            resp['pdf_dat'], content_type='application/pdf')
        response['Access-Control-Allow-Origin'] = '*'
    elif resp.get('report') == '未找到报告':
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'PDF 生成错误'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """生成 JSON 报告。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True,
        jsonres=True)
    if 'error' in resp:
        if resp.get('error') == '无效的扫描哈希':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'report_dat' in resp:
        response = make_api_response(resp['report_dat'], 200)
    elif resp.get('report') == '未找到报告':
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'JSON 生成错误'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """查看 Android & iOS 源文件。"""
    params = {'file', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    if request.POST['type'] in {'eclipse', 'studio',
                                'apk', 'java', 'smali'}:
        resp = view_source.run(request, api=True)
    else:
        resp = ios_view_source.run(request, api=True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_compare(request):
    """比较两个应用。"""
    params = {'hash1', 'hash2'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = compare_apps(
        request,
        request.POST['hash1'],
        request.POST['hash2'],
        True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_scorecard(request):
    """生成应用评分卡。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = appsec_dashboard(
        request,
        request.POST['hash'],
        api=True)
    if 'error' in resp:
        if resp.get('error') == '无效的扫描哈希':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'hash' in resp:
        response = make_api_response(resp, 200)
    elif 'not_found' in resp:
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'JSON 生成错误'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_rule_id(request):
    """POST - 通过规则 ID 抑制。"""
    params = {'rule', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = suppress_by_rule_id(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_files(request):
    """POST - 通过文件抑制。"""
    params = {'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = suppress_by_files(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_list_suppressions(request):
    """POST - 查看抑制项。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = list_suppressions(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_suppression(request):
    """POST - 删除抑制项。"""
    params = {'kind', 'type', 'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = delete_suppression(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response

# @csrf_exempt
# def import_whitelist(request):
#     if request.method == 'POST':
#         if 'file' not in request.FILES:
#             return make_api_response({'error': "未找到上传的文件"}, status=400)

#         file = request.FILES['file']
#         save_path = config('FILE_SAVE_PATH', default='/tmp')
#         file_path = os.path.join(save_path, file.name)

#         with open(file_path, 'wb+') as destination:
#             for chunk in file.chunks():
#                 destination.write(chunk)

#         try:
#             df = pd.read_excel(file_path)
#             required_columns = ['packageName', 'apkName', 'md5', 'result']
#             if not all(column in df.columns for column in required_columns):
#                 return make_api_response({'error': "Excel文件缺少必要的列: packageName, apkName, md5, result"}, status=400)

#             new_data = df[required_columns].to_dict('records')
#             save_whitelist(new_data)

#             return make_api_response({'message': "添加成功"}, status=200)
#         finally:
#             if os.path.exists(file_path):
#                 os.remove(file_path)

#     return make_api_response({'error': "不允许GET请求"}, status=400)

# @csrf_exempt
# def import_blacklist(request):
#     if request.method == 'POST':
#         if 'file' not in request.FILES:
#             return make_api_response({'error': "未找到上传的文件", 'code': "400"}, status=400)

#         file = request.FILES['file']
#         save_path = config('FILE_SAVE_PATH', default='/tmp')
#         file_path = os.path.join(save_path, file.name)

#         with open(file_path, 'wb+') as destination:
#             for chunk in file.chunks():
#                 destination.write(chunk)

#         try:
#             df = pd.read_excel(file_path)
#             required_columns = ['packageName', 'apkName', 'md5', 'result']
#             if not all(column in df.columns for column in required_columns):
#                 return make_api_response({'error': "Excel文件缺少必要的列: packageName, apkName, md5, result"}, 400)

#             new_data = df[required_columns].to_dict('records')
#             save_blacklist(new_data)

#             return make_api_response({'message': "添加成功", 'code': "200"}, status=200)
#         finally:
#             if os.path.exists(file_path):
#                 os.remove(file_path)

#     return make_api_response({'error': "不允许GET请求", 'code': "400"}, status=400)

@csrf_exempt
def import_whitelist(request):
    if request.method == 'POST':
        if 'file' not in request.FILES:
            return make_api_response({'error': "未找到上传的文件"}, status=400)

        file = request.FILES['file']
        save_path = config('FILE_SAVE_PATH', default='/tmp')
        file_path = os.path.join(save_path, file.name)

        with open(file_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        try:
            df = pd.read_excel(file_path)
            required_columns = ['packageName', 'apkName', 'md5', 'result']
            if not all(column in df.columns for column in required_columns):
                return make_api_response({'error': "Excel文件缺少必要的列: packageName, apkName, md5, result"}, status=400)

            whitelist_data = []
            blacklist_data = []

            for _, row in df.iterrows():
                record = row[required_columns].to_dict()
                if isinstance(record['result'], str) and record['result'] and ('black' in record['result'] or '黑' in record['result']):
                    blacklist_data.append(record)
                elif record['result'] == '' or not record['result']:
                    whitelist_data.append(record)
                else:
                    whitelist_data.append(record)

            if whitelist_data:
                save_whitelist(whitelist_data)
            if blacklist_data:
                save_blacklist(blacklist_data)

            return make_api_response({'message': "添加成功"}, status=200)
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

    return make_api_response({'error': "不允许GET请求"}, status=400)

@csrf_exempt
def import_blacklist(request):
    if request.method == 'POST':
        if 'file' not in request.FILES:
            return make_api_response({'error': "未找到上传的文件", 'code': "400"}, status=400)

        file = request.FILES['file']
        save_path = config('FILE_SAVE_PATH', default='/tmp')
        file_path = os.path.join(save_path, file.name)

        with open(file_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        try:
            df = pd.read_excel(file_path)
            required_columns = ['packageName', 'apkName', 'md5', 'result']
            if not all(column in df.columns for column in required_columns):
                return make_api_response({'error': "Excel文件缺少必要的列: packageName, apkName, md5, result"}, status=400)

            blacklist_data = []
            whitelist_data = []

            for _, row in df.iterrows():
                record = row[required_columns].to_dict()
                if isinstance(record['result'], str) and record['result'] and ('white' in record['result'] or '白' in record['result']):
                    whitelist_data.append(record)
                elif record['result'] == '' or not record['result']:
                    blacklist_data.append(record)
                else:
                    blacklist_data.append(record)

            if blacklist_data:
                save_blacklist(blacklist_data)
            if whitelist_data:
                save_whitelist(whitelist_data)

            return make_api_response({'message': "添加成功", 'code': "200"}, status=200)
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

    return make_api_response({'error': "不允许GET请求", 'code': "400"}, status=400)


@request_method(['POST'])
@csrf_exempt
def get_blacklist(request):
    packageName = request.POST.get('PackageName')
    apkName = request.POST.get('App')
    md5 = request.POST.get('MD5')
    result = request.POST.get('Result')
    page = int(request.POST.get('page'))
    size = int(request.POST.get('size', 10))
    try:
        data, total = load_blacklist(packageName, apkName, md5, result, page, size)
        response_data = {
            'items': data,
            'totalItems': total
        }
        return make_api_response(response_data, 200)
    except Exception as e:
        return make_api_response({'error': '查询错误', 'details': str(e)}, 400)

@request_method(['POST'])
@csrf_exempt
def get_whitelist(request):
    packageName = request.POST.get('PackageName')
    apkName = request.POST.get('App')
    md5 = request.POST.get('MD5')
    result = request.POST.get('Result')
    page = int(request.POST.get('page'))
    size = int(request.POST.get('size', 10))
    try:
        data, total = load_whitelist(packageName, apkName, md5, result, page, size)
        response_data = {
            'items': data,
            'totalItems': total
        }
        return make_api_response(response_data, 200)
    except Exception as e:
        return make_api_response({'error': '查询错误', 'details': str(e)}, 400)
    
@request_method(['POST'])
@csrf_exempt
def delete_list(request):
    md5 = request.POST.get('MD5')
    try:
        data = delete_md5(md5)
        return make_api_response(data, 200)
    except Exception as e:
        return make_api_response({'error': '操作错误', 'details': str(e)}, 400)
