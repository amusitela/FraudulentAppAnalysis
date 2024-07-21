# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.views.decorators.csrf import csrf_exempt

from django.db.models import ObjectDoesNotExist

from mobsf.MobSF.views.helpers import request_method
from pathlib import Path
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.DynamicAnalyzer.views.android import (
    dynamic_analyzer,
    operations,
    report,
    tests_common,
    tests_frida,
)
from mobsf.DynamicAnalyzer.views.common import (
    device,
    frida,
)
from mobsf.MobSF.views.ai_model import(
    chatGPT
)
from mobsf.MobSF.views.DAO import (
    check_hash_exists,
)
from mobsf.MobSF.utils import (
    get_android_dm_exception_msg,
    get_config_loc,
    get_device,
    get_proxy_ip,
    is_md5,
    print_n_send_error_response,
    python_list,
    strict_package_check,
)
import json
import os
from django.http import FileResponse, Http404
from decouple import config
from datetime import datetime
from django.conf import settings
from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.MobSF.views.make_ips import(
    extract_and_save_ips_from_pcap,
    load_common_ips,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.MobSF.utils import (
    get_device,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
import logging

logger = logging.getLogger(__name__)
screen = config('SCREEN')
tcp_path = config('TCPDUMP')
save_file = config('FILE_SAVE_PATH')
save_path = config('SAVE_FILE_PATH')
config_ip_file = config('CONFIG_IP_FILE')
# 动态分析 API
@request_method(['GET'])
@csrf_exempt
def api_get_apps(request):
    """GET - 获取动态分析应用的 API。"""
    resp = dynamic_analyzer.android_dynamic_analysis(request, True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_start_analysis(request):
    """POST - 开始动态分析。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = dynamic_analyzer.dynamic_analyzer(
        request,
        request.POST['hash'],
        True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_logcat(request):
    """POST - 获取 Logcat HTTP 流 API。"""
    if 'package' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    lcat = dynamic_analyzer.logcat(request, True)
    if isinstance(lcat, dict):
        if 'error' in lcat:
            return make_api_response(
                lcat, 500)
    return lcat


# Android 操作 API
@request_method(['POST'])
@csrf_exempt
def api_mobsfy(request):
    """POST - MobSFy API。"""
    if 'identifier' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = operations.mobsfy(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_screenshot(request):
    """POST - 截屏 API。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = operations.take_screenshot(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_adb_execute(request):
    """POST - ADB 执行 API。"""
    if 'cmd' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = operations.execute_adb(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_root_ca(request):
    """POST - MobSF CA 操作 API。"""
    if 'action' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = operations.mobsf_ca(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_global_proxy(request):
    """POST - MobSF 全局代理 API。"""
    if 'action' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = operations.global_proxy(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


# Android 动态测试 API
@request_method(['POST'])
@csrf_exempt
def api_act_tester(request):
    """POST - Activity 测试。"""
    params = {'test', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = tests_common.activity_tester(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_start_activity(request):
    """POST - 启动 Activity。"""
    params = {'activity', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = tests_common.start_activity(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_tls_tester(request):
    """POST - TLS/SSL 安全测试。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = tests_common.tls_tests(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_stop_analysis(request):
    """POST - 停止动态分析。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    tests_common.collect_logs(request, True)
    resp = tests_common.download_data(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


# Android Frida API
@request_method(['POST'])
@csrf_exempt
def api_instrument(request):
    """POST - Frida 插桩。"""
    params = {
        'hash',
        'default_hooks',
        'auxiliary_hooks',
        'frida_code'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = tests_frida.instrument(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_api_monitor(request):
    """POST - Frida API 监控。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = tests_frida.live_api(request, True)
    # live_api 可以是 json 或 html
    if resp.get('data'):
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_frida_logs(request):
    """POST - Frida 日志。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = frida.frida_logs(request, True)
    # frida 日志可以是 json 或 html
    if resp.get('data') or resp.get('message'):
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_list_frida_scripts(request):
    """POST - 列出 Frida 脚本。"""
    if 'device' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = frida.list_frida_scripts(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_get_script(request):
    """POST - 获取 Frida 脚本。"""
    if not request.POST.getlist('scripts[]'):
        return make_api_response(
            {'error': '缺少参数'}, 422)
    if 'device' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = frida.get_script(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_get_dependencies(request):
    """POST - 获取 Frida 运行时依赖。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = tests_frida.get_runtime_dependencies(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


# 报告 API
@request_method(['POST'])
@csrf_exempt
def api_dynamic_report(request):
    """POST - 动态分析报告。"""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = report.view_report(
        request,
        request.POST['hash'],
        True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_dynamic_view_file(request):
    """POST - 动态分析报告。"""
    params = {'hash', 'file', 'type'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': '缺少参数'}, 422)
    resp = device.view_file(request, True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)

@request_method(['POST'])
@csrf_exempt
def my_analysis(request):
    """POST - 开始动态分析。"""
    error = ''
    file_path = []
    max_attempts = 3  # 最大尝试次数
    attempts = 0

    if request.method != 'POST':
        return make_api_response({'error': 'Invalid request method'}, 405)

    if 'hash' not in request.POST:
        return make_api_response({'error': '缺少参数'}, 422)

    sta_resp = get_activity(request.POST['hash'])
    max_attempts =int(request.POST['maxAttempts']) 

    if isinstance(sta_resp, dict) and 'error' in sta_resp:
        return make_api_response(sta_resp, 500)

    if 'activities' in sta_resp:
        for activity in sta_resp['activities']:
            mutable_post = request.POST.copy()
            mutable_post['activity'] = activity
            request.POST = mutable_post

            act_resp = tests_common.start_activity(request, True)
            if 'error' in act_resp:
                return make_api_response({'error':act_resp['error']})
            if act_resp['status'] == 'ok':
                # 尝试多次截屏
                screenshot_success = False
                for attempt in range(2):
                    mutable_post = request.POST.copy()
                    mutable_post['cmd'] = 'shell screencap -p /sdcard/screenshot.png'
                    request.POST = mutable_post
                    cmd_resp = operations.execute_adb(request, True)
                    if cmd_resp['status'] == 'ok':
                        mutable_post = request.POST.copy()
                        # 使用 attempts 变量生成唯一的文件名
                        screenshot_filename = f'{screen}/{request.POST["hash"]}_{attempts}.png'
                        mutable_post['cmd'] = f'pull /sdcard/screenshot.png {screenshot_filename}'
                        request.POST = mutable_post
                        cmd_resp1 = operations.execute_adb(request, True)
                        if cmd_resp1['status'] == 'ok':
                            file_path.append(screenshot_filename)
                            screenshot_success = True
                            break
                        else:
                            error = cmd_resp1.get('error', '在拉取截图时发生未知错误')
                    else:
                        error = cmd_resp.get('error', '在截取截图时发生未知错误')

                if not screenshot_success:
                    return make_api_response({'error': error})

                attempts += 1
                if attempts >= max_attempts:
                    res = ''
                    selfList = check_hash_exists(request.POST['hash'])
                    if selfList == '白名单':
                        res = '安全'
                    elif selfList == '黑名单':
                        res = '黑产'
                    else: 
                        res = chatGPT(file_path)
                    update_recent_scan_dynamic(request.POST['hash'], res)
                    return make_api_response({'message': res})
        
        res = ''
        selfList = check_hash_exists(request.POST['hash'])
        if selfList == '白名单':
            res = '安全'
        elif selfList == '黑名单':
            res = '黑产'
        else: 
            res = chatGPT(file_path)
        update_recent_scan_dynamic(request.POST['hash'], res)
        return make_api_response({'message': res})
        
    else:
         logger.error('该APK无法使用自动模式，请手动处理')
         return make_api_response({'error':'该APK无法使用自动模式，请手动处理'})

    # 如果没有成功返回任何响应，则返回一个默认响应
    return make_api_response({'error': '动态分析失败'}, 500)





    # """POST - 开始动态分析。"""
    # error = ''
    # file_path = []
    # max_attempts = 3  # 最大尝试次数
    # attempts = 0

    # if 'hash' not in request.POST:
    #     return make_api_response({'error': '缺少参数'}, 422)

    # sta_resp = dynamic_analyzer.dynamic_analyzer(request, request.POST['hash'], True)
    # if 'error' not in sta_resp:
    #     for activity in sta_resp['activities']:
    #         mutable_post = request.POST.copy()
    #         mutable_post['activity'] = activity
    #         request.POST = mutable_post

    #         act_resp = tests_common.start_activity(request, True)
    #         if act_resp['status'] == 'ok':
    #             # 尝试多次截屏
    #             screenshot_success = False
    #             for attempt in range(max_attempts):
    #                 mutable_post = request.POST.copy()
    #                 mutable_post['cmd'] = 'shell screencap -p /sdcard/screenshot.png'
    #                 request.POST = mutable_post
    #                 cmd_resp = operations.execute_adb(request, True)
    #                 if cmd_resp['status'] == 'ok':
    #                     mutable_post = request.POST.copy()
    #                     # 使用 attempts 变量生成唯一的文件名
    #                     screenshot_filename = f'{screen}/{request.POST["hash"]}_{attempts}.png'
    #                     mutable_post['cmd'] = f'pull /sdcard/screenshot.png {screenshot_filename}'
    #                     request.POST = mutable_post
    #                     cmd_resp1 = operations.execute_adb(request, True)
    #                     if cmd_resp1['status'] == 'ok':
    #                         file_path.append(screenshot_filename)
    #                         screenshot_success = True
    #                         break
    #                     else:
    #                         error = cmd_resp1.get('error', '在拉取截图时发生未知错误')
    #                 else:
    #                     error = cmd_resp.get('error', '在截取截图时发生未知错误')

    #             if not screenshot_success:
    #                 return make_api_response({'error': error}, 500)

    #             attempts += 1
    #             if attempts >= max_attempts:
    #                 res = ''
    #                 selfList = check_hash_exists(request.POST['hash'])
    #                 if selfList == '白名单':
    #                     res = '安全'
    #                 elif selfList == '黑名单':
    #                     res = '黑产'
    #                 else: 
    #                     res = chatGPT(file_path)
    #                 if update_recent_scan_dynamic(request.POST['hash'],res):
    #                     return make_api_response({'message':res}, 200)
    #                 else:
    #                     return make_api_response({'error':'更新数据库失败'}, 400)
    # else:
    #     error = sta_resp['error']
    #     print(error)
    #     return make_api_response({'error': error}, 400)
   

# @request_method(['POST'])
# @csrf_exempt
# def my_analysis(request):
#     """POST - 开始动态分析。"""
#     error = ''
#     file_path = []
#     max_attempts = 3  # 最大尝试次数
#     attempts = 0

#     if 'hash' not in request.POST:
#         return make_api_response({'error': '缺少参数'}, 422)

#     # 启动抓包
#     start_packet_capture(request)

#     sta_resp = dynamic_analyzer.dynamic_analyzer(request, request.POST['hash'], True)
#     if 'error' not in sta_resp:
#         for activity in sta_resp['activities']:
#             mutable_post = request.POST.copy()
#             mutable_post['activity'] = activity
#             request.POST = mutable_post

#             act_resp = tests_common.start_activity(request, True)
#             if act_resp['status'] == 'ok':
#                 # 尝试多次截屏
#                 screenshot_success = False
#                 for attempt in range(max_attempts):
#                     mutable_post = request.POST.copy()
#                     mutable_post['cmd'] = 'shell screencap -p /sdcard/screenshot.png'
#                     request.POST = mutable_post
#                     cmd_resp = operations.execute_adb(request, True)
#                     if cmd_resp['status'] == 'ok':
#                         mutable_post = request.POST.copy()
#                         # 使用 attempts 变量生成唯一的文件名
#                         screenshot_filename = f'{screen}/{request.POST["hash"]}_{attempts}.png'
#                         mutable_post['cmd'] = f'pull /sdcard/screenshot.png {screenshot_filename}'
#                         request.POST = mutable_post
#                         cmd_resp1 = operations.execute_adb(request, True)
#                         if cmd_resp1['status'] == 'ok':
#                             file_path.append(screenshot_filename)
#                             screenshot_success = True
#                             break
#                         else:
#                             error = cmd_resp1.get('error', '在拉取截图时发生未知错误')
#                     else:
#                         error = cmd_resp.get('error', '在截取截图时发生未知错误')

#                 if not screenshot_success:
#                     # 停止抓包
#                     stop_packet_capture(request)
#                     return make_api_response({'error': error}, 500)

#                 attempts += 1
#                 if attempts >= max_attempts:
#                     print(request.POST['hash'])
#                     tests_common.collect_logs(request, True)
#                     resp = tests_common.download_data(request, True)
#                     if resp['status'] == 'ok':
#                         res = ''
#                         selfList = check_hash_exists(request.POST['hash'])
#                         if selfList == '白名单':
#                             res = '安全'
#                         else: 
#                             res = chatGPT(file_path)
#                         update_recent_scan_dynamic(request.POST['hash'],res)
                        
#                         # 停止抓包
#                         stop_packet_capture(request)
                        
#                         # 拉取抓包文件
#                         local_capture_file, cmd_resp = pull_capture_file(request)
#                         if cmd_resp['status'] != 'ok':
#                             return make_api_response({'error': '抓包文件拉取失败'}, 500)
                        
#                         # 提取URL
#                         # urls = extract_urls_from_pcap(local_capture_file)

#                         return make_api_response({'response': cmd_resp}, 200)
#                     break
#             else:
#                 # 停止抓包
#                 stop_packet_capture(request)
#                 return make_api_response(act_resp, 500)
#     else:
#         error = sta_resp['error']
    
#     # 发生错误时也停止抓包
#     stop_packet_capture(request)

#     return make_api_response({'file_path': file_path, 'error': error}, 200)

@request_method(['POST'])
@csrf_exempt
def hand_analysis(request):
    """POST - 开始动态分析。"""
    if 'hash' not in request.POST:
        logger.error('缺少参数')
        return make_api_response({'error': '缺少参数'}, 422)
    
    try:
            identifier = get_device()
    except Exception:
            return make_api_response({'error':'没有获取到设备'},400)

    try:
        checksum = request.POST['hash']
        apk_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.apk'
        
        mutable_post = request.POST.copy()
        mutable_post['cmd'] = f'install -r {apk_path}'
        request.POST = mutable_post
        
        cmd_resp = operations.execute_adb(request, True)
        if 'success' in cmd_resp.get('message', '').lower():
            return make_api_response({'message': '安装apk成功'}, 200)
        else:
            return make_api_response({'error': '此 APK 无法安装。该 APK 是否与 Android VM/模拟器兼容？'}, 400)
    except Exception as e:
        logger.error('安装apk时发生错误: %s', str(e))
        return make_api_response({'error': '安装apk失败'+e}, 400)
    # Install APK
        # reinstall = '1'

        # package = get_package_name(checksum)
        # if not package:
        #     return make_api_response({'error':'没有这个apk'},400)
        
        # env = Environment(identifier)
        # status, output = env.install_apk(
        #     apk_path.as_posix(),
        #     package,
        #     reinstall)
        # if not status:
        #     # Unset Proxy
        #     env.unset_global_proxy()
        #     msg = (f'此 APK 无法安装。该 APK 是否与 Android VM/模拟器兼容？\n{output}')
        #     return make_api_response({'error': '此 APK 无法安装。该 APK 是否与 Android VM/模拟器兼容？'}, 400)
    # except Exception as e:
    #     logger.error('安装apk时发生错误: %s', str(e))
    #     return make_api_response({'error': '安装apk失败'+e}, 400)

@request_method(['POST'])
@csrf_exempt
def take_screen(request):
    """POST - 开始动态分析。"""
    error = ''
    file_path = []

    if 'hash' not in request.POST or 'attempts' not in request.POST:
        logger.error('缺少参数')
        return make_api_response({'error': '缺少参数'}, 422)

    try:
        attempts = int(request.POST['attempts'])
        maxAttempts = int(request.POST['maxAttempts'])
    except ValueError:
        logger.error('无效的 attempts 参数')
        return make_api_response({'error': '无效的 attempts 参数'}, 422)

    mutable_post = request.POST.copy()
    mutable_post['cmd'] = 'shell screencap -p /sdcard/screenshot.png'
    request.POST = mutable_post
    cmd_resp = operations.execute_adb(request, True)
    if cmd_resp['status'] == 'ok':
        post = request.POST.copy()
        screenshot_filename = f'{screen}/{request.POST["hash"]}_{attempts}.png'
        logger.info(f'Screenshot filename: {screenshot_filename}')
        post['cmd'] = f'pull /sdcard/screenshot.png {screenshot_filename}'
        request.POST = post
        cmd_resp1 = operations.execute_adb(request, True)
        if cmd_resp1['status'] == 'ok':
            logger.info(f'Screenshot attempt {attempts} successful')
            error = '没有错误'
        else:
            error = cmd_resp1.get('error', '在拉取截图时发生未知错误')
            logger.error(f'Error pulling screenshot: {error}')
            return make_api_response({'error': error}, 400)
    else:
        error = cmd_resp.get('error', '在截取截图时发生未知错误')
        logger.error(f'Error taking screenshot: {error}')
        return make_api_response({'error': error}, 400)

    if attempts == maxAttempts:
        for i in range(1, maxAttempts+1):
            screenshot_filename = f'{screen}/{request.POST["hash"]}_{i}.png'
            file_path.append(screenshot_filename)
        res = ''
        selfList = check_hash_exists(request.POST['hash'])
        if selfList == '白名单':
            res = '安全'
        elif selfList == '黑名单':
            res = '黑产'
        else: 
            res = chatGPT(file_path)
        update_recent_scan_dynamic(request.POST['hash'], res)
        logger.info(f'Result: {res}')
        return make_api_response({'message': res}, 200)
    else:
        return make_api_response({'message': '截图成功'}, 200)

@request_method(['POST'])
@csrf_exempt    
def start_capture(request):
    if 'hash' not in request.POST:
        logger.error('缺少参数')
        return make_api_response({'error': '缺少参数'}, 422)
    
    mutable_post = request.POST.copy()
    mutable_post['action'] = 'unset'
    request.POST = mutable_post 
    resp_proxy = operations.global_proxy(request, True)
    if resp_proxy['status'] != 'ok':
        return make_api_response({'error':'关闭代理失败'})
    
    mutable_post = request.POST.copy()
    mutable_post['action'] = 'install'
    request.POST = mutable_post 
    resp_ca = operations.mobsf_ca(request, True)
    if resp_ca['status'] != 'ok':
        return make_api_response({'error':'安装证书失败'})


    # 检测/sdcard目录下是否有tcpdump
    mutable_post = request.POST.copy()
    mutable_post['cmd'] = 'shell ls /sdcard/tcpdump'
    request.POST = mutable_post
    cmd_resp = operations.execute_adb(request, True)

    if cmd_resp['status'] != 'ok' or '/sdcard/tcpdump' not in cmd_resp.get('message', ''):
        logger.info('tcpdump 不存在，推送文件...')
        push_post = request.POST.copy()
        push_post['cmd'] = f'push {tcp_path} /sdcard/'
        request.POST = push_post
        push_resp = operations.execute_adb(request, True)
        if push_resp['status'] != 'ok':
            error = '推送 tcpdump 时发生未知错误'
            logger.error(f'Error pushing tcpdump: {error}')
            return make_api_response({'error': error}, 400)
    
    # 使用tcpdump进行抓包
    capture_post = request.POST.copy()
    capture_post['cmd'] = 'shell tcpdump -i any -p -s 0 -w /sdcard/capture.pcap'
    request.POST = capture_post
    capture_resp = operations.execute_capture(request, True)

    if capture_resp['message'] == 'ok':
        return make_api_response({'message': "开始抓包..."}, 200)
    else:
        error = '在抓包时发生未知错误'
        logger.error(f'Error starting capture: {error}')
        return make_api_response({'error': error}, 400)

@request_method(['POST'])
@csrf_exempt
def end_capture(request):

    if 'hash' not in request.POST:
        logger.error('缺少参数')
        return make_api_response({'error': '缺少参数'}, 422)
    
    # 结束抓包
    find_pid_post = request.POST.copy()
    find_pid_post['cmd'] = 'shell pgrep tcpdump'
    request.POST = find_pid_post
    find_pid_resp = operations.execute_adb(request, True)

    if find_pid_resp['status'] == 'ok' and find_pid_resp.get('message'):
        pid = find_pid_resp['message'].strip()
        stop_capture_post = request.POST.copy()
        stop_capture_post['cmd'] = f'shell kill -2 {pid}'  
        request.POST = stop_capture_post
        stop_capture_resp = operations.execute_adb(request, True)

        if stop_capture_resp['status'] == 'ok':
            logger.info('抓包结束成功')
        else:
            error = '在结束抓包时发生未知错误'
            logger.error(f'Error stopping capture: {error}')
            return make_api_response({'error': error}, 400)
    else:
        error = find_pid_resp.get('error', '未找到 tcpdump 进程')
        logger.error(f'Error finding tcpdump PID: {error}')
        return make_api_response({'error': error}, 400)
    
    # 拉取抓包文件到本地
    save_pacp_path = f'{save_file}/{request.POST["hash"]}.pcap'
    pull_capture_post = request.POST.copy()
    pull_capture_post['cmd'] = f'pull /sdcard/capture.pcap {save_pacp_path}'
    request.POST = pull_capture_post
    pull_capture_resp = operations.execute_adb(request, True)

    if pull_capture_resp['status'] == 'ok':
        logger.info('成功拉取抓包文件到本地')
        common_ips = load_common_ips(config_ip_file)
        res = extract_and_save_ips_from_pcap(save_pacp_path,common_ips,f'{save_path}/{request.POST["hash"]}.txt')
        mutable_post = request.POST.copy()
        mutable_post['action'] = 'set'
        request.POST = mutable_post 
        resp_proxy = operations.global_proxy(request, True)
        if resp_proxy['status'] != 'ok':
            return make_api_response({'error':'开启代理失败'})
        return make_api_response({'message': res},200)
    else:
        error = pull_capture_resp.get('error', '在拉取抓包文件时发生未知错误')
        logger.error(f'Error pulling capture file: {error}')
        return make_api_response({'error': error}, 400)
    

@request_method(['POST'])
@csrf_exempt
def auto_capture(request):
    if 'hash' not in request.POST:
        logger.error('缺少参数')
        return make_api_response({'error': '缺少参数'}, 422)
    
    mutable_post = request.POST.copy()
    mutable_post['action'] = 'unset'
    request.POST = mutable_post 
    resp_proxy = operations.global_proxy(request, True)
    if resp_proxy['status'] != 'ok':
        return make_api_response({'error':'关闭代理失败'})
    
    mutable_post = request.POST.copy()
    mutable_post['action'] = 'install'
    request.POST = mutable_post 
    resp_ca = operations.mobsf_ca(request, True)
    if resp_ca['status'] != 'ok':
        return make_api_response({'error':'安装证书失败'})


    # 检测/sdcard目录下是否有tcpdump
    mutable_post = request.POST.copy()
    mutable_post['cmd'] = 'shell ls /sdcard/tcpdump'
    request.POST = mutable_post
    cmd_resp = operations.execute_adb(request, True)

    if cmd_resp['status'] != 'ok' or '/sdcard/tcpdump' not in cmd_resp.get('message', ''):
        logger.info('tcpdump 不存在，推送文件...')
        push_post = request.POST.copy()
        push_post['cmd'] = f'push {tcp_path} /sdcard/'
        request.POST = push_post
        push_resp = operations.execute_adb(request, True)
        if push_resp['status'] != 'ok':
            error = '推送 tcpdump 时发生未知错误'
            logger.error(f'Error pushing tcpdump: {error}')
            return make_api_response({'error': error}, 400)
    
    # 使用tcpdump进行抓包
    capture_post = request.POST.copy()
    capture_post['cmd'] = 'shell tcpdump -i any -p -s 0 -w /sdcard/capture.pcap'
    request.POST = capture_post
    capture_resp = operations.execute_capture(request, True)
    if 'error' in capture_resp:
        return make_api_response({'error':'启动抓包失败，请检查tcpdump位置是否正确。'},400)
    
    try:
        sta_resp = get_activity(request.POST['hash'])
        if 'error' not in sta_resp:
            for activity in sta_resp['activities']:
                mutable_post = request.POST.copy()
                mutable_post['activity'] = activity
                request.POST = mutable_post
                tests_common.start_activity(request, True)
        end_capture(request)
        return make_api_response({'message':'抓包成功'},200)
    except Exception as e:
        end_capture(request)
        return make_api_response({'error':'先检查apk是否和VM兼容或者使用手动抓包'},400)
       

@request_method(['POST'])
@csrf_exempt
def send_txt_file(request):
    if 'hash' not in request.POST:
        logger.error('缺少参数')
        return make_api_response({'error': '缺少参数'}, 422)
    """根据本地路径发送一个TXT文件"""
    file_path = f'{save_path}/{request.POST["hash"]}.txt'
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
        return response
    else:
        raise Http404("File not found")

def update_recent_scan_dynamic(hash_value, data):
    try:
        db_obj = RecentScansDB.objects.get(MD5=hash_value)
        db_obj.DYNAMIC = data  
        db_obj.save()  
        return True  
    except RecentScansDB.DoesNotExist:
        return False  
    except Exception as e:
        print(f"更新数据库失败: {e}")
        return False  
    
def get_activity(checksum):
    """Android 动态分析环境。"""
    try:
        identifier = None
        activities = None
        exported_activities = None
        package = get_package_name(checksum)
        
        try:
            identifier = get_device()
        except Exception:
            return {'error':'获取设备错误'}

        # 从静态分析结果中获取活动信息
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(MD5=checksum)
            exported_activities = python_list(static_android_db.EXPORTED_ACTIVITIES)
            activities = python_list(static_android_db.ACTIVITIES)
        except ObjectDoesNotExist:
            logger.warning('获取活动失败。未完成应用的静态分析。')

        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = f'不能连接到设备 {identifier}'
            return {'error'+msg}

        version = env.get_android_version()
        logger.info('检测到的 Android 版本为 %s', version)

        xposed_first_run = False
        if not env.is_mobsfyied(version):
            msg = ('此 Android 实例未进行 MobSFy 或版本过旧。\n'
                   '正在对 Android 运行环境进行 MobSFy')
            logger.warning(msg)
            if not env.mobsfy_init():
                return {'error':'MobSFy 失败'}
            if version < 5:
                # 启动剪贴板监控器
                env.start_clipmon()
                xposed_first_run = True

        if xposed_first_run:
            msg = ('在进行动态分析之前，您是否已对实例进行了 MobSFy？'
                   '请为 Xposed 安装框架。'
                   '重启设备并启用所有 Xposed 模块。最后再次重启设备。')
            return {'error'+msg}

        # 安装 APK
        apk_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.apk'
        status, output = env.install_apk(apk_path.as_posix(), package, '1')
        if not status:
            # 取消设置代理
            env.unset_global_proxy()
            msg = (f'无法安装此 APK。此 APK 是否与 Android 虚拟机/模拟器兼容？\n{output}')
            return {'error': msg}

        logger.info('测试环境已准备就绪！')
        context = {
            'hash': checksum,
            'activities': activities,
            'exported_activities': exported_activities,
            'title': '动态分析器'
        }
        print(context)
        return context

    except Exception:
        logger.warning('获取活动失败。未完成应用的静态分析。')