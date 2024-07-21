# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os

from django.conf import settings
from django.utils import timezone
from mobsf.MobSF.views.DAO import (
    check_hash_exists,
)
from decouple import config
from mobsf.StaticAnalyzer.models import RecentScansDB

save_file_path = config('SAVE_FILE_PATH')
logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME='',
                PACKAGE_NAME='',
                VERSION_NAME='',
                LIST=data['list'],
                MD5=data['hash'],
                TIMESTAMP=timezone.now())
            new_db_obj.save()
    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(content, extension):
    """Write Uploaded File."""
    md5 = hashlib.md5()
    bfr = isinstance(content, io.BufferedReader)
    if bfr:
        # Not File upload
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        # File upload
        for chunk in content.chunks():
            md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(f'{anal_dir}{md5sum}{extension}', 'wb+') as destination:
        if bfr:
            content.seek(0, 0)
            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            for chunk in content.chunks():
                destination.write(chunk)
    return md5sum

# def download_uploaded_file(f, save_file_path):
#     if not os.path.exists(save_file_path):
#         os.makedirs(save_file_path)
#     md5 = handle_uploaded_file(f, '.apk')
#     file_name = md5 + '.apk'
#     file_path = os.path.join(save_file_path, file_name)
#     with open(file_path, 'wb+') as destination:
#         for chunk in f.chunks():
#             destination.write(chunk)


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name
        self.data = {
            'analyzer': '静态解析',
            'status': '成功',
            'hash': '',
            'scan_type': '',
            'file_name': self.file_name,
            'list':'',
        }

    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apk'
        self.data['list'] = check_hash_exists(md5)
        add_to_recent_scan(self.data)
        # download_uploaded_file(self.file, save_file_path)
        logger.info('Performing Static Analysis of Android APK')
        return self.data

    def scan_xapk(self):
        """Android XAPK."""
        md5 = handle_uploaded_file(self.file, '.xapk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'xapk'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android XAPK base APK')
        return self.data

    def scan_apks(self):
        """Android Split APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apks'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android Split APK')
        return self.data

    def scan_jar(self):
        """Java JAR file."""
        md5 = handle_uploaded_file(self.file, '.jar')
        self.data['hash'] = md5
        self.data['scan_type'] = 'jar'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Java JAR')
        return self.data

    def scan_aar(self):
        """Android AAR file."""
        md5 = handle_uploaded_file(self.file, '.aar')
        self.data['hash'] = md5
        self.data['scan_type'] = 'aar'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android AAR')
        return self.data

    def scan_so(self):
        """Shared object file."""
        md5 = handle_uploaded_file(self.file, '.so')
        self.data['hash'] = md5
        self.data['scan_type'] = 'so'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Shared Object')
        return self.data

    def scan_zip(self):
        """Android /iOS Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip')
        self.data['hash'] = md5
        self.data['scan_type'] = 'zip'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android/iOS Source Code')
        return self.data

    def scan_ipa(self):
        """IOS Binary."""
        md5 = handle_uploaded_file(self.file, '.ipa')
        self.data['hash'] = md5
        self.data['scan_type'] = 'ipa'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of iOS IPA')
        return self.data

    def scan_dylib(self):
        """IOS Dylib."""
        md5 = handle_uploaded_file(self.file, '.dylib')
        self.data['hash'] = md5
        self.data['scan_type'] = 'dylib'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of iOS IPA')
        return self.data

    def scan_a(self):
        """Scan static library."""
        md5 = handle_uploaded_file(self.file, '.a')
        self.data['hash'] = md5
        self.data['scan_type'] = 'a'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Static Library')
        return self.data

    def scan_appx(self):
        """Windows appx."""
        md5 = handle_uploaded_file(self.file, '.appx')
        self.data['hash'] = md5
        self.data['scan_type'] = 'appx'
        self.data['analyzer'] = 'static_analyzer_windows'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Windows APP')
        return self.data
    
