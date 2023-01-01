# -*- coding:utf-8 -*-
import hashlib
import os
import datetime
import time

from django.views import generic
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from utils.logger import logger
from django.views.decorators.clickjacking import xframe_options_exempt

# TODO 此处获取default配置，当用户设置了其他配置时，此处无效，需要进一步完善
MDEDITOR_CONFIGS = settings.MD_DEFAULT_CONFIG


class UploadView(generic.View):
    """ upload image file """

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(UploadView, self).dispatch(*args, **kwargs)

    @xframe_options_exempt
    @csrf_exempt
    def post(self, request, *args, **kwargs):
        upload_image = request.FILES.get("editormd-image-file", None)

        # 输入校验
        if not upload_image:
            return JsonResponse({
                'success': 0,
                'message': "未获取到要上传的图片",
                'url': ""
            })

        # 文件名和后缀拆分
        file_name_list = upload_image.name.split('.')
        file_extension = file_name_list.pop(-1)
        file_name = '.'.join(file_name_list)

        # 校验文件后缀格式
        if file_extension not in MDEDITOR_CONFIGS['upload_image_formats']:
            return JsonResponse({
                'success': 0,
                'message': "上传图片格式错误，允许上传图片格式为：%s" % ','.join(
                    MDEDITOR_CONFIGS['upload_image_formats']),
                'url': ""
            })

        # 文件目录检查
        file_path = os.path.join(os.getcwd(), settings.MD_IMAGES)
        if not os.path.exists(file_path):
            try:
                os.makedirs(file_path)
            except Exception as err:
                return JsonResponse({
                    'success': 0,
                    'message': "上传失败：%s" % repr(err),
                    'url': ""
                })

        # 保存图片
        file_full_name = '%s%s.%s' % (hashlib.md5(file_name.encode("utf-8")).hexdigest(), str(int(time.time())), file_extension)
        # ![图片介绍](http://pxpfco2u1.bkt.clouddn.com/markdown20190921144356.png){:width="100%" align=center}

        # 文件写入
        write_path = os.path.join(os.getcwd(), settings.MD_IMAGES, file_full_name)

        with open(write_path, 'wb+') as file:
            for chunk in upload_image.chunks():
                file.write(chunk)

        url_path = os.path.join(settings.MD_IMAGES, file_full_name)
        # logger.highlight(url_path)
        result = {'success': 1, 'message': "上传成功！", 'url': url_path}
        logger.error(result)
        return JsonResponse(result, safe=False)
