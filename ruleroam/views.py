import hashlib
import json
import re
import shutil
import xml
import time
from django.contrib.auth.models import User
from django.contrib import auth
from django.shortcuts import render, redirect
from django.db.models import Sum, Max, F, Q
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from utils.logger import logger
from .models import *
from utils import mytools
# Create your views here.
from system.models import *
import markdown
from .forms import *


@login_required
def vulnPage(request):
    deo = UserNameManage.objects.all()
    result = {"user_list": deo}
    return render(request, 'ruleroam/vulnerability.html', result)

@login_required
def bugsPage(request):
    deo = UserNameManage.objects.all()
    request_type = "edit"
    result = {"user_list": deo, "request_type": request_type}
    return render(request, 'ruleroam/bugs.html', result)

@csrf_exempt
@login_required
def bugcreatePage(request):
    # https://zhuanlan.zhihu.com/p/45503393
    bug_name = request.GET.get("bug_name")
    # form = CreateBugForm()
    # logger.highlight(form)

    if bug_name:
        request_type = "edit"
        bug_obj = BugManage.objects.filter(bug_name__exact=bug_name).first()
        result = {"request_type": request_type, "request_data": bug_obj}
    else:
        request_type = "create"
        result = {"request_type": request_type}
    # logger.info(result)
    return render(request, 'ruleroam/bugcreate.html', result)


@csrf_exempt
@login_required
def bugdetailPage(request):
    bug_name = request.GET.get("bug_name")
    logger.warn(bug_name)

    # https://blog.csdn.net/weixin_43217710/article/details/82777029
    bug_obj = BugManage.objects.filter(bug_name__exact=bug_name).first()
    # 将markdown语法渲染成html样式
    extensions=[
        # # 包含 缩写、表格等常用扩展
        # 'markdown.extensions.extra',
        # # 语法高亮扩展
        # 'markdown.extensions.codehilite',
        # # 自动生成目录
        # 'markdown.extensions.toc',
        'markdown.extensions.extra',
        'markdown.extensions.abbr',
        'markdown.extensions.attr_list',
        'markdown.extensions.def_list',
        'markdown.extensions.fenced_code',
        'markdown.extensions.footnotes',
        'markdown.extensions.md_in_html',
        'markdown.extensions.tables',
        'markdown.extensions.admonition',
        'markdown.extensions.codehilite',
        'markdown.extensions.legacy_attrs',
        'markdown.extensions.legacy_em',
        'markdown.extensions.meta',
        'markdown.extensions.nl2br',
        'markdown.extensions.sane_lists',
        'markdown.extensions.smarty',
        'markdown.extensions.toc',
        'markdown.extensions.wikilinks'
    ]
    bug_detail = markdown.markdown(bug_obj.bug_detail, extensions=extensions)

    bug_detail = bug_detail.replace('<img alt="" src=', '<img alt="" style="width: 40%;" src=')
    bug_detail = bug_detail.replace('/></p>', '/></p></br>')

    logger.warn(bug_detail)

    result = {'bug_detail': bug_detail}
    # logger.warn(result)
    return render(request, 'ruleroam/bugdetail.html', result)




# @login_required
# def rulePage(request):
#     deo = UserNameManage.objects.all()
#     # mytools.get_new_rule_id(RuleManage.objects.all())
#     rule_version = "rule_100001"
#     result = {
#         "user_list": deo
#         ,"rule_version": rule_version
#     }
#     return render(request, 'ruleroam/rule.html', result)
#






@login_required
@csrf_exempt
def vuln_add_edit(request):
    logger.highlight(request.POST)
    if request.method == 'POST':
        request_data = json.loads(request.POST.get("request_data"))
        vuln_name = request_data.get("vuln_name")
        vuln_description = request_data.get("vuln_description")

        vuln_CVE = request_data.get("vuln_CVE")
        if vuln_CVE and not mytools.is_CVE_or_CNVD_or_CNNVD(vuln_CVE, msg_type="CVE"):
            option_msg = "CVE格式不正确, 请重新输入"
            option_status = "failed"
            logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
            return JsonResponse({"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}, safe=False)

        vuln_CNVD = request_data.get("vuln_CNVD")
        if vuln_CNVD and not mytools.is_CVE_or_CNVD_or_CNNVD(vuln_CNVD, msg_type="CNVD"):
            option_msg = "CNVD格式不正确, 请重新输入"
            option_status = "failed"
            logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
            return JsonResponse({"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}, safe=False)

        vuln_CNNVD = request_data.get("vuln_CNNVD")
        if vuln_CNNVD and not mytools.is_CVE_or_CNVD_or_CNNVD(vuln_CNNVD, msg_type="CNNVD"):
            option_msg = "CNNVD格式不正确, 请重新输入"
            option_status = "failed"
            logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
            return JsonResponse({"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}, safe=False)

        if vuln_name:
            current_ts = mytools.get_current_timestamp()
            request_type = request.POST.get("request_type")
            if request_type == "create":
                if VulnManage.objects.filter(vuln_name__exact=vuln_name).count() == 0:
                    VulnManage.objects.create(
                        vuln_name=vuln_name
                        , vuln_id=mytools.get_hash_8bit_md5(field="vuln_id", objects=VulnManage.objects.all())
                        , vuln_description=vuln_description
                        , vuln_CVE=vuln_CVE
                        , vuln_CNVD=vuln_CNVD
                        , vuln_CNNVD=vuln_CNNVD
                        , vuln_create_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                        , vuln_update_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                        , vuln_create_time=current_ts
                        , vuln_update_time=current_ts
                    )
                    option_msg = "漏洞信息创建成功</br>漏洞名称: {}".format(vuln_name)
                    option_status = "success"
                else:
                    option_msg = "漏洞名称已存在</br>漏洞名称: {}".format(vuln_name)
                    option_status = "failed"
            elif request_type == "edit":
                VulnManage.objects.filter(vuln_name__exact=vuln_name).update(
                    vuln_description=vuln_description
                    , vuln_CVE=vuln_CVE
                    , vuln_CNVD=vuln_CNVD
                    , vuln_CNNVD=vuln_CNNVD
                    , vuln_update_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                    , vuln_update_time=current_ts
                )
                option_msg = "漏洞信息修改成功</br>漏洞名称: {}".format(vuln_name)
                option_status = "success"
            else:
                option_msg = "提交的参数不正确, 请求方式: {}".format(request_type)
                option_status = "failed"
            logger.debug(option_msg)
        else:
            option_status = "failed"
            option_msg = "提交的漏洞信息格式不正确</br>部门名称: {}".format(vuln_name)
    else:
        option_status = "failed"
        option_msg = "当前的请求方式不正确"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result, safe=False)


def get_vuln_list(vuln_obj, request, method):
    tmp_list = []
    data_list = []  # 最终返回的结果集合
    for vuln in vuln_obj:
        data_dict = {
            "vuln_name": vuln.vuln_name
            , "vuln_id": vuln.vuln_id
            , "vuln_description": vuln.vuln_description
            , "vuln_CVE": vuln.vuln_CVE
            , "vuln_CNVD": vuln.vuln_CNVD
            , "vuln_CNNVD": vuln.vuln_CNNVD
            , "vuln_create_user": UserNameManage.objects.filter(username__exact=vuln.vuln_create_user).first().username
            , "vuln_update_user": UserNameManage.objects.filter(username__exact=vuln.vuln_update_user).first().username
            , "vuln_create_time": vuln.vuln_create_time
            , "vuln_update_time": vuln.vuln_update_time
        }
        tmp_list.append(data_dict)
    # logger.highlight(tmp_list)
    try:
        tmp_list.sort(key=lambda k: (k.get('vuln_update_time')), reverse=True)
    except TypeError as e:
        logger.error("漏洞列表排序异常: {}".format(repr(e)))

    if method == "GET":
        page = request.GET.get('page')
        limit = request.GET.get('limit')
    elif method == "POST":
        page = request.POST.get('page')
        limit = request.POST.get('limit')
    else:
        page = None
        limit = None
    if page and limit:
        for contact in Paginator(tmp_list, limit).page(page):
            data_list.append(contact)

    return data_list

@login_required
@csrf_exempt
def vulnlist(request):
    vuln_obj = VulnManage.objects.all()
    data_list = get_vuln_list(vuln_obj, request, "GET")
    option_status = "success"
    option_msg = "漏洞列表加载成功"
    total = vuln_obj.count()
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def vulnsearch(request):
    searchParams = json.loads(request.POST.get("searchParams"))
    vuln_name = searchParams.get("vuln_name")
    vuln_id = searchParams.get("vuln_id")
    vuln_user = searchParams.get("vuln_user")
    vuln_time = searchParams.get("vuln_time")
    vuln_description = searchParams.get("vuln_description")

    try:
        vuln_obj = VulnManage.objects.all()
        if vuln_name:
            logger.error([vuln_name])
            vuln_obj = vuln_obj.filter(vuln_name__icontains=vuln_name)
        if vuln_description:
            vuln_obj = vuln_obj.filter(vuln_description__icontains=vuln_description)
        if vuln_user:
            vuln_obj = vuln_obj.filter(Q(vuln_create_user=UserNameManage.objects.filter(username__exact=vuln_user).first())
                                       | Q(vuln_update_user=UserNameManage.objects.filter(username__exact=vuln_user).first()))
        if vuln_id:
            vuln_obj = vuln_obj.filter(Q(vuln_CVE__icontains=vuln_id)
                                       | Q(vuln_CNVD__icontains=vuln_id)
                                       | Q(vuln_CNNVD__icontains=vuln_id))
        if vuln_time:
            vuln_obj = vuln_obj.filter(Q(vuln_create_time__icontains=vuln_time)
                                       | Q(vuln_update_time__icontains=vuln_time))

        data_list = get_vuln_list(vuln_obj, request, "POST")
        logger.highlight(data_list)
        option_status = "success"
        total = vuln_obj.count()
        option_msg = "搜索成功,搜索的参数: {}, 结果总数: {}".format(searchParams, total)
    except Exception as e:
        option_status = "failed"
        option_msg = "异常处理: {}".format(repr(e))
        total = 0
        data_list = None

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)




@login_required
@csrf_exempt
def vulndelete(request):
    logger.highlight(request.POST)
    vuln_name = request.POST.get("vuln_name")
    vuln_id = request.POST.get("vuln_id")
    if request.method == "POST":
        if vuln_name and vuln_id:
            VulnManage.objects.filter(
                vuln_name=vuln_name
                , vuln_id=vuln_id
            ).delete()
            option_msg = "删除成功，漏洞名称: {}".format(vuln_name)
            option_status = "success"
        else:
            option_msg = "参数有误"
            option_status = "failed"
    else:
        option_msg = "提交的参数不正确"
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)


@login_required
@csrf_exempt
def vulnbatchdelete(request):
    # logger.highlight(request.POST)
    data_list = json.loads(request.POST.get("data"))
    delete_flag = True
    name_list = []
    for data in data_list:
        vuln_name = data.get("vuln_name")
        vuln_id = data.get("vuln_id")
        if vuln_name and vuln_id:
            VulnManage.objects.filter(
                vuln_name__exact=vuln_name
                , vuln_id__exact=vuln_id
            ).delete()
            name_list.append(vuln_name)
        else:
            delete_flag = False

    if delete_flag:
        logger.highlight(",".join(name_list))
        option_msg = "删除成功，漏洞名称: {}".format(",".join(name_list))
        option_status = "success"
    else:
        option_msg = "提交的参数不正确"
        option_status = "failed"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def bug_add_edit(request):
    # logger.highlight(request.POST)
    if request.method == 'POST':
        request_data = json.loads(request.POST.get("request_data"))
        bug_name = request_data.get("bug_name")
        bug_digest = request_data.get("bug_digest")
        bug_detail = request_data.get("bug_detail")
        # logger.error([bug_detail])
        if bug_name:
            current_ts = mytools.get_current_timestamp()
            request_type = request.POST.get("request_type")
            if request_type == "create":
                if BugManage.objects.all().count() != 0:
                    if BugManage.objects.filter(bug_name__exact=bug_name).count() == 0:
                        BugManage.objects.create(
                            bug_name=bug_name
                            , bug_id=mytools.get_hash_8bit_md5(field="bug_id", objects=BugManage.objects.all())
                            , bug_digest=bug_digest
                            , bug_detail=bug_detail
                            , bug_create_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                            , bug_update_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                            , bug_create_time=current_ts
                            , bug_update_time=current_ts
                        )
                        option_msg = "需求信息创建成功</br>需求名称: {}".format(bug_name)
                        option_status = "success"
                    else:
                        option_msg = "需求名称已存在</br>需求名称: {}".format(bug_name)
                        option_status = "failed"
                else:
                    BugManage.objects.create(
                        bug_name=bug_name
                        , bug_id=mytools.get_hash_8bit_md5(field="bug_id", objects=BugManage.objects.all())
                        , bug_digest=bug_digest
                        , bug_detail=bug_detail
                        , bug_create_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                        , bug_update_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                        , bug_create_time=current_ts
                        , bug_update_time=current_ts
                    )
                    option_msg = "需求信息创建成功</br>需求名称: {}".format(bug_name)
                    option_status = "success"
            elif request_type == "edit":
                BugManage.objects.filter(bug_name__exact=bug_name).update(
                    bug_digest=bug_digest
                    , bug_detail=bug_detail
                    , bug_update_user=UserNameManage.objects.filter(username__exact=request.user.username).first()
                    , bug_update_time=current_ts
                )
                option_msg = "需求信息修改成功</br>需求名称: {}".format(bug_name)
                option_status = "success"
            else:
                option_msg = "提交的参数不正确, 请求方式: {}".format(request_type)
                option_status = "failed"
            logger.debug(option_msg)
        else:
            option_status = "failed"
            option_msg = "提交的需求信息格式不正确</br>部门名称: {}".format(bug_name)
    else:
        option_status = "failed"
        option_msg = "当前的请求方式不正确"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result, safe=False)



def get_bug_list(bug_obj, request, method):
    tmp_list = []
    data_list = []  # 最终返回的结果集合
    for bug in bug_obj:
        print('bug.bug_create_user:',bug.bug_create_user)
        print('bug.bug_update_user:',bug.bug_update_user)
        data_dict = {
            "bug_name": bug.bug_name
            , "bug_id": bug.bug_id
            , "bug_digest": bug.bug_digest
            , "bug_detail": bug.bug_detail
            , "bug_create_user": UserNameManage.objects.filter(username__exact=bug.bug_create_user).first().username
            , "bug_update_user": UserNameManage.objects.filter(username__exact=bug.bug_update_user).first().username
            , "bug_create_time": bug.bug_create_time
            , "bug_update_time": bug.bug_update_time
        }
        tmp_list.append(data_dict)
    # logger.highlight(tmp_list)
    try:
        tmp_list.sort(key=lambda k: (k.get('bug_update_time')), reverse=True)
    except TypeError as e:
        logger.error("需求列表排序异常: {}".format(repr(e)))

    if method == "GET":
        page = request.GET.get('page')
        limit = request.GET.get('limit')
    elif method == "POST":
        page = request.POST.get('page')
        limit = request.POST.get('limit')
    else:
        page = None
        limit = None
    if page and limit:
        for contact in Paginator(tmp_list, limit).page(page):
            data_list.append(contact)

    return data_list

@login_required
@csrf_exempt
def buglist(request):
    bug_obj = BugManage.objects.all()
    data_list = get_bug_list(bug_obj, request, "GET")
    option_status = "success"
    option_msg = "需求列表加载成功"
    total = bug_obj.count()
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)


@login_required
@csrf_exempt
def bugsearch(request):
    searchParams = json.loads(request.POST.get("searchParams"))
    logger.error(searchParams.keys())
    bug_name = searchParams.get("bug_name")
    bug_detail = searchParams.get("bug_detail")
    bug_digest = searchParams.get("bug_digest")
    bug_user = searchParams.get("bug_user")
    bug_time = searchParams.get("bug_time")

    try:
        bug_obj = BugManage.objects.all()
        if bug_name:
            bug_obj = bug_obj.filter(bug_name__icontains=bug_name)

        if bug_detail:
            bug_obj = bug_obj.filter(bug_detail__icontains=bug_detail)

        if bug_digest:
            bug_obj = bug_obj.filter(bug_digest__icontains=bug_digest)

        if bug_user:
            bug_obj = bug_obj.filter(Q(bug_create_user=UserNameManage.objects.filter(username__exact=bug_user).first())
                                       | Q(bug_update_user=UserNameManage.objects.filter(username__exact=bug_user).first()))
        if bug_time:
            bug_obj = bug_obj.filter(Q(bug_create_time__icontains=bug_time)
                                       | Q(bug_update_time__icontains=bug_time))

        data_list = get_bug_list(bug_obj, request, "POST")
        option_status = "success"
        total = bug_obj.count()
        option_msg = "搜索成功,搜索的参数: {}, 结果总数: {}".format(searchParams, total)
    except Exception as e:
        option_status = "failed"
        option_msg = "异常处理: {}".format(repr(e))
        total = 0
        data_list = None

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)





@login_required
@csrf_exempt
def bugdelete(request):
    logger.highlight(request.POST)
    bug_name = request.POST.get("bug_name")
    bug_id = request.POST.get("bug_id")
    if request.method == "POST":
        if bug_name and bug_id:
            BugManage.objects.filter(
                bug_name=bug_name
                , bug_id=bug_id
            ).delete()
            option_msg = "删除成功，需求名称: {}".format(bug_name)
            option_status = "success"
        else:
            option_msg = "参数有误"
            option_status = "failed"
    else:
        option_msg = "提交的参数不正确"
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def bugbatchdelete(request):
    # logger.highlight(request.POST)
    # exit()
    data_list = json.loads(request.POST.get("data"))
    delete_flag = True
    name_list = []
    for data in data_list:
        bug_name = data.get("bug_name")
        bug_id = data.get("bug_id")
        if bug_name and bug_id:
            BugManage.objects.filter(
                bug_name__exact=bug_name
                , bug_id__exact=bug_id
            ).delete()
            name_list.append(bug_name)
        else:
            delete_flag = False

    if delete_flag:
        logger.highlight(",".join(name_list))
        option_msg = "删除成功，需求名称: {}".format(",".join(name_list))
        option_status = "success"
    else:
        option_msg = "提交的参数不正确"
        option_status = "failed"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)




