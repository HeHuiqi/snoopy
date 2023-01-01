import json
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
from ruleroam.models import *
from utils import mytools
# Create your views here.
from django.contrib.auth.hashers import check_password, is_password_usable, make_password


def loginPage(request):
    return render(request, 'system/login.html')

@login_required
def userPage(request):
    deo = DepartmentManage.objects.all()
    result = {"department_list": deo}
    return render(request, 'system/user.html', result)

@login_required
def departmentPage(request):
    return render(request, 'system/department.html')


@login_required
def loginhistory(request):
    login_flag_list = [obj.login_flag for obj in LoginHistoryManage.objects.all()]
    result = {"flag_list": list(set(login_flag_list))}
    return render(request, 'system/loginhistory.html', result)

def login_history_handle(request, login_username, login_password, login_flag):
    login_client_ip = request.META.get('HTTP_X_FORWARDED_FOR').split(',')[0] if request.META.get('HTTP_X_FORWARDED_FOR') else request.META.get('REMOTE_ADDR')
    LoginHistoryManage.objects.create(
        login_username=login_username
        , login_password=login_password
        , login_client_ip=login_client_ip
        , login_flag=login_flag
        , login_time=mytools.get_current_timestamp()
    )

@csrf_exempt
def loginSubmit(request):
    logger.info("登录提交数据: {}".format(dict(request.POST)))
    if request.method == 'POST':
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)

        user = auth.authenticate(username=username, password=password)
        if user is not None and user.is_active:
            auth.login(request, user)
            request.session['user'] = username
            # 设置过期时间
            # request.session.set_expiry(0)
            option_status = "success"
            option_msg = "用户登陆成功</br>用户名: {}".format(username)
            login_history_handle(request, username, password, "登录成功")
        else:
            option_status = "failed"
            # option_msg = "用户名或者密码错误</br>用户名: {}</br>密码: {}".format(username, password)
            option_msg = "用户名或者密码错误"
            login_history_handle(request, username, password, "登录失败")
    else:
        option_status = "failed"
        option_msg = "当前的请求方式不正确"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result, safe=False)

@login_required
@csrf_exempt
def logoutSubmit(request):
    if request.method == 'POST':
        logoutsubmit = request.POST.get('logoutsubmit', None)
        if request.user.is_authenticated:
            username = request.user.username
        else:
            username = None

        if logoutsubmit == "yes":
            logout(request)
            option_status = "success"
            option_msg = "{} 注销成功，正在跳转登录页面".format(username)

            login_history_handle(request, username, request.COOKIES.get("sessionid"), "注销成功")
        else:
            option_msg = '{} 账户注销失败'.format(username)
            option_status = "failed"
            login_history_handle(request, username, request.COOKIES.get("sessionid"), "注销失败")
    else:
        option_msg = '请求方式有误'
        option_status = "failed"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result, safe=False)


@login_required
@csrf_exempt
def changePasswdSubmit(request):

    if request.method == 'POST':
        old_password = request.POST.get('old_password', None)
        new_password = request.POST.get('new_password', None)
        again_password = request.POST.get('again_password', None)

        if not request.user.check_password(old_password):
            result = '旧密码不正确'
            return JsonResponse(result, safe=False)

        elif new_password != again_password:
            result = '两次密码不一致'
            return JsonResponse(result, safe=False)

        else:
            request.user.set_password(new_password)
            request.user.save()
            logout(request)     # 修改密码之后注销重新登录
            result = '密码修改成功'
            # return HttpResponseRedirect('/user/login/')
    else:
        result = '请求方式有误'
    return JsonResponse(result, safe=False)



@login_required
@csrf_exempt
def department_add_edit(request):
    # logger.highlight(request.POST)
    if request.method == 'POST':
        request_data = json.loads(request.POST.get("request_data"))
        dpt_name = request_data.get("department_name")
        dpt_desc = request_data.get("department_description")
        if dpt_name:
            current_ts = mytools.get_current_timestamp()
            request_type = request.POST.get("request_type")
            if request_type == "create":
                DepartmentManage.objects.create(
                    department_name=dpt_name
                    , department_description=dpt_desc
                    , department_createtime=current_ts
                    , department_updatetime=current_ts
                )
                option_msg = "部门名称创建成功</br>部门名称: {}".format(dpt_name)
                option_status = "success"
            elif request_type == "edit":
                DepartmentManage.objects.filter(department_name__exact=dpt_name).update(
                    department_description=dpt_desc
                    , department_updatetime=current_ts
                )
                option_msg = "部门名称修改成功</br>部门名称: {}".format(dpt_name)
                option_status = "success"
            else:
                option_msg = "提交的参数不正确, 请求方式: {}".format(request_type)
                option_status = "failed"
            logger.debug(option_msg)
        else:
            option_status = "failed"
            option_msg = "提交的部门名称格式不正确</br>部门名称: {}".format(dpt_name)
    else:
        option_status = "failed"
        option_msg = "当前的请求方式不正确"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result, safe=False)


def get_department_list(dpt_obj, request, method):
    tmp_list = []
    data_list = []  # 最终返回的结果集合
    for dpt in dpt_obj:
        data_dict = {
            "department_name": dpt.department_name
            , "department_description": dpt.department_description
            , "department_createtime": dpt.department_createtime
            , "department_updatetime": dpt.department_updatetime
        }
        tmp_list.append(data_dict)

    try:
        tmp_list.sort(key=lambda k: (k.get('updatetime')), reverse=True)
    except TypeError as e:
        logger.error("部门列表排序异常: {}".format(repr(e)))

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
def departmentlist(request):
    dpt_obj = DepartmentManage.objects.all()
    data_list = get_department_list(dpt_obj, request, "GET")

    option_status = "success"
    option_msg = "部门列表加载成功"
    total = dpt_obj.count()
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)

@login_required
@csrf_exempt
def departmentsearch(request):
    searchParams = json.loads(request.POST.get("searchParams"))
    name = searchParams.get("name")
    dpt_obj = DepartmentManage.objects.all()
    if name:
        dpt_obj = DepartmentManage.objects.filter(department_name__icontains=name)
    data_list = get_department_list(dpt_obj, request, "POST")
    logger.highlight(data_list)

    option_status = "success"
    total = dpt_obj.count()
    option_msg = "搜索成功,搜索的参数: {}, 总数: {}".format(name, total)
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)






@login_required
@csrf_exempt
def departmentdelete(request):
    name = request.POST.get("name")
    if request.method == "POST":
        u_d_obj = UserNameManage.objects.filter(user_department__department_name__exact=name)
        if u_d_obj.count() > 0:
            user_list = []
            for u_d in u_d_obj:
                user_list.append(u_d.username)
            logger.error("该部门仍包含在使用用户，请删除所含用户后重试")
            option_msg = "该部门【{}】 仍包含在使用用户</br>请删除所含用户【{}】后重试".format(name, ",".join(user_list))
            option_status = "failed"
        else:
            if name:
                DepartmentManage.objects.filter(department_name__exact=name).delete()
                option_msg = "部门名称删除成功: {} ".format(name)
                option_status = "success"
            else:
                option_msg = "提交的参数不正确"
                option_status = "failed"
    else:
        option_msg = "提交的参数不正确"
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def departmentbatchdelete(request):
    data_list = json.loads(request.POST.get("data"))
    delete_flag = True
    name_list = []
    for data in data_list:
        name = data.get("name")
        if name:
            u_d_obj = UserNameManage.objects.filter(user_department__department_name__exact=name)
            if u_d_obj.count() > 0:
                user_list = []
                for u_d in u_d_obj:
                    user_list.append(u_d.username)
                option_msg = "该部门【{}】 仍包含在使用用户</br>请删除所含用户【{}】后重试".format(name, ",".join(user_list))
                logger.error(option_msg)
                option_status = "failed"
                total = DepartmentManage.objects.all().count()
                result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
                return JsonResponse(result,  safe=False)
            else:
                DepartmentManage.objects.filter(department_name__exact=name).delete()
                name_list.append(name)
        else:
            delete_flag = False
    if delete_flag:
        logger.highlight(name_list)
        option_msg = "部门名称删除成功: {} ".format(",".join(name_list))
        option_status = "success"
    else:
        option_msg = "提交的参数不正确: {}".format(data_list)
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)





@login_required
@csrf_exempt
def user_add_edit(request):
    if request.method == 'POST':
        request_data = json.loads(request.POST.get("request_data"))
        user_username = request_data.get("username")
        user_department = request_data.get("department")
        user_sex = request_data.get("sex")
        user_email = request_data.get("email")
        user_work = request_data.get("work")
        user_description = request_data.get("description")

        if not mytools.is_email(user_email):
            option_status = "failed"
            option_msg = "邮箱格式不正确: {}".format(user_email)
        elif not user_department:
            option_status = "failed"
            option_msg = "部门名称不能为空"
        elif not user_sex and user_sex != "男" and user_sex != "女":
            logger.highlight(user_sex)
            option_status = "failed"
            option_msg = "性别格式不正确"
        else:
            current_ts = mytools.get_current_timestamp()
            request_type = request.POST.get("request_type")
            if request_type == "create":
                password = mytools.get_random_password()
                UserNameManage.objects.create(
                    username=user_username
                    , user_department=DepartmentManage.objects.filter(department_name__exact=user_department).first()
                    , user_sex=user_sex
                    , user_email=user_email
                    , user_work=user_work
                    , user_desc=user_description
                    , user_createtime=current_ts
                    , user_updatetime=current_ts
                    , password=make_password(password)
                )
                option_msg = "用户创建成功</br>用户名称: {}</br>密码: {}".format(user_username, password)
                option_status = "success"
            elif request_type == "edit":
                UserNameManage.objects.filter(username__exact=user_username).update(
                    user_department=DepartmentManage.objects.filter(department_name__exact=user_department).first()
                    , user_sex=user_sex
                    , user_email=user_email
                    , user_work=user_work
                    , user_desc=user_description
                    , user_updatetime=current_ts
                )
                option_msg = "用户修改成功</br>用户名称: {}".format(user_username)
                option_status = "success"
            else:
                option_msg = "提交的参数不正确, 请求方式: {}".format(request_type)
                option_status = "failed"

        logger.debug("{}, 提交的参数为: {}".format(option_msg, dict(request.POST)))
    else:
        option_status = "failed"
        option_msg = "当前的请求方式不正确"
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": None}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result, safe=False)


def get_user_name_list(user_obj, request, method):
    tmp_list = []
    data_list = []  # 最终返回的结果集合
    for user in user_obj:
        data_dict = {
            "username": user.username
            , "user_sex": user.user_sex
            # , "user_mobile": user.user_mobile
            , "user_work": user.user_work
            , "user_email": user.user_email
            , "user_department": user.user_department.department_name if user.user_department else ""
            , "user_desc": user.user_desc
            , "user_createtime": user.user_createtime
            , "user_updatetime": user.user_updatetime
        }
        if user.username == "admin":
            continue
        tmp_list.append(data_dict)

    try:
        tmp_list.sort(key=lambda k: (k.get('user_updatetime')), reverse=True)
    except TypeError as e:
        logger.error("用户列表排序异常: {}".format(repr(e)))

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
def userlist(request):
    user_obj = UserNameManage.objects.all()
    data_list = get_user_name_list(user_obj, request, "GET")

    option_status = "success"
    option_msg = "用户列表加载成功"
    total = user_obj.count()
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def usersearch(request):
    searchParams = json.loads(request.POST.get("searchParams"))
    logger.highlight(searchParams)
    user_department = searchParams.get("user_department")
    username = searchParams.get("username")
    user_work = searchParams.get("user_work")
    user_email = searchParams.get("user_email")

    # if otherdata:
    #     cty_obj = cty_obj.filter(Q(ctyun_asset_description__icontains=otherdata)
    #                              | Q(ctyun_asset_common__icontains=otherdata)
    #                              | Q(ctyun_asset_createtime__icontains=otherdata)
    #                              | Q(ctyun_asset_updatetime__icontains=otherdata)
    #                              | Q(ctyun_asset_deliveryBatch__icontains=otherdata)
    #                              )

    try:
        user_obj = UserNameManage.objects.all()
        if username:
            user_obj = user_obj.filter(username__icontains=username)
        if user_email:
            user_obj = user_obj.filter(user_email__icontains=user_email)
        if user_department:
            user_obj = user_obj.filter(user_department=DepartmentManage.objects.filter(department_name__exact=user_department).first())
        if user_work:
            user_obj = user_obj.filter(user_work__icontains=user_work)
    except Exception as e:
        logger.error("异常处理: {}".format(repr(e)))
        user_obj = UserNameManage.objects.all()

    data_list = get_user_name_list(user_obj, request, "POST")
    logger.highlight(data_list)

    option_status = "success"
    total = user_obj.count()
    option_msg = "搜索成功,搜索的参数: {}, 总数: {}".format(username, total)
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def userpassreset(request):
    username = request.POST.get("username")
    if username:
        password = mytools.get_random_password()
        UserNameManage.objects.filter(username__exact=username).update(
            password=make_password(password)
        )
        option_msg = "密码重置成功!</br>用户名：{}</br> 密码： {}".format(username, password)
        option_status = "success"
    else:
        option_msg = "提交的参数不正确: {}".format(username)
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)


@login_required
@csrf_exempt
def userpassedit(request):
    logger.highlight(request.POST)
    old_password = request.POST.get("old_password")
    new_password = request.POST.get("new_password")
    again_password = request.POST.get("again_password")

    if old_password and new_password and again_password:
        user_obj = UserNameManage.objects.filter(username__exact=request.user.username).first()
        if check_password(old_password, user_obj.password):
            if new_password == again_password:
                UserNameManage.objects.filter(username__exact=request.user.username).update(
                    password=make_password(new_password)
                )
                option_msg = "用户名：{}</br> 密码： {}".format(request.user.username, new_password)
                option_status = "success"
            else:
                option_msg = "两次密码不一致,请重新输入"
                option_status = "failed"
        else:
            option_msg = "原密码不正确"
            option_status = "failed"
    else:
        option_msg = "提交的参数不正确"
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def userdelete(request):
    username = request.POST.get("username")
    user_sex = request.POST.get("user_sex")
    user_email = request.POST.get("user_email")
    user_work = request.POST.get("user_work")
    user_department = request.POST.get("user_department")
    user_desc = request.POST.get("user_desc")

    if request.method == "POST":
        if username:
            user_obj_search = UserNameManage.objects.filter(username__exact=username).first()
            if BugManage.objects.filter(bug_create_user=user_obj_search).count() > 0 or \
                    BugManage.objects.filter(bug_update_user=user_obj_search).count() > 0 or \
                    VulnManage.objects.filter(vuln_create_user=user_obj_search).count() > 0 or \
                    VulnManage.objects.filter(vuln_update_user=user_obj_search).count() > 0 or \
                    RuleManage.objects.filter(rule_create_user=user_obj_search).count() > 0 or \
                    RuleManage.objects.filter(rule_update_user=user_obj_search).count() > 0:
                option_msg = "用户在占用，无法删除"
                option_status = "failed"
            else:
                UserNameManage.objects.filter(
                    username=username
                    , user_sex=user_sex
                    , user_email=user_email
                    , user_work=user_work
                    , user_department=DepartmentManage.objects.filter(department_name=user_department).first()
                    , user_desc=user_desc
                ).delete()
                option_msg = "删除成功，用户名: {}".format(username)
                option_status = "success"
        else:
            option_msg = "提交的参数不正确"
            option_status = "failed"
    else:
        option_msg = "请求方式有误"
        option_status = "failed"

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": 0, "data": option_msg}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)



@login_required
@csrf_exempt
def userbatchdelete(request):
    data_list = json.loads(request.POST.get("data"))
    delete_flag = True
    name_list = []
    if data_list:
        for data in data_list:
            username = data.get("username")
            if username:
                UserNameManage.objects.filter(username__exact=username).delete()
                name_list.append(username)
            else:
                delete_flag = False
    if delete_flag:
        dpt_obj = DepartmentManage.objects.all()
        data_list = get_user_name_list(dpt_obj, request, "")
        logger.highlight(name_list)
        option_msg = "部门名称删除成功: {} ".format(",".join(name_list))
        option_status = "success"
        total = dpt_obj.count()
    else:
        option_msg = "提交的参数不正确: {}".format(data_list)
        option_status = "failed"
        total = 1
        data_list = []

    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)




def get_login_history_list(login_obj, request, method):
    tmp_list = []
    data_list = []  # 最终返回的结果集合
    for login in login_obj:
        data_dict = {
            "login_username": login.login_username
            , "login_password": login.login_password
            , "login_client_ip": login.login_client_ip
            , "login_flag": login.login_flag
            , "login_time": login.login_time
        }
        tmp_list.append(data_dict)

    try:
        tmp_list.sort(key=lambda k: (k.get('login_time')), reverse=True)
    except TypeError as e:
        logger.error("登录日志列表排序异常: {}".format(repr(e)))

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
def loginhistorylist(request):
    login_obj = LoginHistoryManage.objects.all()
    data_list = get_login_history_list(login_obj, request, "GET")

    option_status = "success"
    option_msg = "登录日志列表加载成功"
    total = login_obj.count()
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)


@login_required
@csrf_exempt
def loginhistorysearch(request):
    searchParams = json.loads(request.POST.get("searchParams"))
    logger.highlight(searchParams)
    username = searchParams.get("username")
    client_ip = searchParams.get("client_ip")
    login_flag = searchParams.get("login_flag")
    login_time = searchParams.get("login_time")

    login_obj = LoginHistoryManage.objects.all()
    if username:
        login_obj = login_obj.filter(login_username__icontains=username)
    if client_ip:
        login_obj = login_obj.filter(login_client_ip__icontains=client_ip)
    if login_flag:
        login_obj = login_obj.filter(login_flag__icontains=login_flag)
    if login_time:
        login_obj = login_obj.filter(login_time__icontains=login_time)

    data_list = get_login_history_list(login_obj, request, "POST")
    logger.highlight(data_list)

    option_status = "success"
    total = login_obj.count()
    option_msg = "搜索成功, 搜索的参数: {}, 总数: {}".format(username, total)
    result = {"code": 0, "status": option_status, "msg": option_msg, "count": total, "data": data_list}
    logger.info("{}, 请求的路径: {}".format(option_msg, request.path))
    return JsonResponse(result,  safe=False)

















# @csrf_exempt
# def loginRequired(request):
#     # return HttpResponseRedirect('/user/login')
#     return render(request, 'system/loginRequired.html')


@login_required
def welcome1(request):
    return render(request, 'system/welcome-1.html')

@login_required
def welcome2(request):
    return render(request, 'system/welcome-2.html')


@login_required
def welcome3(request):
    return render(request, 'system/welcome-3.html')


@login_required
def changePasswd(request):
    return render(request, 'system/user-password.html')

@login_required
def index(request):
    return render(request, 'system/index.html')


@login_required
def changeUserSetting(request):
    return render(request, 'system/user-setting.html')


def page404(request):
    return render(request, 'system/404.html')


def notFount(request,  exception=404):
    return render(request, 'system/404.html')

def serverError(request):
    return render(request, 'system/404.html')

def forbidden(request, exception=403):
    return render(request, 'system/404.html')

@login_required
def menu(request):
    return render(request, 'system/menu.html')

@login_required
def setting(request):
    return render(request, 'system/setting.html')

@login_required
def form(request):
    return render(request, 'system/form.html')

@login_required
def formStep(request):
    return render(request, 'system/form-step.html')

@login_required
def layer(request):
    return render(request, 'system/layer.html')

@login_required
def button(request):
    return render(request, 'system/button.html')

@login_required
def colorSelect(request):
    return render(request, 'system/color-select.html')

@login_required
def tableSelect(request):
    return render(request, 'system/table-select.html')

@login_required
def table(request):
    return render(request, 'system/table.html')

@login_required
def icon(request):
    return render(request, 'system/icon.html')

@login_required
def iconPicker(request):
    return render(request, 'system/icon-picker.html')

@login_required
def upload(request):
    return render(request, 'system/upload.html')

@login_required
def editor(request):
    return render(request, 'system/editor.html')

@login_required
def usersetting(request):
    return render(request, 'system/user-setting.html')


@login_required
def userpassword(request):
    return render(request, 'system/user-password.html')



def quser(request):
    user = UserNameManage.objects.filter(username__exact=request.user.username).first()
    print(user.id)
    rsp = '返回：'
    return HttpResponse(rsp)


