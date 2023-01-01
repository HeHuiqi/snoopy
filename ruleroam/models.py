from django.db import models
# from django.contrib.auth import get_user_model
# User = get_user_model()

from system.models import UserNameManage


# apt install mysql
# from tinymce.models import HTMLField
# pip3 install django-tinymce
# 先生成应用 python3 manage.py startapp Assets
# 设置数据里 setting
# 创建空数据库 create schema  `ruleroam` DEFAULT CHARACTER SET utf8;
# setting 中加入应用名'booktest'
# 定义以下类之后生成迁移 python3 manage.py makemigrations ，自动生成 00001_initial.py，为数据库
# python manage.py syncdb 同步数据库
# celery -A AseetRadar worker -l info   执行 celery
#
# 迁移 python3 manage.py migrate
# 当执行 python manage.py makemigrations 出现错误：TypeError: init() missing 1 required positional argument: ‘on_delete’
#   添加 book = models.ForeignKey('BookInfo', on_delete=models.CASCADE)
# 提示decode错误 query = query.decode(errors=‘replace’) 将decode修改为encode即可
# 定义url: index类
# from django.urls import path
# from . import views
# # 定义自己的 URL
# urlpatterns = [path('', views.index, name='index'),]
# 创建模板文件,index.html
# views 中修改返回值,会返回给index.html
# 运行 python3 manage.py runserver

# 富文本编辑器需要安装 pip3 install django-tinymce
from mdeditor.fields import MDTextField   # 必须导入 markdwown
from mongoengine import *
from mongoengine import StringField, URLField, ListField
import mongoengine
from mongoengine import connect
connect("fracture")


# pip install markdown #view视图中获取到数据库的数据，修饰为html语句，传到前端
# pip install Pygments #实现代码高亮
# 安装第二个包后还要执行
# pygmentize -S default -f html -a .codehilite > markdown_highlighy.css
# pygmentize -S default -f html -a .codehilite > default.css
# pygmentize -S monokai  -f hl -a .codehilite > monokai.css

# 查看支持的风格
# from pygments.styles import STYLE_MAP
# for key in STYLE_MAP.keys():
#     print(key)
# https://blog.csdn.net/mouday/article/details/83114164

# 在文件夹下会发现生成了code.css文件，将这个css文件加入到你的static文件夹下css里面(路径自己定，只要用的时候引入正确就行了)
# 最后一步在需要高亮的html文件里面导入刚刚生成的css文件，例如我的是->要在
# <link rel="stylesheet" type="text/css" href="{% static 'static/css/markdown_highlighy.css' %}">  {#语法高亮#}


class VulnManage(models.Model):
    vuln_name = models.CharField(max_length=200, primary_key=True, unique=True, verbose_name='漏洞名称')
    vuln_id = models.CharField(max_length=100, unique=True, verbose_name='漏洞ID')
    vuln_description = models.CharField(max_length=1000, null=True, verbose_name='漏洞描述')
    vuln_CVE = models.CharField(max_length=1000, null=True, verbose_name='漏洞CVE')
    vuln_CNVD = models.CharField(max_length=1000, null=True, verbose_name='漏洞CNVD')
    vuln_CNNVD = models.CharField(max_length=1000, null=True, verbose_name='漏洞CNNVD')
    vuln_create_user = models.ForeignKey(UserNameManage, null=True, verbose_name='创建人', related_name='vuln_create_user', on_delete=models.CASCADE)
    vuln_update_user = models.ForeignKey(UserNameManage, null=True, verbose_name='修改人', related_name='vuln_update_user', on_delete=models.CASCADE)
    vuln_create_time = models.CharField(max_length=100, null=True, verbose_name='创建时间')
    vuln_update_time = models.CharField(max_length=100, null=True, verbose_name='修改时间')
    isDelete = models.BooleanField(default=False)   # 是否可删除

    class Meta:
        verbose_name = "漏洞名称信息"
        verbose_name_plural = "漏洞名称信息"

    def __unicode__(self):
        return self.vuln_name


class BugManage(models.Model):
# class BugManage(mongoengine.Document):
    bug_name = models.CharField(max_length=200, null=True, verbose_name='Bug名称')
    bug_id = models.CharField(max_length=100, null=True, verbose_name='BugID')
    bug_digest = models.CharField(max_length=1000, null=True, verbose_name='Bug摘要')
    bug_detail = MDTextField()    # 注意为MDTextField() Bug详情
    bug_create_user = models.ForeignKey(UserNameManage, null=True, verbose_name='创建人', related_name='bug_create_user', on_delete=models.CASCADE)
    bug_update_user = models.ForeignKey(UserNameManage, null=True, verbose_name='修改人', related_name='bug_update_user', on_delete=models.CASCADE)
    bug_create_time = models.CharField(max_length=100, null=True, verbose_name='创建时间')
    bug_update_time = models.CharField(max_length=100, null=True, verbose_name='修改时间')
    isDelete = models.BooleanField(default=False)   # 是否可删除

    class Meta:
        verbose_name = "漏洞名称信息"
        verbose_name_plural = "漏洞名称信息"

    def __unicode__(self):
        return self.bug_name




class RuleRoamHistoryManage(models.Model):
    ruleroamhistory_id = models.CharField(max_length=200, null=True, verbose_name='规则流转历史事件id')
    ruleroamhistory_user = models.ForeignKey(UserNameManage, null=True, verbose_name='规则流转历史事件执行人', related_name='ruleroamhistory_user', on_delete=models.CASCADE)
    ruleroamhistory_pase = models.CharField(max_length=100, null=True, verbose_name='规则流转历史所在阶段')
    ruleroamhistory_time = models.CharField(max_length=100, null=True, verbose_name='规则流转历史发生时间')
    isDelete = models.BooleanField(default=False)   # 是否可删除

    class Meta:
        verbose_name = "流转历史信息"
        verbose_name_plural = "流转历史信息"

    def __unicode__(self):
        return self.ruleroamhistory_pase




class OldRuleRoamHistoryManage(models.Model):
    oldruleroamhistory_id = models.CharField(max_length=200, null=True, verbose_name='历史规则流转事件id')
    oldruleroamhistory_user = models.ForeignKey(UserNameManage, null=True, verbose_name='历史规则流转事件执行人', related_name='oldruleroamhistory_user', on_delete=models.CASCADE)
    oldruleroamhistory_phase = models.CharField(max_length=100, null=True, verbose_name='历史规则流转所在阶段')
    oldruleroamhistory_time = models.CharField(max_length=100, null=True, verbose_name='历史规则流转发生时间')
    isDelete = models.BooleanField(default=False)   # 是否可删除

    class Meta:
        verbose_name = "历史规则流转记录"
        verbose_name_plural = "历史规则流转记录"

    def __unicode__(self):
        return self.oldruleroamhistory_phase


class HistoryRuleManage(models.Model):
    historyrule_id = models.CharField(max_length=200, null=True, verbose_name='历史规则ID')
    historyrule_name = models.CharField(max_length=200, null=True, verbose_name='历史规则名')
    historyrule_version = models.CharField(max_length=100, null=True, verbose_name='历史规则版本')
    historyrule_detail = models.CharField(max_length=1000, null=True, verbose_name='历史规则详情')
    historyrule_CVE = models.CharField(max_length=200, null=True, verbose_name='历史规则CVE')
    historyrule_CNVD = models.CharField(max_length=200, null=True, verbose_name='历史规则CNVD')
    historyrule_CNNVD = models.CharField(max_length=200, null=True, verbose_name='历史规则CNNVD')
    historyrule_roam = models.ForeignKey(OldRuleRoamHistoryManage, null=True, verbose_name='历史规则关联流转事件', related_name='historyrule_roam', on_delete=models.CASCADE)
    isDelete = models.BooleanField(default=False)   # 是否可删除

    class Meta:
        verbose_name = "历史规则流转记录"
        verbose_name_plural = "历史规则流转记录"

    def __unicode__(self):
        return self.historyrule_name

class RuleManage(models.Model):
    rule_id = models.CharField(primary_key=True, max_length=100, unique=True, verbose_name='规则Id')
    rule_name = models.CharField(max_length=200, unique=True, verbose_name='规则名称')
    rule_version = models.CharField(default="rule_100001", max_length=100, unique=True, verbose_name='规则版本')
    rule_detail = models.CharField(max_length=1000, null=True, verbose_name='规则详情')
    rule_CVE = models.CharField(max_length=100, null=True, verbose_name='规则CVE')
    rule_CNVD = models.CharField(max_length=100, null=True, verbose_name='规则CNVD')
    rule_CNNVD = models.CharField(max_length=100, null=True, verbose_name='规则CNNVD')
    rule_runphase = models.CharField(max_length=100, null=True, verbose_name='规则所在阶段')
    rule_create_time = models.CharField(max_length=100, null=True, verbose_name='规则创建时间')
    rule_update_time = models.CharField(max_length=100, null=True, verbose_name='规则更新时间')
    rule_pilorun_time = models.CharField(max_length=100, null=True, verbose_name='规则试运行时间')
    rule_run_time = models.CharField(max_length=100, null=True, verbose_name='规则运行时间')
    rule_create_user = models.ForeignKey(UserNameManage, null=True, verbose_name='规则创建人', related_name='rule_create_user', on_delete=models.CASCADE)
    rule_update_user = models.ForeignKey(UserNameManage, null=True, verbose_name='规则更新人', related_name='rule_update_user', on_delete=models.CASCADE)
    rule_polorun_user = models.ForeignKey(UserNameManage, null=True, verbose_name='规则试运行人', related_name='rule_polorun_user', on_delete=models.CASCADE)
    rule_run_user = models.ForeignKey(UserNameManage, null=True, verbose_name='规则运行人', related_name='rule_run_user', on_delete=models.CASCADE)
    rule_bughistory = models.ForeignKey(OldRuleRoamHistoryManage, null=True, verbose_name='规则关联Bug提交事件', related_name='rule_bughistory', on_delete=models.CASCADE)
    rule_edithistory = models.ForeignKey(OldRuleRoamHistoryManage, null=True, verbose_name='规则关联编辑历史', related_name='rule_edithistory', on_delete=models.CASCADE)
    rule_roamhistory = models.ForeignKey(OldRuleRoamHistoryManage, null=True, verbose_name='规则关联流转历史', related_name='rule_roamhistory', on_delete=models.CASCADE)
    rule_vulnname = models.ForeignKey(OldRuleRoamHistoryManage, null=True, verbose_name='规则关联历史名称', related_name='rule_vulnname', on_delete=models.CASCADE)
    isDelete = models.BooleanField(default=False)   # 是否可删除

    class Meta:
        verbose_name = "规则记录"
        verbose_name_plural = "规则记录"

    def __unicode__(self):
        return self.rule_name













# class RuleManage(models.Model):
#     # type = models.CharField(max_length=10, choices=type_choices, default='0', verbose_name='规则类型')
#     # content = models.CharField(max_length=300, verbose_name='工单内容')
#     # type_choices = (('0', '初次安装'), ('1', '售后现场'), ('2', '远程支持'), ('3', '售前支持'))
#     status_choices = (('0', '规则已退回'), ('1', '新建-保存'), ('2', '提交-等待审批'), ('3', '已审批-等待测试'), ('4', '已测试-等待确认'), ('5', '规则已完成'))
#
#     rule_name = models.CharField(max_length=100, default="", null=True, verbose_name='规则名')
#     rule_id = models.CharField(max_length=100, default="", null=True, verbose_name='规则ID')
#     rule_desc = models.CharField(max_length=50, verbose_name='规则描述')
#     rule_note = models.CharField(max_length=10, verbose_name='规则备注')
#     rule_status = models.CharField(max_length=10, choices=status_choices, default='0', verbose_name='规则状态')
#
#     rule_create_time = models.DateTimeField(default='', verbose_name='创建时间')
#     rule_create_user = models.ForeignKey(UserNameManage, related_name='proposer', blank=True, null=True, on_delete=models.SET_NULL, verbose_name='创建人')
#     rule_save_time = models.DateTimeField(auto_now_add=True, verbose_name='编写时间')
#     rule_save_user = models.ForeignKey(UserNameManage, related_name='approver', blank=True, null=True, on_delete=models.SET_NULL, verbose_name='编写人')
#     rule_approval_time = models.DateTimeField(auto_now_add=True, verbose_name='审批时间')
#     rule_approval_user = models.ForeignKey(UserNameManage, related_name='approver', blank=True, null=True, on_delete=models.SET_NULL, verbose_name='审批人')
#     rule_test_time = models.DateTimeField(auto_now_add=True, verbose_name='测试时间')
#     rule_test_user = models.ForeignKey(UserNameManage, related_name='approver', blank=True, null=True, on_delete=models.SET_NULL, verbose_name='测试人')
#     rule_online_time = models.DateTimeField(auto_now_add=True, verbose_name='上线时间')
#     rule_online_user = models.ForeignKey(UserNameManage, related_name='receiver', blank=True, null=True, on_delete=models.SET_NULL, verbose_name='上线人')
#     isDelete = models.BooleanField(default=False)  # 是否可删除




