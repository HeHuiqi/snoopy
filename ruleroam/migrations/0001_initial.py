# Generated by Django 4.1.4 on 2023-01-10 06:21

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import mdeditor.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='OldRuleRoamHistoryManage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oldruleroamhistory_id', models.CharField(max_length=200, null=True, verbose_name='历史规则流转事件id')),
                ('oldruleroamhistory_phase', models.CharField(max_length=100, null=True, verbose_name='历史规则流转所在阶段')),
                ('oldruleroamhistory_time', models.CharField(max_length=100, null=True, verbose_name='历史规则流转发生时间')),
                ('isDelete', models.BooleanField(default=False)),
                ('oldruleroamhistory_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='oldruleroamhistory_user', to=settings.AUTH_USER_MODEL, verbose_name='历史规则流转事件执行人')),
            ],
            options={
                'verbose_name': '历史规则流转记录',
                'verbose_name_plural': '历史规则流转记录',
            },
        ),
        migrations.CreateModel(
            name='VulnManage',
            fields=[
                ('vuln_name', models.CharField(max_length=200, primary_key=True, serialize=False, unique=True, verbose_name='漏洞名称')),
                ('vuln_id', models.CharField(max_length=100, unique=True, verbose_name='漏洞ID')),
                ('vuln_description', models.CharField(max_length=1000, null=True, verbose_name='漏洞描述')),
                ('vuln_CVE', models.CharField(max_length=1000, null=True, verbose_name='漏洞CVE')),
                ('vuln_CNVD', models.CharField(max_length=1000, null=True, verbose_name='漏洞CNVD')),
                ('vuln_CNNVD', models.CharField(max_length=1000, null=True, verbose_name='漏洞CNNVD')),
                ('vuln_create_time', models.CharField(max_length=100, null=True, verbose_name='创建时间')),
                ('vuln_update_time', models.CharField(max_length=100, null=True, verbose_name='修改时间')),
                ('isDelete', models.BooleanField(default=False)),
                ('vuln_create_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='vuln_create_user', to=settings.AUTH_USER_MODEL, verbose_name='创建人')),
                ('vuln_update_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='vuln_update_user', to=settings.AUTH_USER_MODEL, verbose_name='修改人')),
            ],
            options={
                'verbose_name': '漏洞名称信息',
                'verbose_name_plural': '漏洞名称信息',
            },
        ),
        migrations.CreateModel(
            name='RuleRoamHistoryManage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ruleroamhistory_id', models.CharField(max_length=200, null=True, verbose_name='规则流转历史事件id')),
                ('ruleroamhistory_pase', models.CharField(max_length=100, null=True, verbose_name='规则流转历史所在阶段')),
                ('ruleroamhistory_time', models.CharField(max_length=100, null=True, verbose_name='规则流转历史发生时间')),
                ('isDelete', models.BooleanField(default=False)),
                ('ruleroamhistory_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ruleroamhistory_user', to=settings.AUTH_USER_MODEL, verbose_name='规则流转历史事件执行人')),
            ],
            options={
                'verbose_name': '流转历史信息',
                'verbose_name_plural': '流转历史信息',
            },
        ),
        migrations.CreateModel(
            name='RuleManage',
            fields=[
                ('rule_id', models.CharField(max_length=100, primary_key=True, serialize=False, unique=True, verbose_name='规则Id')),
                ('rule_name', models.CharField(max_length=200, unique=True, verbose_name='规则名称')),
                ('rule_version', models.CharField(default='rule_100001', max_length=100, unique=True, verbose_name='规则版本')),
                ('rule_detail', models.CharField(max_length=1000, null=True, verbose_name='规则详情')),
                ('rule_CVE', models.CharField(max_length=100, null=True, verbose_name='规则CVE')),
                ('rule_CNVD', models.CharField(max_length=100, null=True, verbose_name='规则CNVD')),
                ('rule_CNNVD', models.CharField(max_length=100, null=True, verbose_name='规则CNNVD')),
                ('rule_runphase', models.CharField(max_length=100, null=True, verbose_name='规则所在阶段')),
                ('rule_create_time', models.CharField(max_length=100, null=True, verbose_name='规则创建时间')),
                ('rule_update_time', models.CharField(max_length=100, null=True, verbose_name='规则更新时间')),
                ('rule_pilorun_time', models.CharField(max_length=100, null=True, verbose_name='规则试运行时间')),
                ('rule_run_time', models.CharField(max_length=100, null=True, verbose_name='规则运行时间')),
                ('isDelete', models.BooleanField(default=False)),
                ('rule_bughistory', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_bughistory', to='ruleroam.oldruleroamhistorymanage', verbose_name='规则关联Bug提交事件')),
                ('rule_create_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_create_user', to=settings.AUTH_USER_MODEL, verbose_name='规则创建人')),
                ('rule_edithistory', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_edithistory', to='ruleroam.oldruleroamhistorymanage', verbose_name='规则关联编辑历史')),
                ('rule_polorun_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_polorun_user', to=settings.AUTH_USER_MODEL, verbose_name='规则试运行人')),
                ('rule_roamhistory', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_roamhistory', to='ruleroam.oldruleroamhistorymanage', verbose_name='规则关联流转历史')),
                ('rule_run_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_run_user', to=settings.AUTH_USER_MODEL, verbose_name='规则运行人')),
                ('rule_update_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_update_user', to=settings.AUTH_USER_MODEL, verbose_name='规则更新人')),
                ('rule_vulnname', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='rule_vulnname', to='ruleroam.oldruleroamhistorymanage', verbose_name='规则关联历史名称')),
            ],
            options={
                'verbose_name': '规则记录',
                'verbose_name_plural': '规则记录',
            },
        ),
        migrations.CreateModel(
            name='HistoryRuleManage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('historyrule_id', models.CharField(max_length=200, null=True, verbose_name='历史规则ID')),
                ('historyrule_name', models.CharField(max_length=200, null=True, verbose_name='历史规则名')),
                ('historyrule_version', models.CharField(max_length=100, null=True, verbose_name='历史规则版本')),
                ('historyrule_detail', models.CharField(max_length=1000, null=True, verbose_name='历史规则详情')),
                ('historyrule_CVE', models.CharField(max_length=200, null=True, verbose_name='历史规则CVE')),
                ('historyrule_CNVD', models.CharField(max_length=200, null=True, verbose_name='历史规则CNVD')),
                ('historyrule_CNNVD', models.CharField(max_length=200, null=True, verbose_name='历史规则CNNVD')),
                ('isDelete', models.BooleanField(default=False)),
                ('historyrule_roam', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='historyrule_roam', to='ruleroam.oldruleroamhistorymanage', verbose_name='历史规则关联流转事件')),
            ],
            options={
                'verbose_name': '历史规则流转记录',
                'verbose_name_plural': '历史规则流转记录',
            },
        ),
        migrations.CreateModel(
            name='BugManage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bug_name', models.CharField(max_length=200, null=True, verbose_name='Bug名称')),
                ('bug_id', models.CharField(max_length=100, null=True, verbose_name='BugID')),
                ('bug_digest', models.CharField(max_length=1000, null=True, verbose_name='Bug摘要')),
                ('bug_detail', mdeditor.fields.MDTextField()),
                ('bug_create_time', models.CharField(max_length=100, null=True, verbose_name='创建时间')),
                ('bug_update_time', models.CharField(max_length=100, null=True, verbose_name='修改时间')),
                ('isDelete', models.BooleanField(default=False)),
                ('bug_create_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='bug_create_user', to=settings.AUTH_USER_MODEL, verbose_name='创建人')),
                ('bug_update_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='bug_update_user', to=settings.AUTH_USER_MODEL, verbose_name='修改人')),
            ],
            options={
                'verbose_name': '漏洞名称信息',
                'verbose_name_plural': '漏洞名称信息',
            },
        ),
    ]
