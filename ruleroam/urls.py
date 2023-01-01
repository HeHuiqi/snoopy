from django.urls import path, re_path, include
from django.views.generic import TemplateView

from ruleroam import views
import django
from .md_views import UploadView
if django.VERSION[0] > 1:
    from django.urls import path, re_path, include
else:
    from django.conf.urls import url


# 定义自己的 URL
urlpatterns = [
    path('vuln/', views.vulnPage, name='vuln'),
    path('vulnadd/', views.vuln_add_edit, name='vulnadd'),
    path('vulnlist/', views.vulnlist, name='vulnlist'),
    path('vulnsearch/', views.vulnsearch, name='vulnsearch'),
    path('vulndelete/', views.vulndelete, name='vulndelete'),
    path('vulnbatchdelete/', views.vulnbatchdelete, name='vulnbatchdelete'),

    path('bugs/', views.bugsPage, name='bugs'),
    path('bugcreate/', views.bugcreatePage, name='bugcreate'),
    path('bugdetail/', views.bugdetailPage, name='bugdetail'),
    re_path(r'^uploads/$', UploadView.as_view(), name='uploads'),
    path('bugadd/', views.bug_add_edit, name='bugadd'),
    path('buglist/', views.buglist, name='buglist'),
    path('bugsearch/', views.bugsearch, name='bugsearch'),
    path('bugdelete/', views.bugdelete, name='bugdelete'),
    path('bugbatchdelete/', views.bugbatchdelete, name='bugbatchdelete'),



    # path('roamhistory/', views.roamhistoryPage, name='roamhistory'),
    # path('historyrule/', views.historyrulePage, name='roamhistory'),
    # path('bugs/', views.bugsPage, name='roamhistory'),

    # path('user/', views.userPage, name='user'),
    # path('useradd/', views.user_add_edit, name='useradd'),
    # path('userlist/', views.userlist, name='userlist'),
    # path('usersearch/', views.usersearch, name='usersearch'),
    # path('userpassreset/', views.userpassreset, name='userpassreset'),
    # path('userdelete/', views.userdelete, name='userdelete'),
    # path('userbatchdelete/', views.userbatchdelete, name='userbatchdelete'),

]


