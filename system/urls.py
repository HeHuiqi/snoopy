from django.urls import path, re_path, include
from django.views.generic import TemplateView

from system import views
from django.views.generic import TemplateView


# 定义自己的 URL
urlpatterns = [
    path('', views.index, name='index'),    # index 页面是大框
    path('/', views.index, name='index'),    # index 页面是大框
    path('index/', views.index, name='index'),    # index 页面是大框
    path('login/', views.loginPage, name='login'),

    path('loginsubmit/', views.loginSubmit, name='loginsubmit'),
    path('logoutsubmit/', views.logoutSubmit, name='logoutsubmit'),

    path('department/', views.departmentPage, name='department'),
    path('departmentadd/', views.department_add_edit, name='departmentadd'),
    path('departmentlist/', views.departmentlist, name='departmentlist'),
    path('departmentsearch/', views.departmentsearch, name='departmentsearch'),
    path('departmentdelete/', views.departmentdelete, name='departmentdelete'),
    path('departmentbatchdelete/', views.departmentbatchdelete, name='departmentbatchdelete'),

    path('user-setting/', views.usersetting, name='user-setting'),
    path('user-password/', views.userpassword, name='user-password'),

    path('user/', views.userPage, name='user'),
    path('useradd/', views.user_add_edit, name='useradd'),
    path('userlist/', views.userlist, name='userlist'),
    path('usersearch/', views.usersearch, name='usersearch'),
    path('userpassreset/', views.userpassreset, name='userpassreset'),
    path('userpassedit/', views.userpassedit, name='userpassedit'),
    path('userdelete/', views.userdelete, name='userdelete'),
    path('userbatchdelete/', views.userbatchdelete, name='userbatchdelete'),

    # path('create_edit_usersubmit/', views.create_edit_usersubmit, name='create_edit_usersubmit'),
    # path('userlist/', views.userlist, name='userlist'),
    # path('editpasswordsubmit/', views.editpasswordsubmit, name='editpasswordsubmit'),
    # path('deleteusernamesubmit/', views.deleteusernamesubmit, name='deleteusernamesubmit'),
    # path('deleteBatchsubmit/', views.deleteBatchsubmit, name='deleteBatchsubmit'),
    path('loginhistory/', views.loginhistory, name='loginhistory'),
    path('loginhistorylist/', views.loginhistorylist, name='loginhistorylist'),
    path('loginhistorysearch/', views.loginhistorysearch, name='loginhistorysearch'),

    # path('welcome', TemplateView.as_view(template_name="system/welcome.html")),
    # path('welcome1/', TemplateView.as_view(template_name="system/welcome-1.html")),
    # path('welcome2/', TemplateView.as_view(template_name="system/welcome-2.html")),
    # path('welcome3/', TemplateView.as_view(template_name="system/welcome-3.html")),



    path('menu/', views.menu, name='menu'),
    path('welcome1/', views.welcome1, name='welcome1'),
    path('welcome2/', views.welcome2, name='welcome2'),
    path('welcome3/', views.welcome3, name='welcome3'),
    path('setting/', views.setting, name='setting'),
    path('table/', views.table, name='table'),

    path('quser/', views.quser, name='quser'),



    # path('form/', views.form, name='form'),
    # path('form-step/', views.formStep, name='form-step'),
    # path('page404/', views.page404, name='404'),
    # path('error/', views.page404, name='404'),
    # path('button/', views.button, name='button'),
    # path('layer/', views.layer, name='layer'),
    # path('button/', views.button, name='button'),
    # path('form/', views.form, name='form'),
    # path('serverError/', views.serverError, name='error'),
    # path('color-select/', views.colorSelect, name='color-select'),
    # path('table-select/', views.tableSelect, name='table-select'),
    # path('icon/', views.icon, name='icon'),
    # path('icon-picker/', views.iconPicker, name='iconPicker'),
    # path('upload/', views.upload, name='upload'),
    # path('editor/', views.editor, name='editor'),


]
