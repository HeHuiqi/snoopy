from django import forms
from .models import BugManage
from mdeditor.fields import MDTextFormField

# class CreateBugForm(forms.ModelForm):
#     # 代码中CreateBugForm类继承了Django的表单类forms.ModelForm，并在类中定义了内部类class Meta，指明了数据模型的来源，以及表单中应该包含数据模型的哪些字段。
#
#     class Meta:
#         model = BugManage
#         # fields = '__all__'
#         fields = ('bug_name', 'bug_detail')
#         # bug_detail = MDTextFormField()
#         # name = forms.CharField()
#         # content = MDTextFormField()
#         # task_domain = forms.CharField(label="", widget=forms.TextInput(attrs={'class':'form-control'}), max_length=50)

# class CreateBugForm(forms.Form):
#         # https://zhuanlan.zhihu.com/p/55158579
#         bug_detail = MDTextFormField(label="", widget=forms.TextInput(attrs={'class': 'form-control'}), max_length=65535)

