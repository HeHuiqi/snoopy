#! /usr/bin/env python
# -*- coding:utf-8 -*-

from django.shortcuts import render



def page404(request):
    return render(request, 'system/404.html')


def notFount(request,  exception=404):
    return render(request, 'system/404.html')

def serverError(request):
    return render(request, 'system/404.html')


def forbidden(request, exception=403):
    return render(request, 'system/404.html')

