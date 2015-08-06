"""iDigger URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', 'tshark.views.home', name='home'),
    url(r'^conv', 'tshark.views.conv', name='conv'),
    url(r'^plist', 'tshark.views.plist', name='plist'),
    url(r'^decode', 'tshark.views.decode', name='decode'),
    url(r'^capinfo', 'tshark.views.capinfo', name='capinfo'),
    url(r'^expertinfo', 'tshark.views.expertinfo', name='expertinfo'),
    url(r'^set_dfilter', 'tshark.views.set_dfilter', name='set_dfilter'),
    url(r'^uflts$', 'tshark.views.uflts', name='uflts'),
    url(r'^uflts/add', 'tshark.views.uflts_add', name='uflts_add'),
    url(r'^follow_tcp_stream', 'tshark.views.follow_tcp_stream', name='follow_tcp_stream'),
    url(r'^filter_expression', 'tshark.views.filter_expression', name='filter_expression'),
    url(r'^packet_len', 'tshark.views.packet_len', name='packet_len'),
    url(r'^io_phs', 'tshark.views.io_phs', name='io_phs'),
    url(r'^ip_hosts', 'tshark.views.ip_hosts', name='ip_hosts'),
]
