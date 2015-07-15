import pyshark
import subprocess as sp
from tshark import cached
from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
def home(request):
    display_filter = request.GET.get('flt')
    psummary_list = cached.get_summary_list(display_filter)
    if None != cached.dfilter: cached_filter = cached.dfilter
    return render(request, 'list.html', locals())

def plist(request):
    display_filter = request.GET.get('flt')
    psummary_list = cached.get_summary_list(display_filter)
    if None != cached.dfilter: cached_filter = cached.dfilter
    return HttpResponse(str(psummary_list))

def decode(request):
    num = int(request.GET.get('num'))
    decode_dict, pkt = {}, cached.get_pkt_decode(num)
    if pkt.number:          decode_dict['number']           = pkt.number
    if pkt.eth:             decode_dict['link_layer']       = pkt.eth._all_fields
    if pkt.ip:              decode_dict['network_layer']    = pkt.ip._all_fields
    if pkt.transport_layer: decode_dict['transport_layer']  = pkt[pkt.transport_layer]._all_fields
    if pkt.highest_layer:   decode_dict['app_layer']        = pkt[pkt.highest_layer]._all_fields
    return HttpResponse(str(decode_dict))

def expertinfo(request):
    display_filter = request.GET.get('flt')
    FREQUENCY, GROUP, PROTOCOL, SUMMARY = range(4)
    expert = {'Errors': [], 'Warns': [], 'Notes': [], 'Chats': []}

    base_args = ['tshark', '-q', '-r', './capture_test.pcapng', '-z']
    p = sp.Popen(gen_statistics_args(base_args, 'expert', display_filter), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

    currinfo = None
    line = p.stdout.readline()
    while line:
        line = p.stdout.readline()
        if '\n' == line or '====' in line or 'Frequency' in line: 
            continue

        fields = line.strip().split(None, 3)
        if 0 == len(fields): continue
        if not fields[0].isdigit() and expert.has_key(fields[0]): 
            currinfo = expert[fields[0]]
            continue

        record = {}
        record['Frequency']         = fields[FREQUENCY]
        record['Group']             = fields[GROUP]
        record['Protocol']          = fields[PROTOCOL]
        record['Summary']           = fields[SUMMARY]
        currinfo.append(record)
    p.stdout.close()
    p.stdin.close()
    return HttpResponse(str(expert))

def capinfo(request):
    capinfo = {}
    NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
    p = sp.Popen(['capinfos', './capture_test.pcapng'], stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
    line = p.stdout.readline()
    while line:
        fields = line.split(':', 1)
        capinfo[fields[NAME]] = fields[VALUE].strip()
        line = p.stdout.readline()
    p.stdout.close()
    p.stdin.close()
    return HttpResponse(str(capinfo))

def conv(request):
    outconv = []
    display_filter = request.GET.get('flt')
    NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
    SRCINFO, CONVSTR, DSTINFO, PACKETS_DST2SRC, BYTES_DST2SRC, PACKETS_SRC2DST, BYTES_SRC2DST, PACKETS, BYTES, REL_START, DURATION = range(11)

    base_args = ['tshark', '-q', '-nn', '-r', './capture_test.pcapng', '-z']
    p = sp.Popen(gen_statistics_args(base_args, 'conv,tcp', display_filter), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

    line = p.stdout.readline()
    while line:
        line = p.stdout.readline()
        if '<->' not in line: continue
        fields = line.split()
        srcsock = fields[SRCINFO].split(':')
        dstsock = fields[DSTINFO].split(':')
        conv = {}
        conv['Address SRC']         = srcsock[SOCK_ADDR]
        conv['Port SRC']            = srcsock[SOCK_PORT]
        conv['Address DST']         = dstsock[SOCK_ADDR]
        conv['Port DST']            = dstsock[SOCK_PORT]
        conv['Total Packets']       = fields[PACKETS]
        conv['Total Bytes']         = fields[BYTES]
        conv['Packets SRC -> DST']  = fields[PACKETS_SRC2DST]
        conv['Bytes SRC -> DST']    = fields[BYTES_SRC2DST]
        conv['Packets DST -> SRC']  = fields[PACKETS_DST2SRC]
        conv['Bytes DST -> SRC']    = fields[BYTES_DST2SRC]
        conv['Rel Start']           = fields[REL_START]
        conv['Duration']            = fields[DURATION]
        conv['Filter-IP']           = '(ip.addr eq %s and ip.addr eq %s)' % (srcsock[SOCK_ADDR], dstsock[SOCK_ADDR])
        conv['Filter-TCP']          = '(ip.addr eq %s and ip.addr eq %s) and (tcp.port eq %s and tcp.port eq %s)' % \
                                       (srcsock[SOCK_ADDR], dstsock[SOCK_ADDR], srcsock[SOCK_PORT], dstsock[SOCK_PORT])
        outconv.append(conv)
    p.stdout.close()
    p.stdin.close()
    return HttpResponse(str(outconv))

def gen_statistics_args(base_args, statistics, flt):
    if None != flt and '' != flt: 
        base_args.append(statistics + ',' + flt)
    else:
        base_args.append(statistics)
    return base_args

