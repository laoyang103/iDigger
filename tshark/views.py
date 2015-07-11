import pyshark
import subprocess as sp
from tshark import cached
from django.shortcuts import render

# Create your views here.
def home(request):
    display_filter = request.GET.get('dfilter')
    psummary_list = cached.get_summary_list(display_filter)
    if None != cached.dfilter: cached_filter = cached.dfilter
    return render(request, 'list.html', locals())

def decode(request):
    num = int(request.GET.get('num'))
    decode_dict, pkt = {}, cached.get_pkt_decode(num)
    if pkt.number:          decode_dict['number']           = pkt.number
    if pkt.eth:             decode_dict['link_layer']       = pkt.eth._all_fields
    if pkt.ip:              decode_dict['network_layer']    = pkt.ip._all_fields
    if pkt.transport_layer: decode_dict['transport_layer']  = pkt[pkt.transport_layer]._all_fields
    if pkt.highest_layer:   decode_dict['app_layer']        = pkt[pkt.highest_layer]._all_fields
    return render(request, 'detail.html', {'content': decode_dict})

def expertinfo(request):
    FREQUENCY, GROUP, PROTOCOL, SUMMARY = range(4)
    expert = {'Errors': [], 'Warns': [], 'Notes': [], 'Chats': []}
    p = sp.Popen(['tshark', '-q', '-r', './capture_test.pcapng', '-z', 'expert'], stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

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
    return render(request, 'detail.html', {'content': currinfo})

def summary(request):
    outsummary = {}
    NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
    p = sp.Popen(['capinfos', './capture_test.pcapng'], stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
    line = p.stdout.readline()
    while line:
        fields = line.split(':', 1)
        outsummary[fields[NAME]] = fields[VALUE].strip()
        line = p.stdout.readline()
    p.stdout.close()
    p.stdin.close()
    return render(request, 'detail.html', {'content': outsummary})

def conv(request):
    outconv = []
    NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
    p = sp.Popen(['tshark', '-q', '-nn', '-r', './capture_test.pcapng', '-z', 'conv,tcp'], stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
    SRCINFO, CONVSTR, DSTINFO, PACKETS_DST2SRC, BYTES_DST2SRC, PACKETS_SRC2DST, BYTES_SRC2DST, PACKETS, BYTES, REL_START, DURATION = range(11)
    
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
        outconv.append(conv)
    p.stdout.close()
    p.stdin.close()
    return render(request, 'detail.html', {'content': outconv})

