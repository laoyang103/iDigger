import pyshark
import subprocess as sp
from tshark import cached
from tshark.models import userflt
from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
def home(request):
    psummary_list = cached.get_summary_list()
    return render(request, 'list.html', locals())

def uflts(request):
    reslist = []
    flist = userflt.objects.values('name').distinct()
    for f in flist: reslist.append({'name': f['name'].encode("ascii")})
    response = HttpResponse(str(reslist))
    response['Access-Control-Allow-Origin'] = '*'
    return response

def uflts_add(request):
    pname=None
    if request.method == 'GET':   pname = request.GET.get('name')
    if request.method == 'POST':  pname = request.POST.get('name')
    userflt(name=pname).save()
    response = HttpResponse('Y')
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def plist(request):
    psummary_list = cached.get_summary_list()
    response = HttpResponse(str(psummary_list))
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def set_dfilter(request):
    if request.method == 'GET':  cached.set_dfilter(request.GET.get('dflt'))
    if request.method == 'POST': cached.set_dfilter(request.POST.get('dflt'))
    response = HttpResponse('Y')
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def decode(request):
    num = None
    if request.method == 'GET':  num = int(request.GET.get('num'))
    if request.method == 'POST': num = int(request.POST.get('num'))
    decode_dict, pkt = {}, cached.get_pkt_decode(num)
    for layer in pkt.layers: decode_dict['Layer ' + layer.layer_name.upper()] = layer._all_fields
    response = HttpResponse(str(decode_dict))
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def expertinfo(request):
    FILTER, FREQUENCY, GROUP, PROTOCOL, SUMMARY = range(5)
    expert = {'Errors': [], 'Warns': [], 'Notes': [], 'Chats': []}

    base_args = ['tshark', '-q', '-r', './capture_test.pcapng', '-z']
    p = sp.Popen(gen_statistics_args(base_args, 'expert', cached.dfilter), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

    currinfo = None
    line = p.stdout.readline()
    while line:
        line = p.stdout.readline()
        if '\n' == line or '====' in line or 'Frequency' in line: 
            continue

        fields = line.strip().split(None, 4)
        if 0 == len(fields): continue
        if not fields[0].isdigit() and expert.has_key(fields[0]): 
            currinfo = expert[fields[0]]
            continue

        record = {}
        record['Filter']            = fields[FILTER]
        record['Frequency']         = fields[FREQUENCY]
        record['Group']             = fields[GROUP]
        record['Protocol']          = fields[PROTOCOL]
        record['Summary']           = fields[SUMMARY]
        currinfo.append(record)
    p.stdout.close()
    p.stdin.close()
    response = HttpResponse(str(expert))
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
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
    response = HttpResponse(str(capinfo))
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def conv(request):
    outconv = []
    NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
    SRCINFO, CONVSTR, DSTINFO, PACKETS_DST2SRC, BYTES_DST2SRC, PACKETS_SRC2DST, BYTES_SRC2DST, PACKETS, BYTES, REL_START, DURATION = range(11)

    base_args = ['tshark', '-q', '-nn', '-r', './capture_test.pcapng', '-z']
    p = sp.Popen(gen_statistics_args(base_args, 'conv,tcp', cached.dfilter), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

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
        conv['Filter-TCP-Stream']   = '%s:%s,%s:%s' % \
                                       (srcsock[SOCK_ADDR], srcsock[SOCK_PORT], dstsock[SOCK_ADDR], dstsock[SOCK_PORT])
        outconv.append(conv)
    p.stdout.close()
    p.stdin.close()
    response = HttpResponse(str(outconv))
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def follow_tcp_stream(request):
    tcp_stream_flt=None
    if request.method == 'GET':   tcp_stream_flt = request.GET.get('tcp_stream_flt')
    if request.method == 'POST':  tcp_stream_flt = request.POST.get('tcp_stream_flt')

    base_args = ['tshark', '-q', '-r', './capture_test.pcapng', '-z']
    p = sp.Popen(gen_statistics_args(base_args, 'follow,tcp,ascii', tcp_stream_flt), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
    lines = txt2html(p.stdout.read())
    p.stdout.close()
    p.stdin.close()

    response = HttpResponse(lines)
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def filter_expression(request):
    lines = None
    with open('packet-filter.json') as f:
        lines = f.readlines()
    response = HttpResponse(lines)
    response['Access-Control-Allow-Origin'] = '*'
    return response

@csrf_exempt
def packet_len(request):
    out_json = []
    base_args = ['tshark', '-q', '-r', './capture_test.pcapng', '-z', 'plen,tree']
    field_names = ['Topic / Item', 'Count', 'Average', 'Min', 'val', 'Max', 'val', 'Rate', '(ms)', 'Percent', 'Burst', 'rate', 'Burst', 'start']
    p = sp.Popen(base_args, stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
    line = p.stdout.readline()
    while line:
        line = p.stdout.readline().replace('Packet Lengths', 'Packet-Lengths')
        fields = line.split()
        if len(fields) != 9: continue
        out_json.append(dict(zip(field_names, fields)))
    response = HttpResponse(str(out_json))
    response['Access-Control-Allow-Origin'] = '*'
    return response

def gen_statistics_args(base_args, statistics, flt):
    if None != flt and '' != flt: 
        base_args.append(statistics + ',' + flt)
    else:
        base_args.append(statistics)
    return base_args

def txt2html(txt):
    def escape(txt):
        txt = txt.replace('&','&#38;')
        txt = txt.replace(' ','&#160;')
        txt = txt.replace('<','&#60;')
        txt = txt.replace('>','&#62;')
        txt = txt.replace('"','&#34;')
        txt = txt.replace('\'','&#39;')
        return txt
    txt = escape(txt)
    lines = txt.split('\n')
    for i, line in enumerate(lines):
        lines[i] = '<p>' + line + '</p>'
    txt = ''.join(lines)
    return txt
