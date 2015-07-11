import pyshark

dfilter = None
decodes_cap = None
summarys_cap = None
psummary_list = []

def get_summary_list(pdisplay_flt):
    global summarys_cap, psummary_list, dfilter
    if None == summarys_cap or pdisplay_flt != dfilter:
        summarys_cap = pyshark.FileCapture('./capture_test.pcapng', only_summaries=True, display_filter=pdisplay_flt, keep_packets=True)
        dfilter = pdisplay_flt
        psummary_list = []
    if 0 == len(psummary_list):
        try:
            while True:
                pdict = summarys_cap.next()._fields
                pdict['No'] = pdict['No.']
                psummary_list.append(pdict)
        except: pass
    return psummary_list

def get_pkt_decode(pkt_num):
    global decodes_cap
    if None == decodes_cap:
        decodes_cap = pyshark.FileCapture('./capture_test.pcapng', keep_packets=True)
    if 0 == len(decodes_cap._packets):
        try:
            while True: decodes_cap.next()
        except: pass
    return decodes_cap._packets[pkt_num - 1]
