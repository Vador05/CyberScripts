"""
BMC/IPMI Exposure & Offline NTLM Hash Cracking Sentinel

Scans firewall or authentication logs for BMC/IPMI enumeration and
NTLM hash cracking precursor patterns with MITRE ATT&CK context.

Usage:
    python bmc_ipmi_ntlm_sentinel.py firewall.log --mode both --severity low
    python bmc_ipmi_ntlm_sentinel.py auth.log --mode ntlm --severity high
"""
import argparse, ipaddress, re, sys
from collections import defaultdict
from datetime import datetime

BMC_PORTS = {623, 664, 7443, 49152}
_SCAN = [ipaddress.ip_network(c) for c in ("198.20.69.0/24","198.20.70.0/24","198.20.71.0/24","66.240.192.0/19","71.6.135.0/24","71.6.165.0/24","80.82.77.0/24","93.120.27.0/24","162.142.125.0/24")]
_RFC  = [ipaddress.ip_network(c) for c in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]
SEV   = {"low":0,"medium":1,"high":2}
_FW   = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\S*\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\w+)',re.I)
_AU   = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\S*\s+([\d.]+)\s+(\S+)\s+(NTLM\w*)\s+(\w+)',re.I)

def _ts(s):
    for f in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S","%d/%b/%Y:%H:%M:%S"):
        try: return datetime.strptime(s.strip()[:19],f)
        except ValueError: pass

def _pub(ip):
    try: a=ipaddress.ip_address(ip); return not any(a in n for n in _RFC)
    except: return False

def _scan(ip):
    try: a=ipaddress.ip_address(ip); return any(a in n for n in _SCAN)
    except: return False

def parse_log_entries(path):
    rows,drop=[],0
    try: fh=open(path,encoding="utf-8",errors="replace")
    except OSError as e: sys.exit(f"ERROR: {e}")
    with fh:
        hdr=fh.readline(); auth=any(k in hdr.lower() for k in ("ntlm","auth_package","account_name"))
        for ln in fh:
            ln=ln.strip()
            if not ln or ln[0]=="#": continue
            m=(_AU if auth else _FW).search(ln)
            if not m: drop+=1; continue
            t=_ts(m.group(1))
            if t is None: drop+=1; continue
            if auth: rows.append({"ts":t,"src":m.group(2),"acct":m.group(3),"pkg":m.group(4).upper(),"st":m.group(5).upper(),"ty":"au"})
            else: rows.append({"ts":t,"src":m.group(2),"dst":m.group(3),"port":int(m.group(4)),"ty":"fw"})
    return rows,drop

def detect_signals(entries,mode):
    A=[];bmc=defaultdict(list);afail=defaultdict(list);asrc=defaultdict(lambda:defaultdict(list))
    for e in entries:
        if e["ty"]=="fw" and mode in("bmc","both") and e["port"] in BMC_PORTS and _pub(e["src"]):
            bmc[e["src"]].append(e)
        elif e["ty"]=="au" and mode in("ntlm","both") and "NTLM" in e["pkg"]:
            if "V1" in e["pkg"] or e["pkg"]=="NTLM":
                A.append(("NTLMHashLeak","T1110.002","medium",e["src"],e["acct"],"NTLMv1Downgrade",e["ts"].isoformat()))
            if e["st"]=="FAILURE":
                afail[e["acct"]+"|"+e["src"]].append(e["ts"]); asrc[e["acct"]][e["src"]].append(e["ts"])
    for k,ts in afail.items():
        ts.sort()
        for t in ts:
            if sum(1 for x in ts if 0<=(x-t).total_seconds()<=30)>=3:
                ac,src=k.split("|",1); A.append(("NTLMHashLeak","T1187","high",src,ac,"HashRelayBurst",t.isoformat())); break
    for ac,srcs in asrc.items():
        if len(srcs)>=2:
            all_t=sorted(t for v in srcs.values() for t in v)
            if all_t and (all_t[-1]-all_t[0]).total_seconds()<=60:
                A.append(("NTLMHashLeak","T1187","high",next(iter(srcs)),ac,"MultiSourceReplay",all_t[0].isoformat()))
    for src,hits in bmc.items():
        hits.sort(key=lambda x:x["ts"]); sc=_scan(src)
        for i,h in enumerate(hits):
            sev="high" if sc else "medium"
            A.append(("BMCEnumProbe","T1595.002" if sc else "T1046",sev,src,str(h["port"]),"KnownScannerIP" if sc else "BMCPortProbe",h["ts"].isoformat()))
            t0=h["ts"]
            seen_ports={hx["port"] for hx in hits if 0<=(hx["ts"]-t0).total_seconds()<=120}
            if len(seen_ports)>=2:
                A.append(("BMCEnumProbe","T1046","high",src,str(h["port"]),"MultiPortSweep",h["ts"].isoformat())); break
    return A

def report_findings(alerts,min_sev):
    seen={};em=[];peak="low";rank=SEV[min_sev]
    for sig,mid,sev,src,tgt,pat,ts in sorted(alerts,key=lambda x:x[6]):
        if SEV[sev]<rank: continue
        k=f"{sig}|{src}|{tgt}|{pat}"; win=120 if sig=="BMCEnumProbe" else 60
        pr=seen.get(k)
        if pr and 0<=(datetime.fromisoformat(ts)-datetime.fromisoformat(pr)).total_seconds()<=win: continue
        seen[k]=ts; print(f"[{ts}] {sig} | {mid} | SEV:{sev.upper()} | src={src} | target={tgt} | pattern={pat}")
        em.append((sig,mid,sev,src)); peak=sev if SEV[sev]>SEV[peak] else peak
    cl=defaultdict(lambda:{"n":0,"ips":set(),"t":set()})
    for s,m,v,ip in em: cl[s]["n"]+=1;cl[s]["ips"].add(ip);cl[s]["t"].add(m)
    print("\n--- Summary ---")
    for c,d in cl.items(): print(f"{c}: {d['n']} alerts | {len(d['ips'])} unique IPs | techniques: {','.join(sorted(d['t']))}")
    print(f"Peak severity: {peak.upper()}"); return peak=="high"

def main():
    ap=argparse.ArgumentParser(description="BMC/IPMI & NTLM hash cracking sentinel")
    ap.add_argument("log_file"); ap.add_argument("--mode",choices=["bmc","ntlm","both"],default="both")
    ap.add_argument("--severity",choices=["low","medium","high"],default="low"); args=ap.parse_args()
    rows,drop=parse_log_entries(args.log_file)
    print(f"Parsed {len(rows)} entries ({drop} dropped)\n")
    sys.exit(1 if report_findings(detect_signals(rows,args.mode),args.severity) else 0)

if __name__=="__main__": main()