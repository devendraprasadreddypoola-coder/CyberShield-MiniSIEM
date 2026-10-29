from datetime import datetime
from database import add_alert
WINDOW_SECONDS=60
FAILED_ATTEMPT_THRESHOLD=5

def parse_time(v):
    for fmt in ("%Y-%m-%d %H:%M:%S","%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M"):
        try: return datetime.strptime(v,fmt)
        except ValueError: pass
    return None

def detect_brute_force(events):
    by_ip={}
    for e in events:
        if e["result"]!="failed": continue
        t=parse_time(e["timestamp"])
        if t: by_ip.setdefault(e["ip_address"],[]).append(t)
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            j=i
            while j<len(times) and (times[j]-times[i]).total_seconds()<=WINDOW_SECONDS: j+=1
            if j-i>=FAILED_ATTEMPT_THRESHOLD:
                start=times[i].strftime("%Y-%m-%d %H:%M:%S")
                end=times[j-1].strftime("%Y-%m-%d %H:%M:%S")
                key=f"bruteforce:{ip}:{start}:{end}:{j-i}"
                add_alert(ip,"HIGH","Possible brute-force login activity",
                          f"{j-i} failed logins from this IP within 60 seconds ({start} to {end}). This is a warning indicator, not proof of an attack.",key)
                break
