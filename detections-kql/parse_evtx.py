import sys, re
from Evtx.Evtx import Evtx
from collections import Counter
path=sys.argv[1]
eids=Counter(); sample_by_eid={}
with Evtx(path) as log:
    for rec in log.records():
        x=rec.xml()
        m=re.search(r"<EventID[^>]*>(\d+)</EventID>", x)
        if not m: continue
        eid=m.group(1); eids[eid]+=1
        if eid not in sample_by_eid:
            sample_by_eid[eid]=x
print("EVENT ID COUNTS:", dict(eids.most_common(8)))
# show the fields of the most common eid
top=eids.most_common(1)[0][0]
print(f"\n--- sample EventID {top} fields ---")
x=sample_by_eid[top]
for m in re.finditer(r'<Data Name=[\'"]([^\'"]+)[\'"]>([^<]*)</Data>', x):
    v=m.group(2)[:70]
    if v.strip(): print(f"  {m.group(1)} = {v}")
