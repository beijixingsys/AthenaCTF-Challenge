import sys, traceback
sys.path.insert(0, r'D:\2026\ctf\bjxctfbc\Agentctf\timu\awdp-plus\\_tools')
import verify
try:
    r = verify.verify_one([s for s in verify.specs.SPECS if s['name']=='ez_Render'][0])
    print('RESULT', r)
except Exception:
    traceback.print_exc()
