# -*- coding: utf-8 -*-
"""PLACEMENT LABELER — web tool local. Nhập list website HOẶC chọn Excel -> bảng kết quả + tải file (thêm cột 'loại website')."""
import http.server, socketserver, threading, json, cgi, os, re, time, datetime, urllib.request, uuid, webbrowser
import concurrent.futures as cf
import pandas as pd

HERE=os.path.dirname(os.path.abspath(__file__))
OUTDIR=os.path.join(HERE,'labeled_output'); os.makedirs(OUTDIR,exist_ok=True)
CACHE_F=os.path.join(HERE,'domain_cache.json')
CACHE=json.load(open(CACHE_F,encoding='utf-8')) if os.path.exists(CACHE_F) else {}

RULES={
 'lau':(r'crack|nulled|repack|keygen|torrent|pirate|warez|\bmod(ed|apk)?\b|\bapk\b|free-?download|xemphim|phim-?lau|phimmoi|full-?movie|watch-?free|smoke-?patch|spfl|pes-?patch','Nội dung lậu'),
 'phishing':(r'phish|verify-?account|account-?(suspend|verif)|secure-?login|signin-?verify|wallet-?connect|confirm-?identity','Phishing/Scam'),
 'tin_dung':(r'\bloan(s)?\b|\bcredit\b|\binsurance\b|mortgage|payday|\bvay\b|\bfinance\b|thefinance|debt-?relief|refinanc','Tài chính (vay/tín dụng/bảo hiểm)'),
 'earn':(r'\bearn(ing)?\b|\breward(s)?\b|free-?gift|giveaway|\bsurvey\b|cashback|\bprize\b|robux|gift-?card|make-?money|get-?paid|metroopinion|apexfocus','Kiếm tiền/thưởng/khảo sát'),
 'download':(r'\bdownloader\b|download-?free|stream-?free|watch-?online|\bmp3\b|video-?converter|savefrom|y2mate|\bytdl\b','Download/Streaming miễn phí'),
 'gambling':(r'casino|\bbet(ting)?\b|\bpoker\b|\bslot(s)?\b|gambling|\bjudi\b|1xbet|baccarat|roulette','Cờ bạc/Betting'),
 'adult':(r'\bporn|\bxxx\b|\bsex\b|escort|camgirl|onlyfans','Người lớn'),
 'crypto':(r'airdrop|free-?crypto|earn-?token|claim-?token|crypto-?giveaway','Crypto scam'),
 'game':(r'\bgame(s|r)?\b|\barcade\b|minigame|h5game|playgame|game-?online','Game/giải trí'),
 'bds':(r'real-?estate|propert(y|ies)|bat-?dong-?san|nha-?dat|\brealty\b|homes?-?for-?sale|apartment(s)?-?for','Bất động sản'),
}
SHORTENERS={'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','cutt.ly','rebrand.ly','shorturl.at'}
EDU_GOV=re.compile(r'\.(edu|gov|ac)(\.[a-z]{2})?$')
RULES_2B={
 'job':(r'\bjob(s)?\b|career|hiring|employ|recruit|vacanc|naukri|rojgar|\bvisa\b|immigrat|sponsorship','Việc làm/Visa'),
 'edu':(r'\bstudent(s)?\b|\bexam\b|school|bimbel|olympiad|scholarship|mendidik|dikdas|du-?hoc','Giáo dục/Du học'),
 'consumer':(r'\bsport|football|\bmusic\b|\blyric|recipe|horoscope|birthday|personality-?test|\breview(s)?\b','Nội dung tiêu dùng/Review'),
}
DEFAULT_ON={'phishing','crypto','lau','gambling','adult',
            'age','earn','download','thin','adheavy','game','shield','edu_gov'}
def rdap_age(dom):
    try:
        with urllib.request.urlopen('https://rdap.org/domain/%s'%dom,timeout=8) as r: j=json.load(r)
        for e in j.get('events',[]):
            if e.get('eventAction')=='registration':
                return (datetime.date.today()-datetime.date.fromisoformat(e['eventDate'][:10])).days
    except: return None
    return None
def urlscan(dom):
    try:
        with urllib.request.urlopen('https://urlscan.io/api/v1/search/?q=domain:%s&size=5'%dom,timeout=12) as r: j=json.load(r)
        res=j.get('results',[])
        title=' | '.join({x.get('page',{}).get('title','') for x in res if x.get('page',{}).get('title')})
        urls=' '.join(x.get('page',{}).get('url','') for x in res)
        return title,urls,any('malicious' in str(x.get('verdicts','')).lower() for x in res)
    except: return '','',False
PV=1  # phien ban du lieu trang; tang so nay de ep quet lai noi dung
UA={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'}
ADS_NET=re.compile(r'googlesyndication|doubleclick|adsbygoogle|taboola|outbrain|\bmgid\b|propellerads|adnxs|criteo|media\.net|revcontent|adsterra|popads',re.I)
TAG_RE=re.compile(r'<(script|style|noscript)[^>]*>.*?</\1>',re.S|re.I)

def fetch_page(dom):
    """Tai trang that -> title, meta description, so tu, so mang quang cao."""
    for scheme in ('https://','http://'):
        try:
            req=urllib.request.Request(scheme+dom,headers=UA)
            html=urllib.request.urlopen(req,timeout=8).read(200000).decode('utf-8','ignore')
        except Exception: continue
        t=re.search(r'<title[^>]*>(.*?)</title>',html,re.S|re.I)
        d=re.search(r'name=["\']description["\'][^>]*content=["\'](.*?)["\']',html,re.S|re.I)
        body=TAG_RE.sub(' ',html)
        text=re.sub(r'<[^>]+>',' ',body)
        text=re.sub(r'&[a-z#0-9]+;',' ',text)
        words=len(re.findall(r'[A-Za-zÀ-ỹ0-9]{2,}',text))
        return {'pv':PV,'ok':True,
                'ptitle':(t.group(1).strip()[:300] if t else ''),
                'pdesc':(d.group(1).strip()[:300] if d else ''),
                'ptext':' '.join(text.split())[:4000],
                'words':words,'ads':len(set(ADS_NET.findall(html)))}
    return {'pv':PV,'ok':False,'ptitle':'','pdesc':'','ptext':'','words':0,'ads':0}

def enrich(dom):
    e=CACHE.get(dom)
    if e is None:
        t,u,m=urlscan(dom); a=rdap_age(dom)
        e={'title':t,'urls':u,'malicious':m,'age_days':a}; time.sleep(0.2)
    if e.get('pv')!=PV: e.update(fetch_page(dom))
    CACHE[dom]=e; return e
def classify(dom, on=None):
    on=on if on is not None else set(DEFAULT_ON)
    dom=dom.strip().lower().replace('http://','').replace('https://','').split('/')[0]
    if not dom: return dom,'—','',''
    e=enrich(dom); age=e.get('age_days')
    if dom in SHORTENERS: return dom,'Chặn — URL shortener','BLOCK','redirect, không phải nội dung'
    # Dò rule chỉ trên title+description (tín hiệu cao). Body text quá nhiễu —
    # dò cả body thì scribd.com dính rule Game vì chữ "game" lọt đâu đó trong trang.
    page=(e.get('ptitle','')+' '+e.get('pdesc','')).lower()
    body=(page+' '+e.get('ptext','')).lower()
    got_page=bool(e.get('ok'))
    text=(dom+' '+e.get('urls','')+' '+e.get('title','')+' '+page).lower()
    reasons=[]; verdict='REVIEW'; cat=''
    if 'malware' in on and e.get('malicious'): reasons.append('Malware/threat'); verdict='BLOCK'; cat='Nguy hiểm'
    allrules={**RULES,**RULES_2B}
    for k,(pat,lab) in allrules.items():
        if k not in on: continue
        if not re.search(pat,text): continue
        ind=bool(re.search(pat,dom))
        # Phan bac dung ca body: chi ha an khi tu khoa vang mat hoan toan khoi trang
        inpage=bool(re.search(pat,body))
        # Ten mien khop nhung noi dung that KHONG khop -> nghi chan oan, ha xuong REVIEW
        if ind and got_page and not inpage:
            reasons.append(lab+'[tên miền khớp, nội dung không khớp→review]')
            verdict='BLOCK' if verdict=='BLOCK' else 'REVIEW'; cat=cat or lab; continue
        sh=('shield' in on) and (not ind) and age is not None and age>1095
        if ind: reasons.append(lab+'[tên miền]'); verdict='BLOCK'; cat=cat or lab
        elif sh: reasons.append(lab+'[nội dung,domain già→review]'); verdict='BLOCK' if verdict=='BLOCK' else 'REVIEW'; cat=cat or lab
        else: reasons.append(lab+'[nội dung]'); verdict='BLOCK'; cat=cat or lab
    if 'age' in on and age is not None and age<180: reasons.append('Domain mới %d ngày'%age); verdict='BLOCK'; cat=cat or 'Domain mới'
    if 'thin' in on and got_page and e.get('words',0)<300:
        reasons.append('Nội dung mỏng (%d từ)'%e.get('words',0)); cat=cat or 'Nội dung mỏng'
    if 'adheavy' in on and got_page and e.get('ads',0)>=4:
        reasons.append('Nhồi quảng cáo (%d mạng ads)'%e.get('ads',0)); cat=cat or 'Nhồi quảng cáo'
    if 'edu_gov' in on and verdict!='BLOCK' and EDU_GOV.search(dom):
        reasons.append('TLD uy tín (.gov/.edu) → whitelist'); verdict='KEEP'
    if not reasons:
        reasons.append('Chưa có tín hiệu xấu — cần verify' if got_page else 'Không tải được trang — chưa có dữ liệu để kết luận')
    loai = ('Chặn — '+cat) if verdict=='BLOCK' else ('Giữ (uy tín tạm)' if verdict=='KEEP' else 'Cần kiểm tra')
    return dom, loai, verdict, ' ; '.join(reasons)

JOBS={}
def run_job(jid, domains=None, excel=None, orig='ket_qua.xlsx', on=None):
    J=JOBS[jid]
    try:
        is_csv=False
        if excel:
            is_csv=str(orig).lower().endswith('.csv') or str(excel).lower().endswith('.csv')
            reader=(lambda **k: pd.read_csv(excel,encoding='utf-8-sig',**k)) if is_csv else (lambda **k: pd.read_excel(excel,**k))
            raw=reader(header=None,nrows=8); hdr,col=0,None
            for i in range(len(raw)):
                vals=[str(v).strip().lower() for v in raw.iloc[i].tolist()]
                for c in ('placement','domain','placement url','url','website'):
                    if c in vals: hdr,col=i,raw.iloc[i].tolist()[vals.index(c)]; break
                if col: break
            if col is None: hdr,col=0,raw.iloc[0,0]
            df=reader(header=hdr); df=df[~df[col].astype(str).str.startswith('Total')].copy()
            keycol=col
        else:
            df=pd.DataFrame({'website':domains}); keycol='website'
        uniq=sorted({str(x).strip().lower() for x in df[keycol] if str(x).strip() and str(x)!='nan'})
        J['total']=len(uniq); cache_res={}; rows=[]
        # Nap du lieu (urlscan + RDAP + tai trang) song song — day la phan cham nhat
        norm=lambda d: d.strip().lower().replace('http://','').replace('https://','').split('/')[0]
        todo=sorted({norm(d) for d in uniq if norm(d)})
        with cf.ThreadPoolExecutor(8) as ex:
            for i,_ in enumerate(ex.map(enrich,todo),1): J['done']=i
        for d in uniq:
            dom,loai,verdict,reason=classify(d,on); cache_res[d]=(loai,verdict,reason)
            rows.append({'website':dom,'loai':loai,'verdict':verdict,'reason':reason})
        json.dump(CACHE,open(CACHE_F,'w',encoding='utf-8'),ensure_ascii=False,indent=1)
        m=df[keycol].astype(str).str.strip().str.lower()
        df['loại website']=m.map(lambda d:cache_res.get(d,('—','',''))[0])
        stem=os.path.splitext(os.path.basename(orig))[0]
        if is_csv:
            base=stem+'_labeled.csv'; df.to_csv(os.path.join(OUTDIR,base),index=False,encoding='utf-8-sig')
        else:
            base=stem+'_labeled.xlsx'; df.to_excel(os.path.join(OUTDIR,base),index=False)
        from collections import Counter; c=Counter(r['verdict'] for r in rows)
        J.update(status='done',counts=dict(c),outfile=base,rows=rows)
    except Exception as ex:
        J.update(status='error',error=str(ex))
    finally:
        if excel:
            try: os.remove(excel)
            except: pass

PAGE=r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Placement Labeler</title><style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#eef1f7;color:#222;padding:24px}
.card{background:#fff;max-width:760px;margin:0 auto;border-radius:16px;box-shadow:0 8px 34px rgba(31,56,100,.13);overflow:hidden}
.hd{background:#1f3864;color:#fff;padding:18px 24px}.hd h1{margin:0;font-size:19px}.hd p{margin:4px 0 0;font-size:12.5px;opacity:.8}
.bd{padding:22px 24px}
.tabs{display:flex;gap:6px;margin-bottom:14px}.tabs button{flex:1;border:1px solid #d3dae7;background:#f6f8fc;border-radius:9px;padding:9px;font-size:14px;cursor:pointer}.tabs button.on{background:#1f3864;color:#fff;border-color:#1f3864}
textarea{width:100%;height:150px;border:1px solid #cfd7e6;border-radius:10px;padding:11px;font:13px Menlo,monospace;resize:vertical}
.drop{border:2px dashed #b9c4d8;border-radius:12px;padding:30px;text-align:center;color:#556;cursor:pointer}.drop.over{border-color:#2e75b6;background:#f2f8ff}.drop b{color:#1f3864}
input[type=file]{display:none}
.btn{background:#2e75b6;color:#fff;border:0;border-radius:10px;padding:11px 22px;font-size:15px;font-weight:600;cursor:pointer;margin-top:12px}.btn:disabled{opacity:.5}
.bar{height:10px;background:#e6eaf2;border-radius:6px;overflow:hidden;margin:16px 0 5px;display:none}.bar i{display:block;height:100%;width:0;background:#2e75b6;transition:.3s}
.pct{font-size:12px;color:#667;text-align:center}
.chips{display:flex;gap:8px;justify-content:center;margin:14px 0}.chip{padding:6px 13px;border-radius:11px;font-weight:700;font-size:13px}.chip.BLOCK{background:#fde8e6;color:#c0392b}.chip.REVIEW{background:#fdf3e0;color:#b7791f}.chip.KEEP{background:#e7f4ec;color:#2e9e5b}
.dl{background:#2e9e5b;color:#fff;text-decoration:none;display:inline-block;padding:10px 20px;border-radius:9px;font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:14px;font-size:13px}th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #eef1f6}th{background:#f4f6fb;color:#667;font-size:11px;text-transform:uppercase}
.v{font-weight:700;font-size:11px;padding:2px 8px;border-radius:10px;color:#fff}.v.BLOCK{background:#c0392b}.v.REVIEW{background:#e8a33d}.v.KEEP{background:#2e9e5b}
.wrapT{max-height:340px;overflow:auto;border:1px solid #eef1f6;border-radius:10px;margin-top:10px;display:none}
.res{display:none;text-align:center;margin-top:6px}
.note{font-size:11px;color:#8a93a6;margin-top:12px;line-height:1.5}
.checks{margin:12px 0;border:1px solid #e3e8f2;border-radius:10px;padding:8px 12px;background:#fafbfe}
.checks summary{cursor:pointer;font-weight:600;font-size:13px;color:#1f3864}
.ckgrp{margin:10px 0 2px;padding-left:10px;border-left:3px solid #d3dae7}
.ckgrp>span{display:block;font-size:11px;color:#5a6478;font-weight:700;letter-spacing:.3px;margin-bottom:4px}
.ckgrp label{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;margin:2px 12px 2px 0;cursor:pointer}
.ckgrp input{accent-color:#1f3864}
.t1{border-left-color:#c0392b}.t2{border-left-color:#e8a33d}.t3{border-left-color:#7b8ba8}
.t4{border-left-color:#2e75b6}.t5{border-left-color:#2e9e5b}.t6{border-left-color:#c9cedb}
.ckgrp label.off{color:#aab2c2;cursor:not-allowed;text-decoration:line-through;text-decoration-color:#d6dbe6}
.ckgrp label.off input{cursor:not-allowed}
.t6>span{color:#aab2c2}
.gap{margin-top:12px;padding:8px 10px;background:#f4f6fb;border-radius:8px;font-size:11px;color:#8a93a6;line-height:1.6}
.method summary{color:#5a6478}
.mgrp{margin:10px 0;padding:9px 11px;background:#fafbfe;border:1px solid #eef1f6;border-radius:8px}
.mgrp b{font-size:12.5px;color:#1f3864}.mgrp p{margin:5px 0 0;font-size:12px;color:#5a6478;line-height:1.55}
.mgrp code{background:#eef1f7;padding:1px 4px;border-radius:3px;font-size:11px}
.src{font:11px Menlo,monospace;color:#8a93a6;margin-left:6px}
.lim{color:#a05a2c !important;background:#fdf6ec;padding:6px 8px;border-radius:6px}
.mgrp.bot{background:#f4f6fb;border-color:#dfe5f0}
</style></head><body>
<div class="card"><div class="hd"><h1>Placement Labeler</h1><p>Nhập list website hoặc chọn Excel → gắn nhãn loại website → tải file</p></div>
<div class="bd">
 <div class="tabs"><button id="t1" class="on">Nhập website (mỗi dòng 1 cái)</button><button id="t2">Chọn file Excel / CSV</button></div>
 <div id="m1"><textarea id="ta" placeholder="career209.com&#10;pessmokepatch.com&#10;cnn.com"></textarea></div>
 <div id="m2" style="display:none"><label class="drop" id="drop"><input type="file" id="file" accept=".xlsx,.xls,.csv"><div id="dtext"><b>Kéo Excel hoặc CSV vào đây</b><br>hoặc bấm chọn</div></label></div>
 <details class="checks" open><summary>⚙︎ Tầng kiểm tra — chọn loại cần lọc</summary>
  <div class="ckgrp t1"><span>🚨 Cấp 1 · Loại ngay (Brand Safety)</span>
   <label class="off" title="Nguồn urlscan không trả về dữ liệu verdict — phép kiểm tra này không bao giờ chạy. Cần đổi sang Google Safe Browsing."><input type="checkbox" disabled>Malware / Threat</label>
   <label><input type="checkbox" data-k="phishing" checked>Phishing / Scam</label>
   <label><input type="checkbox" data-k="crypto" checked>Crypto Scam</label>
   <label><input type="checkbox" data-k="lau" checked>Nội dung lậu (Piracy)</label>
   <label><input type="checkbox" data-k="gambling" checked>Cờ bạc / Betting</label>
   <label><input type="checkbox" data-k="adult" checked>Người lớn (Adult)</label></div>
  <div class="ckgrp t2"><span>⚠️ Cấp 2 · Chất lượng thấp</span>
   <label><input type="checkbox" data-k="age" checked>Domain mới (&lt; 6 tháng)</label>
   <label><input type="checkbox" data-k="earn" checked>Kiếm tiền / Thưởng / Khảo sát</label>
   <label><input type="checkbox" data-k="download" checked>Download / Streaming miễn phí</label>
   <label><input type="checkbox" data-k="thin" checked>Nội dung mỏng (&lt; 300 từ)</label>
   <label><input type="checkbox" data-k="adheavy" checked>Nhồi quảng cáo (≥ 4 mạng ads)</label>
   <label class="off" title="Cần đọc hiểu văn phong — chỉ làm được bằng LLM"><input type="checkbox" disabled>AI Content Farm</label>
   <label class="off" title="Cần đọc hiểu tiêu đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Clickbait</label>
   <label class="off" title="Cần theo dõi luồng traffic mua–bán, tool không có dữ liệu này"><input type="checkbox" disabled>Traffic Arbitrage</label></div>
  <div class="ckgrp t3"><span>🎮 Cấp 3 · Thường không phù hợp ads</span>
   <label><input type="checkbox" data-k="game" checked>Game / Giải trí</label>
   <label class="off" title="Cần nhận diện cấu trúc trang, chưa làm"><input type="checkbox" disabled>Forum / UGC</label>
   <label class="off" title="Cần đọc hiểu nội dung — chỉ làm được bằng LLM"><input type="checkbox" disabled>Meme / Viral</label>
   <label class="off" title="Cần nhận diện cấu trúc trang, chưa làm"><input type="checkbox" disabled>Tin tổng hợp (Aggregator)</label></div>
  <div class="ckgrp t4"><span>🎯 Cấp 4 · Tùy khách hàng — chỉ bật khi khách yêu cầu</span>
   <label><input type="checkbox" data-k="job">Việc làm / Visa</label>
   <label><input type="checkbox" data-k="edu">Giáo dục / Du học</label>
   <label><input type="checkbox" data-k="tin_dung">Tài chính (vay, tín dụng, bảo hiểm)</label>
   <label><input type="checkbox" data-k="bds">Bất động sản</label>
   <label><input type="checkbox" data-k="consumer">Nội dung tiêu dùng / Review</label>
   <label class="off" title="Từ khoá crypto hợp pháp và crypto scam trùng nhau — regex không tách được"><input type="checkbox" disabled>Crypto hợp pháp</label>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Tin tức</label></div>
  <div class="ckgrp t6"><span>🔥 Cấp 5 · Nhạy cảm thương hiệu — chưa làm được ô nào</span>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Chính trị</label>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Tôn giáo</label>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Bạo lực</label>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Tai nạn / Thảm họa</label>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Nội dung gây tranh cãi</label>
   <label class="off" title="Cần phân loại chủ đề — chỉ làm được bằng LLM"><input type="checkbox" disabled>Sức khỏe / Bệnh lý</label></div>
  <div class="ckgrp t5"><span>🛡️ Giảm false positive</span>
   <label><input type="checkbox" data-k="shield" checked>Domain lâu năm (&gt; 3 năm)</label>
   <label><input type="checkbox" data-k="edu_gov" checked>TLD uy tín (.gov, .edu)</label>
   <label class="off" title="Cần đọc trang About / dữ liệu schema.org, chưa làm"><input type="checkbox" disabled>Có thông tin doanh nghiệp rõ ràng</label>
   <label class="off" title="Cần dữ liệu lịch sử index, tool không có nguồn"><input type="checkbox" disabled>Được index ổn định nhiều năm</label>
   <label class="off" title="Cần danh sách thương hiệu đã xác thực, chưa có"><input type="checkbox" disabled>Thương hiệu đã xác thực</label></div>
  <div class="gap">Ô <b>màu xám là chưa làm được</b> — không phải đang tắt. Rê chuột vào từng ô để xem
   vì sao. Phần lớn cần đọc hiểu nội dung trang, sẽ mở được khi gắn thêm tầng phân loại bằng LLM.</div>
 </details>
 <details class="checks method"><summary>🔍 Tool kiểm tra bằng cách nào — và tin được đến đâu</summary>
  <div class="mgrp bot"><b>Tóm tắt trong 30 giây</b>
   <p>Tool <b>mở từng trang web ra xem</b>, đọc tiêu đề và nội dung, rồi dò từ khoá xấu.
   Nó cũng tra <b>tuổi tên miền</b> để biết trang mới lập hay lâu đời.</p>
   <p>Kết quả có 3 mức: <b>BLOCK</b> = có bằng chứng xấu, nên chặn ·
   <b>REVIEW</b> = chưa đủ bằng chứng, bạn phải tự xem ·
   <b>KEEP</b> = chắc chắn an toàn, hiện chỉ áp dụng cho tên miền .gov và .edu.</p>
   <p><b>Phần lớn sẽ ra REVIEW.</b> Đó là cố ý. Tool chỉ giúp bạn khỏi phải xem hết vài trăm
   trang, chứ không tự quyết thay bạn. Nếu nó nói KEEP cho những trang nó không chắc,
   bạn sẽ bỏ qua nhầm trang rác.</p></div>
  <div class="mgrp"><b>1 · Mở trang web ra xem</b> <span class="src">nguồn chính</span>
   <p>Tool tự vào trang chủ của từng website, đọc <b>tiêu đề</b>, <b>mô tả</b> và <b>nội dung chữ</b>.
   Từ đó nó đếm được trang có bao nhiêu chữ, và nhúng bao nhiêu mạng quảng cáo.
   Đây là thứ nuôi hai ô "Nội dung mỏng" và "Nhồi quảng cáo".</p>
   <p>Thử nghiệm: mở được <b>21 trong 25</b> website.</p>
   <p class="lim">⚠ Chỉ xem <b>trang chủ</b>, không đọc từng bài viết bên trong.
   Trang nào chặn không cho vào, hoặc đã ngừng hoạt động, thì kết quả ghi rõ
   <b>"Không tải được trang"</b> — nghĩa là thiếu thông tin, <b>không phải trang đó sạch</b>.</p></div>
  <div class="mgrp"><b>2 · Tra tuổi tên miền</b> <span class="src">nguồn: RDAP</span>
   <p>Biết tên miền đăng ký ngày nào. Tên miền lập dưới 6 tháng thì đáng ngờ — hay được dùng
   để dựng trang rác rồi bỏ. Tên miền trên 3 năm thì tool chặn nhẹ tay hơn.</p>
   <p class="lim">⚠ Khoảng <b>12%</b> tên miền không tra được tuổi. Khi đó các ô liên quan đến tuổi
   lặng lẽ bỏ qua, không báo gì.</p>
   <p class="lim">⚠ <b>Tuổi cao không có nghĩa là trang tốt.</b> Trước đây tool tự cho qua mọi
   tên miền trên 7 năm — kiểm lại thấy 8 trong 25 trang được cho qua kiểu đó thực chất là trang
   rỗng, sơ sài. Luật đó đã bỏ. Giờ tuổi chỉ dùng để giảm mức chặn, không dùng để phong uy tín.</p></div>
  <div class="mgrp"><b>3 · Dò từ khoá xấu</b>
   <p>Tìm các từ như casino, porn, crack, apk, loan… trong <b>tên miền</b> và trong
   <b>tiêu đề trang</b>. Thấy trong tên miền thì chặn thẳng. Chỉ thấy trong tiêu đề, mà trang
   đã tồn tại trên 3 năm, thì hạ xuống mức "cần xem lại" cho đỡ oan.</p>
   <p>Có thêm một bước chống chặn oan: nếu tên miền chứa từ xấu <b>nhưng nội dung thật không hề
   nhắc đến</b>, tool tự hạ xuống "cần xem lại" thay vì chặn.</p>
   <p class="lim">⚠ <b>Đây chỉ là so khớp chữ, tool không hiểu nghĩa.</b> Một tờ báo lớn đăng bài
   về casino vẫn bị tính là trang cờ bạc. Ngược lại, trang rác đặt tên và tiêu đề nghe tử tế
   thì lọt qua hoàn toàn.</p></div>
  <div class="mgrp"><b>4 · Danh sách cố định</b>
   <p>Đuôi <b>.gov</b> và <b>.edu</b> được cho qua ngay. Tám trang rút gọn link
   (bit.ly, tinyurl.com, goo.gl, t.co, ow.ly, cutt.ly, rebrand.ly, shorturl.at) bị chặn ngay,
   vì chúng chỉ chuyển hướng chứ không có nội dung gì.</p></div>
  <div class="mgrp"><b>5 · Bộ nhớ tạm</b> <span class="src">file domain_cache.json</span>
   <p>Mỗi website chỉ kiểm tra qua mạng một lần rồi ghi nhớ, nên chạy lại lần sau rất nhanh.</p>
   <p class="lim">⚠ <b>Bộ nhớ này không tự hết hạn.</b> Trang kiểm tra từ tháng trước vẫn giữ kết quả
   cũ, dù nay đã đổi chủ hoặc bị hack. Muốn kiểm tra lại từ đầu thì xoá file
   <code>domain_cache.json</code> trong thư mục 15Jul.</p></div>
  <div class="mgrp bot"><b>Tool KHÔNG làm được gì</b>
   <p>Không hiểu nội dung nói về chủ đề gì, nên không nhận ra trang chính trị, tôn giáo, bạo lực,
   tin giả hay nội dung do AI viết hàng loạt. Không đánh giá được trang uy tín hay không —
   trừ .gov/.edu. Không xem được các trang bên trong, chỉ trang chủ.</p>
   <p><b>Ô Malware / Threat hiện đã bị khoá</b>, vì nguồn dữ liệu đang dùng không trả về kết quả
   quét mã độc — phép kiểm tra đó chưa bao giờ chạy được. Muốn có thật thì phải nối sang
   Google Safe Browsing.</p>
   <p>Nói gọn: tool này <b>thu hẹp việc phải xem tay</b>, chứ không thay thế được việc xem tay.</p></div>
 </details>
 <div style="text-align:center"><button class="btn" id="go">▶ Gắn nhãn</button></div>
 <div class="bar" id="bar"><i id="fill"></i></div><div class="pct" id="pct"></div>
 <div class="res" id="res"><div class="chips" id="chips"></div><a class="dl" id="dl" href="#">⬇ Tải file (thêm cột loại website)</a></div>
 <div class="wrapT" id="wrapT"><table><thead><tr><th>Website</th><th>Verdict</th><th>Loại website</th><th>Lý do</th></tr></thead><tbody id="tb"></tbody></table></div>
 <div class="note">Chạy local, dữ liệu không rời máy. Lần đầu mỗi domain hơi lâu (urlscan+RDAP), sau nhanh nhờ cache. Cấp 4 (tùy khách) mặc định tắt.</div>
</div></div>
<script>
let mode=1,chosen=null;
const $=id=>document.getElementById(id);
$('t1').onclick=()=>{mode=1;$('t1').classList.add('on');$('t2').classList.remove('on');$('m1').style.display='';$('m2').style.display='none';};
$('t2').onclick=()=>{mode=2;$('t2').classList.add('on');$('t1').classList.remove('on');$('m2').style.display='';$('m1').style.display='none';};
$('file').onchange=e=>{if(e.target.files[0]){chosen=e.target.files[0];$('dtext').innerHTML='<b>'+chosen.name+'</b><br>sẵn sàng';}};
['dragover','dragenter'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',e=>{if(e.dataTransfer.files[0]){chosen=e.dataTransfer.files[0];$('dtext').innerHTML='<b>'+chosen.name+'</b><br>sẵn sàng';}});
$('go').onclick=async()=>{
 const fd=new FormData();
 if(mode===1){const t=$('ta').value.trim(); if(!t){alert('Nhập ít nhất 1 website');return;} fd.append('domains',t);}
 else{if(!chosen){alert('Chọn file Excel');return;} fd.append('file',chosen);}
 const checks=[...document.querySelectorAll('input[data-k]:checked')].map(i=>i.dataset.k).join(',');
 fd.append('checks',checks);
 $('go').disabled=true;$('res').style.display='none';$('wrapT').style.display='none';$('bar').style.display='block';
 const {id}=await (await fetch('/process',{method:'POST',body:fd})).json();
 const t=setInterval(async()=>{
  const s=await (await fetch('/status?id='+id)).json();
  const p=s.total?Math.round(s.done/s.total*100):0; $('fill').style.width=p+'%';
  $('pct').textContent='Đang xử lý '+s.done+'/'+(s.total||'?')+' ('+p+'%)';
  if(s.status==='done'){clearInterval(t);$('pct').textContent='Xong!';const c=s.counts||{};
   $('chips').innerHTML=['BLOCK','REVIEW','KEEP'].map(k=>'<div class="chip '+k+'">'+k+' '+(c[k]||0)+'</div>').join('');
   $('dl').href='/download?f='+encodeURIComponent(s.outfile);$('res').style.display='block';
   $('tb').innerHTML=s.rows.map(r=>'<tr><td>'+r.website+'</td><td><span class="v '+r.verdict+'">'+r.verdict+'</span></td><td>'+r.loai+'</td><td style="color:#667;font-size:12px">'+r.reason+'</td></tr>').join('');
   $('wrapT').style.display='block';$('go').disabled=false;}
  if(s.status==='error'){clearInterval(t);$('pct').textContent='LỖI: '+s.error;$('go').disabled=false;}
 },600);
};
</script></body></html>'''

class H(http.server.BaseHTTPRequestHandler):
    def log_message(s,*a): pass
    def _s(s,code,ct,b): s.send_response(code);s.send_header('Content-Type',ct);s.send_header('Content-Length',str(len(b)));s.end_headers();s.wfile.write(b)
    def do_GET(s):
        from urllib.parse import urlparse,parse_qs
        u=urlparse(s.path); q=parse_qs(u.query)
        if u.path=='/': s._s(200,'text/html; charset=utf-8',PAGE.encode('utf-8'))
        elif u.path=='/status': s._s(200,'application/json',json.dumps(JOBS.get(q.get('id',[''])[0],{'status':'?'})).encode())
        elif u.path=='/download':
            f=os.path.basename(q.get('f',[''])[0]); p=os.path.join(OUTDIR,f)
            if os.path.exists(p):
                data=open(p,'rb').read(); s.send_response(200)
                ct='text/csv; charset=utf-8' if f.lower().endswith('.csv') else 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                s.send_header('Content-Type',ct)
                s.send_header('Content-Disposition','attachment; filename="%s"'%f); s.send_header('Content-Length',str(len(data))); s.end_headers(); s.wfile.write(data)
            else: s._s(404,'text/plain',b'not found')
        else: s._s(404,'text/plain',b'404')
    def do_POST(s):
        if s.path!='/process': return s._s(404,'text/plain',b'404')
        form=cgi.FieldStorage(fp=s.rfile,headers=s.headers,environ={'REQUEST_METHOD':'POST','CONTENT_TYPE':s.headers['Content-Type']})
        jid=uuid.uuid4().hex; JOBS[jid]={'status':'run','done':0,'total':0}
        on=set(x for x in form.getvalue('checks','').split(',') if x) or set(DEFAULT_ON)
        if 'file' in form and form['file'].filename:
            fi=form['file']; orig=os.path.basename(fi.filename); ext=os.path.splitext(orig)[1] or '.xlsx'; tmp=os.path.join(OUTDIR,'_tmp_'+jid+ext); open(tmp,'wb').write(fi.file.read())
            threading.Thread(target=run_job,args=(jid,),kwargs={'excel':tmp,'orig':orig,'on':on},daemon=True).start()
        else:
            doms=[l.strip() for l in form.getvalue('domains','').splitlines() if l.strip()]
            threading.Thread(target=run_job,args=(jid,),kwargs={'domains':doms,'orig':'website_list.xlsx','on':on},daemon=True).start()
        s._s(200,'application/json',json.dumps({'id':jid}).encode())

if __name__=='__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address=True
    port_env=os.environ.get('PORT')
    if port_env:
        # Chạy trên host (Render/Railway): bind mọi IP, không tự mở browser
        PORT=int(port_env); srv=socketserver.ThreadingTCPServer(('0.0.0.0',PORT),H)
        print('Placement Labeler đang chạy ở cổng %d'%PORT); srv.serve_forever()
    else:
        # Chạy local: quét cổng trống, tự mở browser
        PORT=8000
        for p in range(8000,8010):
            try: srv=socketserver.ThreadingTCPServer(('127.0.0.1',p),H); PORT=p; break
            except OSError: continue
        url='http://127.0.0.1:%d'%PORT; print('Placement Labeler:',url,'— đóng cửa sổ này để tắt.')
        threading.Timer(1.0,lambda: webbrowser.open(url)).start(); srv.serve_forever()
