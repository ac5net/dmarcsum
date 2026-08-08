#!/usr/bin/env python3
# dmarcsum.py - DMARC集計レポート(RUA)を集計する
# 使い方: ./dmarcsum.py <レポートを置いたディレクトリ>
import sys, os, glob, gzip, zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict

def load_bytes(path):
    """.gz / .zip / 素の .xml を透過的に読む。zipは中の全xmlを返す"""
    if path.endswith('.gz'):
        with gzip.open(path, 'rb') as f:
            return [f.read()]
    if path.endswith('.zip'):
        out = []
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.lower().endswith('.xml'):
                    out.append(z.read(n))
        return out
    if path.lower().endswith('.xml'):
        with open(path, 'rb') as f:
            return [f.read()]
    return []

def strip_ns(elem):
    """名前空間を再帰的に剥がす。これをやらないとレポートを無言で取りこぼす"""
    for e in elem.iter():
        if isinstance(e.tag, str) and e.tag.startswith('{'):
            e.tag = e.tag.split('}', 1)[1]
    return elem

def text(node, path, default=''):
    """要素が無い場合に落ちないget。policy_evaluated/dkim は省略されることがある"""
    f = node.find(path)
    return (f.text or '').strip() if f is not None and f.text else default

total = 0
aligned_pass = 0
sampled_out = 0
by_source = defaultdict(lambda: {'n': 0, 'pass': 0})
fail_rows = []
raw_results = defaultdict(int)
parse_errors = []
files = 0

target = sys.argv[1] if len(sys.argv) > 1 else '.'
for path in sorted(glob.glob(os.path.join(target, '*'))):
    for blob in load_bytes(path):
        files += 1
        try:
            root = strip_ns(ET.fromstring(blob))
        except ET.ParseError as e:
            parse_errors.append((os.path.basename(path), str(e)))
            continue

        pol_domain = text(root, 'policy_published/domain', '(不明)')
        pct = text(root, 'policy_published/pct', '100')

        for rec in root.findall('record'):
            try:
                cnt = int(text(rec, 'row/count', '0'))
            except ValueError:
                cnt = 0
            total += cnt

            ip   = text(rec, 'row/source_ip', '(不明)')
            disp = text(rec, 'row/policy_evaluated/disposition', 'none')
            # policy_evaluated は「アライメント込みの評価結果」。pass/fail の2値しかない
            a_dkim = text(rec, 'row/policy_evaluated/dkim', 'fail')
            a_spf  = text(rec, 'row/policy_evaluated/spf',  'fail')
            reason = text(rec, 'row/policy_evaluated/reason/type', '')
            hfrom  = text(rec, 'identifiers/header_from', '')

            by_source[ip]['n'] += cnt
            if a_dkim == 'pass' or a_spf == 'pass':
                aligned_pass += cnt
                by_source[ip]['pass'] += cnt
            else:
                if reason == 'sampled_out':
                    sampled_out += cnt
                # auth_results は「生の認証結果」。ここを取り違えると原因を誤診する
                rd = [(text(d, 'domain'), text(d, 'selector'), text(d, 'result'))
                      for d in rec.findall('auth_results/dkim')]
                rs = [(text(s, 'domain'), text(s, 'scope'), text(s, 'result'))
                      for s in rec.findall('auth_results/spf')]
                for _, _, r in rd:
                    raw_results['dkim:' + (r or 'なし')] += cnt
                for _, _, r in rs:
                    raw_results['spf:' + (r or 'なし')] += cnt
                if not rd:
                    raw_results['dkim:署名なし'] += cnt
                fail_rows.append({'ip': ip, 'cnt': cnt, 'disp': disp, 'reason': reason,
                                  'hfrom': hfrom, 'dkim': rd, 'spf': rs,
                                  'domain': pol_domain, 'pct': pct})

print('読み込んだレポート : {} 件'.format(files))
print('総メッセージ数     : {}'.format(total))
if total:
    print('DMARC pass         : {} ({:.1f}%)'.format(aligned_pass, 100*aligned_pass/total))
    print('DMARC fail         : {} ({:.1f}%)'.format(total-aligned_pass, 100*(total-aligned_pass)/total))
if sampled_out:
    print('うち sampled_out   : {} （pct未満で対象外。実際には隔離/拒否されていない）'.format(sampled_out))

print('\\n=== 送信元IP別 ===')
for ip, v in sorted(by_source.items(), key=lambda x: -x[1]['n']):
    rate = 100*v['pass']/v['n'] if v['n'] else 0
    print('  {:<24} {:>6} 通  pass {:>5.1f}%'.format(ip, v['n'], rate))

print('\\n=== 失敗の生の認証結果（auth_results） ===')
for k, c in sorted(raw_results.items(), key=lambda x: -x[1]):
    print('  {:<20} {}'.format(k, c))

print('\\n=== 失敗行の詳細（上位10件） ===')
for r in sorted(fail_rows, key=lambda x: -x['cnt'])[:10]:
    print('  {} / {} 通 / disposition={} {}'.format(r['ip'], r['cnt'], r['disp'],
          '/ reason=' + r['reason'] if r['reason'] else ''))
    print('      header_from={}  policy_domain={} pct={}'.format(r['hfrom'], r['domain'], r['pct']))
    for d, s, res in r['dkim']:
        print('      DKIM d={} s={} -> {}'.format(d, s, res))
    for d, sc, res in r['spf']:
        print('      SPF  domain={} scope={} -> {}'.format(d, sc, res))

if parse_errors:
    print('\\n=== 解析できなかったファイル ===')
    for n, e in parse_errors:
        print('  {}: {}'.format(n, e))

sys.exit(0)
