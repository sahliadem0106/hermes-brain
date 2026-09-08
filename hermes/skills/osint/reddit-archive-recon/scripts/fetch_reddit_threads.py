#!/usr/bin/env python3
"""Fetch Reddit posts + full comments for given thread IDs via archive APIs.

Usage:
  python fetch_reddit_threads.py 1qmgws9 dg4uu4 1fouy49 > out.txt
  python fetch_reddit_threads.py 1qmgws9 --api pullpush   # fallback API

Readable transcript to stdout. Raw receipts = the output file.
"""
import argparse, json, sys, time, datetime, urllib.request

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) hermes-recon/1.0'}


def get(url, tries=3, wait=5):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=90) as r:
                return r.read().decode('utf-8', 'replace')
        except Exception as e:
            print(f'[retry {i+1}/{tries}] {url[:90]} -> {e}', file=sys.stderr)
            time.sleep(wait * (i + 1))
    return None


def fmt(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime('%Y-%m-%d')
    except Exception:
        return '?'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('ids', nargs='+', help='Reddit thread ids (base36, e.g. 1qmgws9)')
    ap.add_argument('--api', choices=['arctic', 'pullpush'], default='arctic')
    args = ap.parse_args()

    if args.api == 'arctic':
        BASE = 'https://arctic-shift.photon-reddit.com/api'
        posts_url = f'{BASE}/posts/ids?ids={",".join(args.ids)}'
        com_url = lambda tid: f'{BASE}/comments/search?link_id={tid}&limit=100'
    else:
        BASE = 'https://api.pullpush.io/reddit/search'
        posts_url = f'{BASE}/submission/?ids={",".join(args.ids)}'
        com_url = lambda tid: f'{BASE}/comment/?link_id={tid}&size=100'

    raw = get(posts_url)
    posts = {p.get('id'): p for p in json.loads(raw).get('data', [])} if raw else {}
    for tid in args.ids:
        p = posts.get(tid)
        print('=' * 90)
        if p:
            print('POST:', p.get('title'), '|', fmt(p.get('created_utc')), '| score', p.get('score'))
            st = (p.get('selftext') or '').strip()
            if st:
                print('SELFTEXT:', st[:2000])
            print('URL: https://www.reddit.com' + (p.get('permalink') or ''))
        else:
            print('POST', tid, 'not found in archive')
        time.sleep(1)
        rawc = get(com_url(tid))
        if rawc:
            coms = json.loads(rawc).get('data', [])
            print(f'--- {len(coms)} comments ---')
            for c in coms:
                body = (c.get('body') or '').replace('\n', ' ')
                print('---', c.get('author'), '|', fmt(c.get('created_utc')), '|', body[:900])
        time.sleep(2)
    print('DONE')


if __name__ == '__main__':
    main()
