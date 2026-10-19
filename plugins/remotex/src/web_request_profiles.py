"""Private, strict revision-3 request views. Parsing never grants authority."""
from __future__ import annotations

import base64
import decimal
import json
import re
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit

from web_authorization import ScopeError

PROFILES=('json-utf8-v1','form-utf8-v1','form-json-name-view-v1')
MAX_REFERENCE_UNITS=32
MAX_PROPOSAL_UNITS=96
CAPTURE_KEYS={'version','method','origin','resource_type','target_b64','body_b64','content_type_b64',
              'original_headers','effective_headers','transport_policy','cookie_context','protection_refs'}
HOP={'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'}
FIXED={'host','content-length','accept-encoding','content-type','cookie'}
HARD_NAME=re.compile(r'^(?:internalAuth|password|passwd|pwd|token|access_token|refresh_token|session_id|sessionid|csrf|csrf_token|nonce|signature|ticket)$',re.I)
AUTH_HEADER=re.compile(r'authorization|(?:^|[-_])(?:auth|token|session|csrf|nonce|signature|credential|api[-_]?key)(?:$|[-_])',re.I)


def _bad():
    raise ScopeError('request-contract-unavailable')


def _capacity():
    raise ScopeError('setup-plan-capacity-required')


def _text(value):
    if (not isinstance(value,str) or any(unicodedata.category(c) in {'Cc','Cs'} for c in value) or
            re.search(r'-----BEGIN |\b(?:ghp_|glpat-|sk-proj-)',value)):
        _bad()
    return value


def _size(value):
    return len(value.encode('utf-8'))


def _b64(value):
    if not isinstance(value,str):
        _bad()
    raw=base64.b64decode(value,validate=True)
    if base64.b64encode(raw).decode('ascii')!=value:
        _bad()
    return raw


def _key(value):
    _text(value)
    if not value or _size(value)>128 or value in {'__proto__','constructor','prototype'} or HARD_NAME.fullmatch(value):
        _bad()
    return value


def _headers(rows):
    if not isinstance(rows,list) or len(rows)>100:
        _bad()
    result=[]
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!={'name_b64','value_b64'}:
            _bad()
        name=_b64(row['name_b64']).decode('utf-8')
        value=_b64(row['value_b64']).decode('utf-8')
        _text(name)
        _text(value)
        if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or
                not re.fullmatch(r'[\x20-\x7e]*',value) or name.lower() in seen or AUTH_HEADER.search(name)):
            _bad()
        seen.add(name.lower())
        result.append([name,value])
    return result


def effective_v3_headers(original,origin,body_length):
    result={name.lower():value for name,value in original if name.lower() not in HOP}
    result.update({'host':urlsplit(origin).netloc,'accept-encoding':'identity','content-length':str(body_length)})
    return [list(row) for row in sorted(result.items())]


def decode_v3_capture(capture):
    try:
        if (not isinstance(capture,dict) or set(capture)!=CAPTURE_KEYS or type(capture['version']) is not int or
                capture['version']!=3 or capture['method']!='POST' or capture['resource_type'] not in {'xhr','fetch'} or
                capture['transport_policy']!='fixed-egress-v1' or capture['protection_refs']!=[]):
            _bad()
        if _size(json.dumps(capture,ensure_ascii=False,separators=(',',':')))>32768:
            _capacity()
        origin=capture['origin']
        peer=urlsplit(origin)
        if (not isinstance(origin,str) or not re.fullmatch(r'https://[!-~]+',origin) or peer.scheme!='https' or
                peer.path or peer.query or peer.fragment or peer.username or peer.password or not peer.hostname or
                peer.netloc.lower()!=peer.netloc or peer.port==443):
            _bad()
        body=_b64(capture['body_b64'])
        target=_b64(capture['target_b64']).decode('utf-8')
        content_type=_b64(capture['content_type_b64']).decode('utf-8')
        url=urlsplit(target)
        if (len(body)>16384 or not re.fullmatch(r'/(?!/)[\x21-\x7e]*',target) or '#' in target or
                _size(url.query)>8192 or url.scheme or url.netloc or
                any(_component(p.replace('+','%2B')) in {'.','..'} for p in url.path.split('/'))):
            _bad()
        if not re.fullmatch(r'application/(?:json|x-www-form-urlencoded)(?:; *charset=(?:utf-8|"utf-8"))?',content_type,re.I):
            _bad()
        original=_headers(capture['original_headers'])
        effective=_headers(capture['effective_headers'])
        if (next((v for n,v in original if n.lower()=='content-type'),None)!=content_type or
                effective!=effective_v3_headers(original,origin,len(body))):
            _bad()
        cookie=capture['cookie_context']
        if any(n.lower()=='cookie' for n,_ in original):
            if (not isinstance(cookie,dict) or set(cookie)!={'jar_ref','epoch_ref'} or
                    any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{32}',v) for v in cookie.values())):
                _bad()
        elif cookie is not None:
            _bad()
        return {'body':body,'target':target,'content_type':content_type,'original':original,'effective':effective,'url':url}
    except Exception as exc:
        if isinstance(exc,ScopeError) and exc.code=='setup-plan-capacity-required':
            raise
        raise ScopeError('request-contract-unavailable') from None


def _component(raw):
    if re.search(r'%(?![0-9a-fA-F]{2})',raw):
        _bad()
    return _text(unquote_to_bytes(raw.replace('+',' ')).decode('utf-8'))


def _form(raw,*,carrier=False):
    if not raw:
        return []
    parts=raw.split('&')
    if len(parts)>100:
        _bad()
    seen=set()
    result=[]
    for part in parts:
        name,_,value=part.partition('=')
        name,value=_component(name),_component(value)
        if not name or name in seen:
            _bad()
        seen.add(name)
        if not carrier:
            if re.match(r'^[\s\ufeff]*[\[{]',name):
                _bad()
            _key(name)
        result.append([name,value])
    return result


class _Pairs(list):
    pass


def _json_tree(raw):
    def invalid_constant(_value):
        _bad()
    root=json.loads(raw,object_pairs_hook=_Pairs,parse_float=decimal.Decimal,parse_constant=invalid_constant)
    if not isinstance(root,_Pairs):
        _bad()

    def visit(node,depth=0):
        if depth>8:
            _bad()
        if isinstance(node,_Pairs):
            if len(node)>100:
                _bad()
            seen=set()
            entries=[]
            for name,part in node:
                _key(name)
                if name in seen:
                    _bad()
                seen.add(name)
                entries.append([name,visit(part,depth+1)])
            return {'type':'object','entries':entries}
        if isinstance(node,list):
            if len(node)>100:
                _bad()
            return {'type':'array','items':[visit(part,depth+1) for part in node]}
        if node is None:
            return {'type':'null','value':None}
        if type(node) is bool:
            return {'type':'boolean','value':node}
        if isinstance(node,str):
            return {'type':'string','value':_text(node)}
        if type(node) is int or isinstance(node,decimal.Decimal):
            if abs(node)>9007199254740991 or node!=int(node):
                _bad()
            return {'type':'integer','value':int(node)}
        _bad()
    return visit(root)


def validate_v3_capture(capture,profile_id):
    try:
        if profile_id not in PROFILES:
            _bad()
        c=decode_v3_capture(capture)
        is_json=profile_id=='json-utf8-v1'
        if c['content_type'].split(';')[0].lower()!=('application/json' if is_json else 'application/x-www-form-urlencoded'):
            _bad()
        path=[_component(p.replace('+','%2B')) for p in c['url'].path.split('/') if p]
        query=_form(c['url'].query)
        raw=c['body'].decode('utf-8')
        carrier=profile_id=='form-json-name-view-v1'
        if is_json:
            body=_json_tree(raw)
        else:
            pairs=_form(raw,carrier=carrier)
            if carrier:
                if len(pairs)!=1 or pairs[0][1]!='':
                    _bad()
                body=_json_tree(pairs[0][0])
            else:
                body={'type':'form','pairs':pairs}
        locations=[]

        def add(identity,kind,value,sensitive=False):
            if isinstance(value,str) and _size(value)>256:
                _capacity()
            locations.append({'id':identity,'type':kind,'sensitive':sensitive})

        def add_pairs(rows,prefix):
            for index,(name,value) in enumerate(rows):
                _key(name)
                add(f'{prefix}.{index}.key','key',name,bool(re.search('session|auth|token|key|credential|challenge',name,re.I)))
                add(f'{prefix}.{index}.value','string',value)

        def walk(node,identity):
            if node['type']=='object':
                if not node['entries']:
                    add(identity,'empty-object',None)
                for index,(name,part) in enumerate(node['entries']):
                    add(f'{identity}.{index}.key','key',name,bool(re.search('session|auth|token|key|credential|challenge',name,re.I)))
                    walk(part,f'{identity}.{index}.value')
            elif node['type']=='array':
                if not node['items']:
                    add(identity,'empty-array',None)
                for index,part in enumerate(node['items']):
                    walk(part,f'{identity}.{index}')
            elif node['type']=='form':
                add_pairs(node['pairs'],identity)
            else:
                add(identity,node['type'],node['value'])

        for index,part in enumerate(path):
            add(f'path.{index}','string',part)
        add_pairs(query,'query')
        add_pairs([(n,v) for n,v in c['effective'] if n not in FIXED],'header')
        if carrier:
            add('body.carrier','structured-carrier',None)
            add('body.outer-value','string','')
        walk(body,'body')
        if len(locations)>MAX_REFERENCE_UNITS:
            _capacity()
        return {'profile_id':profile_id,'ordered_tree':{'path':path,'query':query,'body':body},'locations':locations,
                'unit_count':len(locations),'byte_count':_size(json.dumps(capture,ensure_ascii=False,separators=(',',':')))}
    except Exception as exc:
        if isinstance(exc,ScopeError) and exc.code=='setup-plan-capacity-required':
            raise
        raise ScopeError('request-contract-unavailable') from None


def validate_public_reference(capture,view,reference):
    result={'matched':False,'complete':False,'unit_count':view['unit_count']}
    try:
        if (not isinstance(reference,dict) or set(reference)!={'profile_id','target_text','content_type','body_text','public_headers'} or
                reference['profile_id']!=view['profile_id'] or not isinstance(reference['public_headers'],list) or
                len(reference['public_headers'])>100):
            return result
        c=decode_v3_capture(capture)
        headers=[]
        for row in reference['public_headers']:
            if (not isinstance(row,dict) or set(row)!={'name','value'} or not isinstance(row['name'],str) or
                    row['name']!=row['name'].lower() or not isinstance(row['value'],str) or
                    _size(row['name'])>256 or _size(row['value'])>256):
                return result
            headers.append([row['name'],row['value']])
        matched=(reference['target_text']==c['target'] and reference['content_type']==c['content_type'] and
                 reference['body_text']==c['body'].decode('utf-8') and headers==[r for r in c['effective'] if r[0] not in FIXED])
        return {'matched':matched,'complete':matched,'unit_count':view['unit_count']}
    except Exception:
        return result


def safe_v3_observation(refs,public_identity):
    if (not isinstance(refs,dict) or set(refs)!={'network_ref','representation_ref','literal_review_refs'} or
            not isinstance(public_identity,dict) or set(public_identity)!={'origin','account'} or
            not isinstance(refs['literal_review_refs'],list) or len(refs['literal_review_refs'])>MAX_REFERENCE_UNITS or
            any(not isinstance(v,str) or not re.fullmatch('[a-f0-9]{32}',v) for v in
                [refs['network_ref'],refs['representation_ref'],*refs['literal_review_refs']])):
        _bad()
    return {**refs,'literal_review_refs':list(refs['literal_review_refs']),'method':'POST','purpose':'initialization-read',
            'profiles':list(PROFILES),**public_identity}
