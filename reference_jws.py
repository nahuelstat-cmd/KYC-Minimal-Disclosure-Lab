"""Synthetic component experiment; no PCN imports, no real KYC, no OID conformance.
JWS/JWT via PyJWT 2.10.1, Ed25519 via cryptography. Private claims are lab profile.
Authority is an in-memory fixture: NOT independent custody or production recovery.
"""
import hashlib, json, secrets, sqlite3, tempfile, time
from pathlib import Path
from contextlib import contextmanager
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ISS='https://kyc.lab.invalid'; POLICY='age18-kyc/v1'; AGE=18

def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':'))
def digest(x): return hashlib.sha256(x.encode()).hexdigest()
def pub(k): return k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()

@contextmanager
def db_connection(path):
    """Commit/rollback the transaction, then always close the SQLite handle."""
    connection = sqlite3.connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()

class Reference:
 def __init__(self,root):
  self.root=Path(root);self.issuer=Ed25519PrivateKey.generate();self.active=True
  self.epoch=1;self.revoked=set();self.paths={a:self.root/(a+'.sqlite') for a in ['a','b']}
  for p in self.paths.values():
   with db_connection(p) as c:
    c.executescript('CREATE TABLE request(n TEXT PRIMARY KEY, context TEXT, expires INTEGER); CREATE TABLE receipt(n TEXT PRIMARY KEY, result TEXT);')
 def issue(self,a,holder,adult=True,kyc=True,key=None,exp=None):
  now=int(time.time());return jwt.encode(dict(iss=ISS,aud=a,iat=now,exp=exp or now+600,jti=secrets.token_hex(16),cnf={'lab_public_hex':pub(holder)},adult=adult,kyc=kyc,policy=POLICY,epoch=self.epoch),key or self.issuer,algorithm='EdDSA',headers={'typ':'JWT'})
 def challenge(self,a,policy=POLICY):
  now=int(time.time());x=dict(aud=a,nonce=secrets.token_hex(32),policy=policy,purpose='synthetic-access',iat=now,exp=now+60)
  with db_connection(self.paths[a]) as c:c.execute('INSERT INTO request VALUES(?,?,?)',(x['nonce'],canonical(x),x['exp']))
  return x
 def present(self,cred,holder,x):return jwt.encode(dict(aud=x['aud'],iat=int(time.time()),exp=x['exp'],nonce=x['nonce'],credential_hash=digest(cred),context_hash=digest(canonical(x))),holder,algorithm='EdDSA',headers={'typ':'JWT'})
 def verify(self,a,cred,proof,x):
  if not self.active:raise ValueError('issuer withdrawn')
  claims=jwt.decode(cred,self.issuer.public_key(),algorithms=['EdDSA'],audience=a,issuer=ISS,options={'require':['iss','aud','iat','exp','jti','cnf','adult','kyc','policy','epoch']})
  if claims['policy']!=POLICY or x['policy']!=POLICY or claims['epoch']!=self.epoch or claims['jti'] in self.revoked or claims['adult'] is not True or claims['kyc'] is not True:raise ValueError('claims')
  holder=Ed25519PublicKey.from_public_bytes(bytes.fromhex(claims['cnf']['lab_public_hex']))
  q=jwt.decode(proof,holder,algorithms=['EdDSA'],audience=a,options={'require':['aud','iat','exp','nonce','credential_hash','context_hash']})
  if q['nonce']!=x['nonce'] or q['credential_hash']!=digest(cred) or q['context_hash']!=digest(canonical(x)):raise ValueError('binding')
  with db_connection(self.paths[a]) as c:
   c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT context,expires FROM request WHERE n=?',(x['nonce'],)).fetchone()
   if not r or r[0]!=canonical(x) or r[1]<int(time.time()) or c.execute('SELECT 1 FROM receipt WHERE n=?',(x['nonce'],)).fetchone():raise ValueError('challenge/replay')
   c.execute('INSERT INTO receipt VALUES(?,?)',(x['nonce'],'ACCEPTED'))
  return 'ACCEPTED'
 def recover_receipt(self,a,x):
  with db_connection(self.paths[a]) as c:r=c.execute('SELECT result FROM receipt WHERE n=?',(x['nonce'],)).fetchone()
  return r[0] if r else 'UNKNOWN'

def run():
 checks={}
 def expect(n,fn,accept):
  try:fn();observed=True
  except (ValueError,jwt.PyJWTError):observed=False
  checks[n]={'expected_accept':accept,'observed_accept':observed,'pass':observed==accept}
 with tempfile.TemporaryDirectory() as td:
  r=Reference(td);holders={a:Ed25519PrivateKey.generate() for a in ['a','b']};creds={a:r.issue(a,holders[a]) for a in ['a','b']}
  for a in ['a','b']:
   x=r.challenge(a);proof=r.present(creds[a],holders[a],x)
   expect('valid_'+a,lambda:r.verify(a,creds[a],proof,x),True)
   expect('replay_'+a,lambda:r.verify(a,creds[a],proof,x),False)
   checks['lost_response_'+a]={'pass':r.recover_receipt(a,x)=='ACCEPTED','meaning':'historical receipt; not renewed authorization'}
  for name,kwargs in [('underage',{'adult':False}),('bad_kyc',{'kyc':False}),('expired',{'exp':int(time.time())-10}),('unauthorized_issuer',{'key':Ed25519PrivateKey.generate()})]:
   c=r.issue('a',holders['a'],**kwargs);x=r.challenge('a');p=r.present(c,holders['a'],x);expect(name,lambda:r.verify('a',c,p,x),False)
  x=r.challenge('a');p=r.present(creds['a'],Ed25519PrivateKey.generate(),x);expect('wrong_holder',lambda:r.verify('a',creds['a'],p,x),False)
  x=r.challenge('b');p=r.present(creds['a'],holders['a'],x);expect('wrong_audience',lambda:r.verify('b',creds['a'],p,x),False)
  x=r.challenge('a');p=r.present(creds['a'],holders['a'],x);y=dict(x,policy='age0-kyc/v1');expect('policy_substitution',lambda:r.verify('a',creds['a'],p,y),False)
  x=r.challenge('a');p=r.present(creds['a'],holders['a'],x);part=creds['a'].split('.');part[1]=('A' if part[1][0]!='A' else 'B')+part[1][1:];bad='.'.join(part);expect('tampering',lambda:r.verify('a',bad,p,x),False)
  x=r.challenge('a');p=r.present(creds['a'],holders['a'],x);r.revoked.add(jwt.decode(creds['a'],options={'verify_signature':False})['jti']);expect('revoked',lambda:r.verify('a',creds['a'],p,x),False)
  # Deliberate counterexample: signing-key theft can mint a false positive before withdrawal.
  forged=r.issue('a',holders['a'],key=r.issuer);x=r.challenge('a');p=r.present(forged,holders['a'],x);expect('stolen_trusted_key_forgery_COUNTEREXAMPLE',lambda:r.verify('a',forged,p,x),True)
  r.active=False;x=r.challenge('a');p=r.present(forged,holders['a'],x);expect('withdrawn_issuer',lambda:r.verify('a',forged,p,x),False)
  r.issuer=Ed25519PrivateKey.generate();r.epoch+=1;r.active=True;x=r.challenge('b');p=r.present(creds['b'],holders['b'],x);expect('old_key_after_recovery',lambda:r.verify('b',creds['b'],p,x),False)
  fresh=r.issue('a',holders['a']);x=r.challenge('a');p=r.present(fresh,holders['a'],x);expect('new_key_epoch',lambda:r.verify('a',fresh,p,x),True)
  dec={a:jwt.decode(c,options={'verify_signature':False}) for a,c in creds.items()}
  checks['distinct_personal_fields']={'pass':dec['a']['jti']!=dec['b']['jti'] and dec['a']['cnf']!=dec['b']['cnf']}
  forbidden=['DNI_CANARY','SELFIE_CANARY','DOB_CANARY'];persist=''.join(p.read_bytes().hex() for p in r.paths.values())
  checks['no_documents_in_presentations_or_db']={'pass':all(s not in canonical(dec) and s.encode().hex() not in persist for s in forbidden),'limit':'issuer never supplied those fields; not a complete dataflow audit'}
 result={'status':'PASS' if all(c['pass'] for c in checks.values()) else 'FAIL','scope':'synthetic JWS components only; no PCN imports; no OID/SD-JWT conformance; authority fixture in memory; no legal acceptance','checks':checks,'check_count':len(checks),'versions':{'PyJWT':jwt.__version__},'counterexample_is_expected':True,'not_demonstrated':['real KYC','AML','two independent organizations','no issuer correlation','authority independence','complete restore','status list standard','same requirements as dual PCN','production']}
 return result
if __name__=='__main__':
 out=run();Path(__file__).with_name('reference_jws_result.json').write_text(json.dumps(out,indent=2));print(out['status'],out['check_count']);raise SystemExit(out['status']!='PASS')
