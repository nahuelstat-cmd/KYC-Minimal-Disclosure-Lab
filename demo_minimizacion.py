"""Synthetic data-flow audit. Run: python demo_minimizacion.py.
One process, synthetic KYC, lab JWT profile; no production or legal approval.
Private keys remain ephemeral. Artifacts include synthetic documents ONLY.
"""
import json, tempfile, hashlib
from pathlib import Path
from reference_jws import Reference, canonical, db_connection, run as security_checks
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MARKERS={'documento':'DOCUMENTO_FICTICIO_PCN_874209','selfie':'SELFIE_FICTICIA_PCN_629415','nacimiento':'DOB_FICTICIO_PCN_1948_02_29','nombre':'NOMBRE_FICTICIO_PCN_438106'}

def write(path, obj):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(obj,ensure_ascii=False,indent=2))

def backup_db(source, destination):
 with db_connection(source) as src,db_connection(destination) as dst:src.backup(dst)

def audit(root):
 records=[]
 for path in sorted(root.rglob('*')):
  if path.is_file():
   data=path.read_bytes();records.append({'archivo':str(path.relative_to(root)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'marcadores_PII':[name for name,value in MARKERS.items() if value.encode() in data]})
 return records

def main():
 security=security_checks()
 with tempfile.TemporaryDirectory(prefix='pcn-minimo-') as temp:
  root=Path(temp);issuer=root/'proveedor';wallet=root/'wallet';services=root/'servicios';services.mkdir()
  capture=dict(MARKERS)
  write(issuer/'evidencia.json',capture)
  write(issuer/'logs.json',{'captura':'completada','decision':'APROBADO_SINTETICO','advertencia':'No verificación de identidad humana real'})
  write(issuer/'backups/evidencia.json',capture)
  # Explicitly fixed assertions stand in for a KYC decision. No biometric algorithm.
  ref=Reference(services);holders={a:Ed25519PrivateKey.generate() for a in ('a','b')}
  tokens={a:ref.issue(a,holders[a],adult=True,kyc=True) for a in holders}
  write(wallet/'credenciales.json',tokens)
  write(wallet/'logs.json',{'credenciales':2,'documentos_recibidos':False})
  write(wallet/'backups/credenciales.json',tokens)
  observations=[]
  for audience in ('a','b'):
   folder=services/audience;folder.mkdir()
   challenge=ref.challenge(audience);proof=ref.present(tokens[audience],holders[audience],challenge)
   wire={'credencial':tokens[audience],'prueba_holder':proof,'contexto':challenge}
   write(folder/'captura_presentacion.json',wire)
   outcome=ref.verify(audience,tokens[audience],proof,challenge)
   # Preserve business receipt after discarding a response, not replaying acceptance.
   recovered=ref.recover_receipt(audience,challenge)
   write(folder/'logs.json',{'resultado':outcome,'politica':'age18-kyc/v1','tipo':'laboratorio','recibo_recuperado':recovered})
   write(folder/'cache.json',{'reglas':['age18-kyc/v1'],'datos_personales':[]})
   (folder/'backups').mkdir();backup_db(ref.paths[audience],folder/'backups/recibos.sqlite')
   (folder/'restauracion').mkdir();backup_db(folder/'backups/recibos.sqlite',folder/'restauracion/recibos.sqlite')
   with db_connection(folder/'restauracion/recibos.sqlite') as db:
    restored=db.execute('SELECT result FROM receipt WHERE n=?',(challenge['nonce'],)).fetchone()[0]
   observations.append({'servicio':audience,'resultado':outcome,'recibo_tras_respuesta_perdida':recovered,'recibo_tras_restore':restored,'bytes_cuerpo_presentacion':len(canonical(wire).encode()),'claims_personales':['adult','kyc'],'metadatos':['iss','aud','iat','exp','jti','cnf','policy','epoch'],'clave_holder_persistida':False})
  files=audit(root)
  provider=[x for x in files if x['archivo'].startswith('proveedor/')]
  downstream=[x for x in files if not x['archivo'].startswith('proveedor/')]
  controls={'captura_realmente_inyectada_en_fixture':all(x in (issuer/'evidencia.json').read_text() for x in MARKERS.values()),'control_positivo_detecta_documentos_en_proveedor':any(x['marcadores_PII'] for x in provider),'marcadores_ausentes_en_wallet_y_servicios':all(not x['marcadores_PII'] for x in downstream),'dos_servicios_aceptan_y_restauran_recibo':all(x['resultado']==x['recibo_tras_respuesta_perdida']==x['recibo_tras_restore']=='ACCEPTED' for x in observations),'controles_JWS_21':security['status']=='PASS'}
  result={'estado':'PASS' if all(controls.values()) else 'FAIL','alcance':'SIMULADO: auditoría de archivos controlados; una fixture, un proceso, dos DB locales','controles':controls,'servicios':observations,'archivos_auditados':files,'seguridad_JWS':security,'comparacion_copias':{'convencional_modelado':'Un paquete documental por proveedor y por servicio: 3 ubicaciones primarias','fixture_minima':'Solo proveedor: 1 ubicación primaria; también un backup documental en ese mismo rol','limite':'Modelo sintético, no medición de un proveedor convencional real; backups no son nuevas instituciones'},'no_demostrado':['KYC humano auténtico','AML','aceptación legal','organizaciones independientes','OID4VCI/OID4VP/SD-JWT conformes','dos backends bajo idénticos requisitos','antifraude biométrico','unlinkability frente al emisor','custodia independiente','recuperación de wallet o autoridad persistente','inexistencia de fugas por transformaciones, memoria, red, dumps o software externo','borrado físico y ciclo completo de backups']}
  write(Path(__file__).with_name('resultado_minimizacion.json'),result)
  print(result['estado'],len(files),'archivos auditados;',security['check_count'],'controles JWS')
  print('Documento/selfie/nacimiento/nombre: presentes en proveedor; ausentes en archivos controlados de wallet y servicios.')
  assert result['estado']=='PASS'

if __name__=='__main__':main()
