# Qué reutilizamos y qué probamos

Actualización 0.2. Documentación consultada el 7 de octubre de 2026.
Estado de todos los ensayos de esta versión: **SIMULADO**. Ningún resultado
demuestra una vulnerabilidad del backend de los proveedores, una integración
certificada, ahorro comercial ni preparación para producción.

## Decisión de alcance

Construimos una capa pequeña de interpretación de estados y observabilidad
mínima. Aprovechamos contratos publicados; no implementamos otro KYC, otra
wallet ni criptografía nueva. Las funciones son propias y no incorporan código
de los repositorios públicos que motivaron la investigación.

| Proveedor | Capacidad existente o regla documentada | Incorporación al laboratorio |
| --- | --- | --- |
| Ripio | Captura hosted y consulta de estado por cliente | La fuente simulada se vuelve a consultar aun después de aprobar |
| Sumsub | Endpoint de review status y semántica de finalización | Solo `completed + GREEN` aprueba; se distingue reintento de rechazo |
| Truora | Resultado de proceso con corrección manual | `override_status` prevalece; un paso exitoso no aprueba el proceso |
| Veriff | Decisión dentro de `verification` | El éxito del envelope no aprueba identidad; se exige asociación de sesión |
| Extrimian / verificadores VC | Separación entre verificación y observabilidad | Se registran eventos mínimos; no se añade su backend ni se prueba su criptografía |

## Contratos y fuentes primarias

### Ripio

El [flujo hosted](https://docs.ripio.com/ramps-api/kyc/kyc-with-ripio)
permite redirigir al proveedor. El partner no tiene que recapturar documentos
para iniciar ese flujo. La lectura documentada es
`GET /api/v1/customers/{customerId}/kycSubmissions/`; el ejemplo devuelve
`customerId`, `status` y `createdAt`. El laboratorio proyecta `COMPLETED`,
`FAILED` e `IN_REVIEW`. No inventa un `submissionId` en esa respuesta: **el
binding probado es de cliente**, no de un intento concreto.

Antes de una conexión real hay que confirmar cómo identificar la submission
vigente. El `providerUrl` y los tokens de reutilización no deben registrarse
en logs generales. La [reutilización](https://docs.ripio.com/ramps-api/kyc/reusable-kyc)
requiere configuración y compatibilidad; no está implementada aquí.

### Sumsub

Se toma el subconjunto de [review status](https://docs.sumsub.com/reference/get-applicant-review-status),
`GET /resources/applicants/{applicantId}/status`, y la tabla de
[estados](https://docs.sumsub.com/docs/applicant-statuses). `GREEN` con
`awaitingService` no es aprobación definitiva. `RED/RETRY` y `RED/FINAL`
tienen resultados diferentes. Se exige el `levelName` previsto. El endpoint
no devuelve applicantId: el lector confiado debe asociar ruta, cuenta y respuesta;
esa asociación se simula mediante `Snapshot.binding`.

El [Gateway](https://docs.sumsub.com/docs/reusable-kyc-gateway) ya separa al
integrador no regulado del receptor regulado. Un token opaco no es el resultado
KYC del receptor. [Reusable KYC Share](https://docs.sumsub.com/docs/reusable-kyc-share)
puede transferir datos y documentos: no elimina todas las copias.
`preservedVerificationStatus=true` hace que se ignore `requireFreshSelfie`.
`reuse_options` rechaza esa combinación contradictoria. No envía una solicitud
de reutilización ni asegura que haya ocurrido un nuevo control biométrico.

### Truora

El [resultado de proceso](https://dev.truora.com/digital-identity/how-to/get_results/)
se consulta en `GET /v1/processes/{process_id}/result`. La proyección comprueba
process_id, account_id, flow_id y flow_version. Si aparece `override_status`,
se usa aunque sea desconocido o nulo: no se retrocede silenciosamente a un
`status=success` anterior. No se busca la palabra éxito en capas arbitrarias.
Un evento de paso exitoso tampoco equivale a proceso completado.

La respuesta puede contener identidad, imágenes y detalles de validación.
El transporte los recibiría; esta capa solo evita propagarlos a su resultado
y a sus logs. **No evita por sí sola la exposición en la recepción.** El contrato
del resultado GET no debe confundirse con el de cualquier webhook configurado.

### Veriff

La [decisión](https://devdocs.veriff.com/docs/decision-webhook) distingue el
`status` externo de `verification.status`. El laboratorio exige sesión,
endUserId configurado, attemptId no vacío y `approved` con código 9001.
Una verificación nula o un estado desconocido no aprueban. No deriva AML del
campo legacy `pepSanctionMatch`.

Existe una [consulta de decisión](https://devdocs.veriff.com/apidocs/v1sessionsiddecision-1)
para reconciliar resultados cuando faltan webhooks. Aquí el lector sigue
siendo una fixture: HMAC, permisos, forma completa de respuesta y asociaciones
de intentos necesitan validación de integración.

Para un requisito exclusivamente de edad, evaluar primero
[Age Validation](https://www.veriff.com/product/age-validation).
No inventamos su esquema API ni lo tratamos como KYC/AML completo.

### Lección de los verificadores de credenciales

El aprendizaje trasladado a `decision_log` es mantener cuerpos de credenciales,
adjuntos y diagnósticos arbitrarios fuera de los logs generales. La función
acepta un resultado limitado y valida sus valores. Esto no demuestra privacidad
de una wallet ni de un backend VC completo. El soporte de
[adjuntos de Extrimian](https://extrimian.io/es/verifiable-credentials-with-attachments-docs/)
no constituye por sí mismo un fallo: importa qué recibe y conserva cada rol.

## Dos experimentos, responsabilidades diferentes

`demo_minimizacion.py` conserva el proveedor, wallet y dos verificadores JWS.
Los atributos de edad y KYC siguen siendo una fixture positiva. Se amplía la
auditoría de los mismos 18 archivos a formatos codificados.

`demo_proveedores.py` usa una fuente simulada y dos consumidores locales por
perfil. No participa una wallet. Cada autorización solicita una nueva lectura,
verifica su asociación y proyecta el estado a una decisión mínima. Ambos
consumidores aprueban inicialmente y bloquean después de un cambio adverso,
incluso al recibir dos avisos positivos atrasados. Ante timeout tampoco usan
la aprobación inicial. Las transiciones son estímulos sintéticos; no hechos
observados en tráfico de proveedores.

| Dato | Dónde existe en este diseño | Qué se evita |
| --- | --- | --- |
| Documentos originales | Captura/custodia del proveedor en la primera demo | Pasarlos a wallet y presentación ordinaria del perfil simulado |
| Respuesta KYC completa | Memoria del transporte o fixture | Serializarla automáticamente en el resultado, log o excepción |
| Cliente, proceso, sesión, nivel | Configuración confiada del lector | Exponerlos en los logs mínimos del segundo experimento |
| Decisión y motivo acotado | Consumidor y observabilidad mínima | Usar comentarios de revisión o datos personales como motivo libre |
| Recibo anterior | Base local del primer experimento | Interpretarlo como permiso nuevo en el segundo |

Una entidad obligada puede necesitar identidad y evidencias, y un receptor de
reutilización puede recibir documentos. Esta versión no determina sus deberes
ni borra expedientes. La minimización en logs no equivale a borrado en APM,
proxy, cache, backups o soporte.

## Fronteras de confianza y resultados negativos

- `Binding`, política y función `fetch` provienen del servidor confiado del
  laboratorio. No deben construirse con parámetros libres del navegador.
- `Snapshot.observed_at` es metadato del lector, no un campo firmado del
  proveedor. Se rechaza si precede a la petición, está en el futuro, no es
  finito o la lectura supera su plazo. Esto **no detecta una respuesta antigua
  que el backend remoto vuelva a entregar con una observación local nueva**.
- El plazo de lectura de 5 segundos y los tiempos de fixtures son parámetros
  de ensayo, no una regla regulatoria. Caducidad del permiso, fecha del KYC,
  vigencia documental y actualización AML son conceptos distintos.
- `notify(authenticated=...)` recibe una autenticación simulada; no verifica
  firmas reales. Solo devuelve un evento mínimo. Nunca actualiza una aprobación.
  Un sistema real necesita autenticar eventos, reconciliar, controlar reintentos
  y revisar todos los caminos que conceden permisos.
- El gate devuelve una decisión local, no un token para autorizar dinero.
  Falta atomicidad entre leer y actuar, concurrencia distribuida y una política
  de consistencia. No se demuestra frescura continua después de la lectura.
- Consultar por acción introduce dependencias y puede facilitar correlación
  por el proveedor. No se midieron latencia, tarifas, rate limits o disponibilidad.
- La clave de emisor comprometida de la demo JWS todavía permite falsificar
  afirmaciones mientras sea confiada. Esta actualización no corrige ese riesgo.

## Pruebas y evidencia

La suite cuenta con 23 pruebas: cuatro regresiones existentes y 19 nuevas.
Incluye estados intermedios, corrección manual, entrada malformada, otra cuenta
o nivel, token de compartir usado como aprobación, caída, respuesta antigua,
reloj inválido, caducidad durante la lectura, notificación falsa, política o
audiencia sustituida y datos codificados. No son certificaciones de proveedores.

El usuario reportó en Windows la ejecución de `03b88ab`: las 23 pruebas
terminaron en OK en 2,607 segundos y ambas demos terminaron en PASS.
La evidencia procede de la consola compartida, con PowerShell 7.6.6; no incluye
la versión de Python, los archivos JSON producidos ni hashes del entorno local.
Se registra en `results/validacion_windows_v02_reportada_20261007.json`, sin
reemplazar el manifiesto de la ejecución Linux anterior. No se interpreta el
tiempo de la suite como latencia de proveedor ni como resultado productivo.

El segundo experimento ejecuta 18 controles funcionales y 24 lecturas simuladas
contadas en el lector. La referencia de caché es **un modelo explícito** que
conserva el booleano inicial; no es una API real ni una medición del comportamiento
completo de una integración ajena.

El control de logs inyecta tres canarios en un cuerpo Base64: búsqueda literal
0, búsqueda decodificada 3. Los logs mínimos contienen 0 de esos canarios. No
se presenta un porcentaje de mejora global de privacidad ni una reducción de
bytes de una operación KYC real.

El escáner cubre candidatos textuales Base64/Base64URL y segmentos JWT. Límites
por archivo: 1 MiB inspeccionado, tres niveles y 1024 nodos. Si alcanza un límite,
la auditoría no puede aprobar. El archivo se lee antes de limitar el escaneo:
esto sirve para los artefactos controlados de la demo, no para analizar archivos
enormes o adversariales con garantías de memoria. No descomprime, no descifra,
no hace OCR ni detecta toda PII desconocida. Las detecciones devuelven nombres
de marcadores, sin copiar sus valores en el reporte.

## Primer ensayo real y criterio de rechazo

Elegir **una** integración autorizada donde exista una copia concreta del
payload en logs. Obtener una muestra anonimizada y el contrato de observabilidad.
Sustituir solo esa copia por campos mínimos y ensayar aceptación, rechazo,
firma inválida, reintento y recuperación, sin cambiar el expediente legal.
Buscar los canarios también en exportaciones, APM y restauración de backups.

Rechazar el cambio si aparece un canario en un destino excluido, se pierde una
evidencia necesaria, cambia una decisión de negocio válida o deja de poder
investigarse un fallo. Para el gate de estados, validar después un lector real
de solo lectura y medir la ventana de desactualización y costo bajo los mismos
requisitos. Hasta entonces, las mejoras siguen siendo evidencia de laboratorio.
