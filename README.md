# KYC Minimal Disclosure Lab

Demostración educativa de minimización de datos KYC: un proveedor/emisor, una wallet y dos verificadores locales. **Solo laboratorio: KYC simulado, sin integración con proveedores reales y sin preparación para producción.**

![Ilustración educativa del flujo](docs/kyc-minimal-disclosure.png)

La imagen es conceptual. En la demo, **ambos servicios** verifican mayoría de edad y KYC vigente.

## Qué demuestra

- Documentos y datos ficticios se inyectan en la captura del proveedor.
- El emisor entrega constancias JWT/JWS diferentes por audiencia, vinculadas a claves holder distintas.
- A y B verifican firma, emisor, expiración, atributos, política, audiencia, nonce y contexto.
- SQLite conserva un recibo transaccional que permite recuperar una decisión después de perder su respuesta.
- El laboratorio inspecciona archivos controlados, logs, cache, backups y restauración para buscar marcadores documentales.

La captura ficticia **no verifica autenticidad documental, vida, rostro ni identidad humana**. Los atributos positivos son una fixture. El perfil JWT usa claims privados: no implementa SD-JWT VC ni conformidad OpenID4VCI/OpenID4VP.

## Ejecutar

Entorno probado: Python 3.12.14, PyJWT 2.10.1, cryptography 46.0.0. Las versiones están fijadas para reproducibilidad; no son una selección productiva.

```bash
python -m venv .venv
```

En Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

En Linux/macOS:

```bash
source .venv/bin/activate
```

```bash
python -m pip install -r requirements.txt
python demo_minimizacion.py
```

Resultado esperado de la ejecución de referencia:

```text
PASS 18 archivos auditados; 21 controles JWS
```

El script produce `resultado_minimizacion.json` en la carpeta del código. Los archivos inspeccionados y las claves de la fixture son temporales; el resultado conserva rutas, tamaños, hashes y detecciones. La ejecución publicada está en `results/resultado_minimizacion_20261007.json`.

Para ejecutar solo los controles criptográficos de componentes:

```bash
python reference_jws.py
```

## Archivos

| Archivo | Función |
| --- | --- |
| `demo_minimizacion.py` | Captura ficticia, dos presentaciones, auditoría y restore |
| `reference_jws.py` | Referencia de componentes JWS, binding y recibos |
| `PCN_Minimo_Educativo.html` | Explicación y matriz para abrir localmente |
| `matriz_minimizacion.json` | Propuesta de datos y responsabilidades, sin aceptación del integrador |
| `results/resultado_minimizacion_20261007.json` | Evidencia sintética de una ejecución |
| `docs/kyc-minimal-disclosure.png` | Ilustración conceptual generada con IA |

## Límites y resultados negativos

- **Una clave de emisor robada y todavía confiada puede emitir afirmaciones falsas aceptadas.** Una de las pruebas PASS reproduce deliberadamente ese contraejemplo; PASS no significa que el riesgo esté resuelto.
- La autoridad y sus cambios de clave son fixtures en memoria. No hay custodia independiente ni recuperación productiva de autoridad o wallet.
- Los dos verificadores se ejecutan en el mismo proceso, con bases separadas. No son organizaciones independientes desplegadas.
- El emisor puede correlacionar las constancias. Diferentes claves por servicio no demuestran anonimato total.
- La ausencia de marcadores literales en 18 archivos no demuestra ausencia de filtraciones en memoria, red, dumps, transformaciones, soporte externo u otros sistemas.
- La respuesta perdida se simula **después del commit**. El caso de respuesta del proveedor perdida antes del commit sigue pendiente.
- Se restaura un recibo SQLite. No se prueba recuperación integral ante rollback adversarial, pérdida de todas las réplicas ni eliminación física de backups.
- La comparación de tres ubicaciones documentales convencionales frente a una es un modelo sintético, no una medición de un integrador real.
- Si una entidad obligada debe identificar al cliente o conservar/acceder a evidencias, estas afirmaciones no la eximen.

## Próximo experimento

Acordar con un integrador qué datos necesita, para qué finalidad, quién conserva evidencias, los plazos y el acceso legal. Comparar flujo convencional y mínimo bajo los mismos requisitos, con proveedor auténtico, dos backends, revocación, compromiso de claves, recuperación persistente y auditoría de todos los canales.

Este repositorio contiene únicamente la demo de laboratorio y sus materiales educativos; no incorpora el repositorio ni la investigación privada de PCN.
