# Gestión de un incidente de ciberseguridad

**Trabajo práctico · Apartados 1 a 3:** Prevención y concienciación · Detección y auditoría · Investigación y análisis forense

> **Caso:** empresa de ~100 empleados, infraestructura híbrida (Ubuntu Server y Windows Server con Directorio Activo), sin procedimientos formales de prevención ni de respuesta. Incidente de phishing con ejecución de un adjunto malicioso y sospecha de exfiltración de datos de clientes.

**Autor/a:** _(nombre)_ · **Fecha:** _(fecha)_ · **Rol:** responsable del equipo de ciberseguridad

---

## Índice

1. [Prevención y concienciación](#1-prevención-y-concienciación)
2. [Detección y auditoría](#2-detección-y-auditoría)
3. [Investigación y análisis forense](#3-investigación-y-análisis-forense)

---

# 1. Prevención y concienciación

> **Caso:** empresa de ~100 empleados, infraestructura híbrida (Ubuntu Server y Windows Server con Directorio Activo), sin procedimientos formales de prevención ni de respuesta. Incidente de phishing con ejecución de un adjunto malicioso y sospecha de exfiltración de datos de clientes.

## 1.1 Principales riesgos y amenazas

Se sigue la lógica de MAGERIT v3 / ISO 27005: activo → amenaza → vulnerabilidad → riesgo (probabilidad × impacto, escala 1-5).

| ID | Activo | Amenaza | Vulnerabilidad en la empresa | P | I | Riesgo | Tratamiento |
|---|---|---|---|:-:|:-:|:-:|---|
| R1 | Puestos de trabajo | Phishing con adjunto malicioso | Usuarios sin formación; sin filtrado de adjuntos ejecutables | 5 | 4 | 20 · Crítico | Mitigar: formación, filtro de correo, EDR |
| R2 | Servidores de ficheros | Acceso a carpetas compartidas con cuenta comprometida | Permisos amplios, sin MFA, sin mínimo privilegio | 4 | 5 | 20 · Crítico | Mitigar: permisos por rol, MFA, LAPS |
| R3 | Datos personales de clientes | Exfiltración | Sin DLP, sin control de salida, sin segmentación | 4 | 5 | 20 · Crítico | Mitigar: segmentación, filtrado egress, monitorización |
| R4 | Directorio Activo | Escalada de privilegios y movimiento lateral | Cuentas de administración compartidas, sin tiering | 3 | 5 | 15 · Crítico | Mitigar: modelo de administración por niveles |
| R5 | Copias de seguridad | Ransomware que cifra también las copias | Copias en la misma red, sin copia inmutable | 3 | 5 | 15 · Crítico | Mitigar: regla 3-2-1 con copia offline |
| R6 | Sistemas Windows/Linux | Explotación de vulnerabilidades conocidas | Sin política de parches | 3 | 4 | 12 · Alto | Mitigar: parcheo por criticidad |
| R7 | Organización | Falta de respuesta coordinada | Sin procedimiento de incidentes ni contactos | 4 | 4 | 16 · Crítico | Mitigar: plan de respuesta (apartados 4-6) |
| R8 | Cumplimiento | Sanción por brecha no notificada | Sin protocolo RGPD de brechas | 3 | 4 | 12 · Alto | Mitigar: protocolo de notificación (apartado 5) |

**Niveles:** Crítico 15-25 · Alto 10-14 · Medio 5-9 · Bajo 1-4.

> 📸 **[CAPTURA 1.1]** Inventario de activos obtenido en el laboratorio (`nmap -sV 192.168.1.0/24`, `ss -tulpn`, `Get-NetTCPConnection -State Listen`).

## 1.2 Normas de seguridad para los puestos de trabajo

Base: CIS Controls v8.1 (grupo IG1) y medidas del ENS como referencia.

| Ámbito | Norma | Control de referencia |
|---|---|---|
| Cuentas | Cuenta personal e intransferible; los usuarios no son administradores locales (mínimo privilegio). | CIS 5, 6 |
| Autenticación | Contraseñas de 14+ caracteres, comprobadas contra listas filtradas; MFA obligatorio en VPN, correo y cuentas de administración. | CIS 5, 6 |
| Administradores | Contraseña de administrador local única por equipo (Windows LAPS); cuentas de administración separadas de las de uso diario. | CIS 5 |
| Software | Solo software autorizado; sin instalación por parte del usuario; macros de Office bloqueadas por defecto en archivos de Internet. | CIS 2 |
| Actualizaciones | SO y aplicaciones parcheados: críticos en 72 h, altos en 15 días, resto mensual. | CIS 7 |
| Antimalware/EDR | Instalado, activo y no desactivable por el usuario. | CIS 10 |
| Dispositivos | USB bloqueado salvo autorización; cifrado de disco (BitLocker / LUKS). | CIS 3, 4 |
| Pantalla y sesión | Bloqueo automático a los 5-10 minutos. | CIS 4 |
| Correo | Adjuntos ejecutables (`.exe`, `.js`, `.vbs`, `.iso`, `.lnk`…) bloqueados; avisos de «remitente externo»; SPF, DKIM y DMARC configurados. | CIS 9 |
| Datos | Información de clientes solo en servidores autorizados; prohibido enviarla a cuentas personales o nubes no corporativas. | CIS 3 |
| Notificación | Todo correo sospechoso se reporta con un botón/buzón único; no se borra ni se reenvía. | CIS 14 |

Ejemplo aplicable en el laboratorio (Windows, PowerShell):

```powershell
# Bloquear macros... se hace por GPO; aquí se verifica el bloqueo de USB y el estado de Defender
Get-MpComputerStatus | Select AMServiceEnabled, RealTimeProtectionEnabled
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name Start   # 4 = deshabilitado
```

![[captura_1_2.png]]

> 📸 **[CAPTURA 1.2]** Salida de los comandos anteriores y/o directiva de grupo aplicada.

## 1.3 Plan de formación y concienciación

| Fase | Público | Contenido | Formato | Duración | Indicador |
|---|---|---|---|---|---|
| 0. Evaluación inicial | Todos | Campaña de phishing simulado (línea base) | Simulación controlada | 1 semana | % que hace clic / reporta |
| 1. Sesión general | Todos | Phishing, contraseñas y MFA, datos personales, cómo reportar | Presentación + demo, 45 min | Mes 1 | Asistencia ≥ 95 % |
| 2. Roles de riesgo | RR. HH., finanzas, dirección, administradores | Fraude del CEO, suplantación de RR. HH., BEC, gestión de privilegios | Taller práctico, 60 min | Mes 2 | Evaluación superada |
| 3. Microformación | Todos | Píldoras de 5 min sobre casos reales | Correo/intranet mensual | Continuo | Participación |
| 4. Simulacros | Todos | Phishing simulado trimestral | Plataforma de simulación | Trimestral | Tasa de clics ↓, reportes ↑ |
| 5. Incorporaciones | Nuevos empleados | Módulo básico el primer día | Presencial/online | Continuo | 100 % de altas |

**Métricas objetivo:** tasa de clic en simulacros < 5 % en 12 meses; tasa de reporte > 60 %; tiempo medio de reporte < 15 min.

**Principio de cultura:** cultura sin culpa; quien reporta pronto ayuda, no es sancionado.

### Contenido del cartel «No muerdas el anzuelo» (phishing)

> **TÍTULO:** ¿Te ha llegado un correo raro? **Párate. Piensa. Reporta.**
>
> **Señales de alarma**
> 1. 🕵️ **Remitente:** el nombre parece conocido, pero el dominio no coincide (`rrhh@empresa-rrhh.co` ≠ `@empresa.com`).
> 2. ⏰ **Urgencia o amenaza:** «hoy o pierdes tu nómina».
> 3. 📎 **Adjunto inesperado:** `.zip`, `.iso`, `.html`, documento que pide «habilitar contenido/macros».
> 4. 🔗 **Enlace sospechoso:** pasa el ratón y mira la URL real antes de hacer clic.
> 5. 🔑 **Te piden credenciales o datos:** RR. HH. nunca los pide por correo.
> 6. ✍️ **Saludo genérico y errores** de redacción.
>
> **Qué hacer:** ❌ No abras · ❌ No hagas clic · ❌ No reenvíes · ✅ **Pulsa «Reportar phishing»** o escribe a `seguridad@empresa.com` · 📞 Ext. **XXXX** (Informática).
>
> **Si ya has hecho clic:** desconecta el cable/Wi-Fi, **no apagues el equipo** y llama a Informática de inmediato.

![[captura_1_3.png]]

> 📸 **[CAPTURA 1.3]** Cartel maquetado (PDF/PNG) a partir del texto anterior.

### Guía rápida de buenas prácticas

| Tema | Haz | Evita |
|---|---|---|
| Contraseñas | Frases largas únicas por servicio; gestor de contraseñas; MFA | Reutilizarlas; apuntarlas en notas visibles |
| Correo | Verificar remitente por otro canal si hay dinero/datos de por medio | Abrir adjuntos inesperados |
| Equipo | Bloquear con `Win+L` al levantarte; aceptar actualizaciones | Desactivar el antivirus; instalar software no autorizado |
| Datos | Guardar en los servidores corporativos | Enviar datos de clientes a correos personales o USB |
| Teletrabajo | Usar la VPN corporativa; Wi-Fi doméstica protegida | Redes públicas sin VPN |
| Incidentes | Reportar enseguida; desconectar de la red sin apagar | Intentar «arreglarlo» solo o ocultarlo |

## 1.4 Fundamentos criptográficos aplicados

### 1.4.1 Cifrado simétrico

Una única clave cifra y descifra. Es rápido y adecuado para grandes volúmenes (discos, ficheros, canal TLS ya establecido). Problema: cómo compartir la clave de forma segura.

- Algoritmo de referencia: **AES** (128/256 bits), en modo autenticado (**AES-GCM**).
- Uso en la empresa: BitLocker/LUKS en discos, copias de seguridad cifradas, datos en tránsito.

```bash
# Cifrar y descifrar un fichero con AES-256 (Ubuntu)
openssl enc -aes-256-cbc -pbkdf2 -salt -in clientes.csv -out clientes.csv.enc
openssl enc -d -aes-256-cbc -pbkdf2 -in clientes.csv.enc -out clientes_descifrado.csv
```

> 📸 **[CAPTURA 1.4]** Cifrado y descifrado del fichero de prueba (datos ficticios).

### 1.4.2 Cifrado asimétrico

Par de claves: la **pública** se distribuye; la **privada** se custodia. Lo cifrado con una solo se descifra con la otra. Es más lento: se usa para intercambiar claves y firmar, no para datos masivos.

- Algoritmos: **RSA** (≥ 2048 bits, recomendable 3072), **ECC** (curvas P-256, Ed25519).
- Usos: confidencialidad (cifrar con la pública del receptor) y autenticidad (firmar con la privada del emisor).

```bash
openssl genrsa -out privada.pem 3072
openssl rsa -in privada.pem -pubout -out publica.pem
echo "dato confidencial" > msg.txt
openssl pkeyutl -encrypt -pubin -inkey publica.pem -in msg.txt -out msg.enc
openssl pkeyutl -decrypt -inkey privada.pem -in msg.enc
```

### 1.4.3 Comparativa

| Característica | Simétrico | Asimétrico |
|---|---|---|
| Claves | 1 compartida | Par público/privado |
| Velocidad | Muy alta | Baja |
| Distribución de claves | Difícil | Resuelta (clave pública) |
| Servicios | Confidencialidad | Confidencialidad, autenticidad, no repudio |
| Ejemplos | AES, ChaCha20 | RSA, ECDSA, Ed25519 |

**Cifrado híbrido:** se usa asimétrico (o Diffie-Hellman) para acordar una clave de sesión y simétrico para los datos. Es lo que hace TLS.

### 1.4.4 Funciones hash (SHA-256)

Función unidireccional que convierte cualquier entrada en una huella de tamaño fijo (256 bits). Propiedades: determinista, resistente a preimagen, a segunda preimagen y a colisiones, y con efecto avalancha (un bit distinto cambia la huella por completo).

Usos: **integridad de ficheros**, almacenamiento de contraseñas (con sal y algoritmo lento como Argon2/bcrypt, no SHA-256 a secas), firmas, **evidencias forenses** (apartado 3).

```bash
sha256sum fichero.pdf
echo -n "hola" | sha256sum
echo -n "Hola" | sha256sum        # efecto avalancha
```
```powershell
Get-FileHash .\fichero.pdf -Algorithm SHA256
```

> 📸 **[CAPTURA 1.5]** Hash de un fichero antes y después de modificar un carácter.

### 1.4.5 Certificados digitales y PKI

Un **certificado X.509** vincula una clave pública a una identidad (sujeto), con validez, uso permitido y la firma de una **Autoridad de Certificación (CA)**.

**PKI (Public Key Infrastructure):** conjunto de CA raíz y subordinadas, Autoridad de Registro (RA), repositorios, y mecanismos de revocación (CRL, OCSP). Validación: el navegador comprueba la cadena hasta una CA raíz de confianza, la vigencia, el nombre y que no esté revocado.

En la empresa: certificados TLS para servicios web internos/externos, autenticación de clientes VPN, firma de correo (S/MIME) y AD CS en Windows Server.

```bash
openssl s_client -connect www.incibe.es:443 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

> 📸 **[CAPTURA 1.6]** Cadena de certificación de un sitio (navegador o `openssl`).

### 1.4.6 Firma electrónica

Se calcula el hash del documento y se cifra con la **clave privada** del firmante; el receptor lo verifica con la **clave pública** (certificado). Garantiza **integridad, autenticidad y no repudio**.

```bash
openssl dgst -sha256 -sign privada.pem -out firma.bin documento.pdf
openssl dgst -sha256 -verify publica.pem -signature firma.bin documento.pdf   # Verified OK
```

Marco legal europeo: Reglamento (UE) 910/2014 (eIDAS) y su revisión (UE) 2024/1183; en España, Ley 6/2020 de servicios electrónicos de confianza. Tipos: simple, avanzada y cualificada (equivalente legal a la manuscrita).

### 1.4.7 Diffie-Hellman

Permite que dos partes acuerden un **secreto compartido** por un canal inseguro sin transmitirlo. Se basa en la dificultad del logaritmo discreto.

**Ejemplo didáctico** (números pequeños; en la práctica se usan grupos de 2048+ bits o curvas, ECDH/X25519):

| Paso | Alicia | Bob |
|---|---|---|
| Públicos | p = 23, g = 5 | p = 23, g = 5 |
| Secreto privado | a = 6 | b = 15 |
| Calcula y envía | A = 5⁶ mod 23 = **8** | B = 5¹⁵ mod 23 = **19** |
| Secreto compartido | 19⁶ mod 23 = **2** | 8¹⁵ mod 23 = **2** |

Un atacante que vea p, g, 8 y 19 no puede obtener 2 con facilidad si los números son grandes. **Limitación:** DH sin autenticación es vulnerable a *man-in-the-middle*; por eso en TLS va ligado a certificados/firmas. Con claves efímeras (DHE/ECDHE) se logra **Perfect Forward Secrecy**.

### 1.4.8 Cómo se combina todo (ejemplo TLS)

1. El servidor presenta su **certificado** (PKI) y el cliente valida la cadena.
2. Se acuerda una clave de sesión con **ECDHE** (Diffie-Hellman), autenticada con la **firma** del servidor.
3. Los datos viajan cifrados con **AES-GCM** (simétrico) y con integridad garantizada (hash/AEAD).

```bash
openssl s_client -connect www.incibe.es:443 -tls1_3 </dev/null 2>/dev/null | grep -E "Protocol|Cipher|Server Temp Key"
```

> 📸 **[CAPTURA 1.7]** Protocolo, suite de cifrado e intercambio de claves negociados.

## 1.5 Relación con el incidente

| Fallo preventivo | Medida de este apartado |
|---|---|
| Un usuario abrió y ejecutó el adjunto | Formación, simulacros, bloqueo de ejecutables y macros |
| Acceso a carpetas compartidas | Mínimo privilegio, LAPS, MFA |
| Posible exfiltración de datos | Cifrado de datos, segmentación, control de salida |
| Nadie sabía a quién avisar | Botón de reporte y canal único |

## 1.6 Fuentes y referencias

- INCIBE – Protege tu empresa / catálogo de guías y plantillas de políticas: https://www.incibe.es
- INCIBE – Servicio de ciberseguridad 017 (línea de ayuda): https://www.incibe.es
- CCN-CERT – Guías CCN-STIC y herramientas CLARA, PILAR: https://www.ccn-cert.cni.es
- MAGERIT v3 – Portal de Administración Electrónica: https://administracionelectronica.gob.es
- Real Decreto 311/2022 (ENS): https://www.boe.es
- CIS Controls v8.1 y CIS Benchmarks: https://www.cisecurity.org
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST FIPS 180-4 (SHA-2) y FIPS 197 (AES): https://csrc.nist.gov
- NIST SP 800-63B (autenticación y contraseñas): https://pages.nist.gov/800-63-4/
- RFC 5280 (X.509), RFC 8446 (TLS 1.3), RFC 7748 (X25519), RFC 8017 (RSA)
- Reglamento (UE) 910/2014 y 2024/1183 (eIDAS): https://eur-lex.europa.eu

> ⚠️ **Antes de entregar:** comprueba que cada enlace sigue activo y sustituye los enlaces generales por la página concreta de cada guía que cites, con fecha de consulta.


---

# 2. Detección y auditoría

> **Aviso sobre los datos:** las IP, dominios, hashes y nombres de equipo de este apartado son **ficticios** (rangos de documentación `203.0.113.0/24`, `198.51.100.0/24` y dominios `.example`). Sustitúyelos por los de tu laboratorio. Los indicadores se escriben «defangeados» (`hxxp`, `[.]`) para evitar clics accidentales.

## 2.1 Clasificación del incidente y gravedad

### Clasificación por taxonomía

La Guía Nacional de Notificación y Gestión de Ciberincidentes (INCIBE, CCN-CERT y otros organismos) clasifica cada incidente por **tipo** y por **nivel de peligrosidad e impacto**. Este caso combina varios tipos:

| Fase | Tipo (taxonomía de la guía) | Evidencia |
|---|---|---|
| Entrada | **Fraude → phishing** | Correo falso de RR. HH. a varios empleados |
| Ejecución | **Código dañino** | Un usuario ejecutó un archivo malicioso; alertas del antivirus |
| Acceso | **Intrusión** (compromiso de cuenta/equipo) | Intentos de acceso a carpetas compartidas |
| Salida | **Compromiso de la información → exfiltración** (sospecha) | Conexiones hacia IP externas |

Como referencia complementaria se mapean las técnicas a **MITRE ATT&CK**:

| Táctica | Técnica probable | ID |
|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Command and Control | Application Layer Protocol (HTTPS) | T1071.001 |
| Discovery | Network Share Discovery | T1135 |
| Collection / Exfiltration | Exfiltration Over C2 Channel | T1041 |

*(Son hipótesis a validar con la investigación del apartado 3.)*

### Nivel de gravedad: **CRÍTICO** (provisional)

| Criterio | Valoración | Razón |
|---|---|---|
| Peligrosidad | Alta | Malware con comunicación activa con el exterior |
| Impacto en confidencialidad | Alto | Posible fuga de datos personales de clientes |
| Impacto en integridad | Medio | Sin evidencia aún de modificación de datos |
| Impacto en disponibilidad | Bajo (por ahora) | Servicios operativos |
| Extensión | Por determinar | Varios destinatarios del correo, un equipo confirmado |
| Implicación legal | Alta | Posible brecha de datos personales (RGPD) |

Se aplica el criterio de la guía: **el nivel más alto entre peligrosidad e impacto marca los plazos**. Se clasifica como **Crítico** hasta que se descarte la exfiltración; si se descartara, bajaría a **Alto**. Prioridad ITIL equivalente: **P1** (respuesta inmediata).

> 📝 Revisa en la versión vigente de la guía la tabla exacta de niveles y plazos antes de citarla.

## 2.2 Sistemas y servicios afectados

| Activo | Estado | Motivo | Acción de verificación |
|---|---|---|---|
| Estación del usuario que ejecutó el adjunto | **Comprometido (confirmado)** | Ejecución del archivo, alertas AV | Triaje y aislamiento |
| Estaciones de otros destinatarios | **En riesgo** | Recibieron el mismo correo | Buscar el mensaje, adjunto y clics |
| Servidor de ficheros (Windows) | **Sospechoso** | Intentos de acceso a recursos compartidos | Revisar eventos 5140/5145 y 4625 |
| Controlador de dominio (AD) | **En riesgo** | Si hubo robo de credenciales o enumeración | Revisar 4624, 4672, 4769, 4768 |
| Cuenta del usuario afectado | **Comprometida (presunto)** | Sesión activa durante la ejecución | Forzar cierre de sesión y restablecer |
| Servidor web/Linux | **En riesgo bajo** | Misma red plana | Revisar `auth.log`, `ss`, conexiones salientes |
| Pasarela de correo | **Origen** | Entrega del phishing | Trazar y purgar mensajes |
| Cortafuegos / proxy | **Fuente de evidencia** | Registra las conexiones salientes | Exportar logs |
| Copias de seguridad | **En riesgo** | Si están accesibles desde la red | Verificar aislamiento |
| Datos de clientes | **Posiblemente exfiltrados** | Acceso a carpetas con datos personales | Determinar qué ficheros se tocaron |

## 2.3 Herramientas de detección y monitorización

| Capa | Herramienta | Qué aporta | Licencia |
|---|---|---|---|
| SIEM / XDR | **Wazuh** | Correlación de logs, FIM, evaluación de configuración (SCA), detección en endpoints Windows/Linux | Libre |
| Telemetría Windows | **Sysmon** (+ configuración SwiftOnSecurity o Olaf Hartong) | Creación de procesos, conexiones de red, hashes, consultas DNS | Gratuita |
| EDR/antivirus | **Microsoft Defender for Endpoint** u otro EDR | Detección de comportamiento, aislamiento remoto del equipo | Comercial |
| Red | **Wireshark / tshark** | Captura y análisis de paquetes | Libre |
| Red | **Zeek** o **Suricata** | Metadatos de conexión, DNS, TLS; reglas IDS | Libre |
| Linux | **auditd**, `journalctl`, `ss`, `lsof` | Auditoría de llamadas y conexiones | Libre |
| Triaje | **Velociraptor** o **KAPE** | Recolección remota de artefactos | Libre / gratuita |
| Inteligencia | **MISP**, VirusTotal, AbuseIPDB | Enriquecimiento de IoC | Libre / gratuita |
| Correo | Cabeceras + sandbox (ANY.RUN, Hybrid Analysis, Cuckoo/CAPE) | Análisis del adjunto | Gratuita / libre |
| Gestión | **GLPI / DFIR-IRIS / TheHive** | Registro del caso y tareas | Libre |

### Reglas y consultas de detección de ejemplo

```text
# Wazuh / SIEM: ideas de reglas
- Proceso hijo sospechoso de Office (WINWORD.EXE/EXCEL.EXE → cmd.exe/powershell.exe/wscript.exe)
- Ejecución desde %TEMP%, %APPDATA% o Downloads
- Conexión saliente de proceso no habitual (no navegador) a IP sin dominio
- Más de N fallos 4625 seguidos de un 4624 (fuerza bruta con éxito)
- Acceso masivo a recursos compartidos desde un solo equipo en poco tiempo
- Volumen de salida anómalo hacia una misma IP externa
```

> 📸 **[CAPTURA 2.1]** Dashboard de Wazuh (o SIEM equivalente) con alertas del agente de prueba.

## 2.4 Registros que se consultan

### 2.4.1 Antivirus / EDR

| Dónde | Qué buscar |
|---|---|
| Consola Defender / EDR | Nombre de la amenaza, ruta, hash, acción realizada (bloqueada/en cuarentena/permitida), usuario, hora |
| Visor de eventos → `Microsoft-Windows-Windows Defender/Operational` | **1116** (detección), **1117** (acción tomada), **5001** (protección en tiempo real desactivada) |

```powershell
Get-MpThreatDetection | Select InitialDetectionTime, ProcessName, Resources, ThreatID
Get-MpThreat
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,5001} | Select TimeCreated,Id,Message -First 20
```

### 2.4.2 Sistema operativo Windows

| Event ID | Registro | Significado | Uso en el caso |
|---|---|---|---|
| 4624 / 4625 | Security | Inicio de sesión correcto / fallido | Movimiento lateral, fuerza bruta |
| 4648 | Security | Inicio de sesión con credenciales explícitas | Uso de credenciales robadas |
| 4672 | Security | Privilegios especiales asignados | Cuentas administradoras |
| 4688 | Security | Creación de proceso (con línea de comandos si se activa) | Ejecución del adjunto |
| 4698 | Security | Tarea programada creada | Persistencia |
| 4720 / 4732 | Security | Cuenta creada / añadida a grupo | Persistencia, escalada |
| 5140 / 5145 | Security | Acceso a recurso compartido / objeto de red | Acceso a carpetas de clientes |
| 7045 | System | Servicio instalado | Persistencia |
| 4104 | PowerShell/Operational | Bloque de script | PowerShell malicioso |
| Sysmon 1 / 3 / 11 / 22 | Sysmon/Operational | Proceso / conexión / fichero creado / DNS | Cadena de ejecución y C2 |

```powershell
# Procesos creados en las últimas 24 h (requiere auditoría 4688 habilitada)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-1)} |
  Select TimeCreated, @{n='Proc';e={$_.Properties[5].Value}}, @{n='Padre';e={$_.Properties[13].Value}} -First 50

# Fallos de autenticación
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} | Group-Object {$_.Properties[19].Value} | Sort Count -Desc

# Conexiones activas con el proceso propietario
Get-NetTCPConnection -State Established |
  Select LocalPort, RemoteAddress, RemotePort, @{n='Proceso';e={(Get-Process -Id $_.OwningProcess).Name}}
```

> 📸 **[CAPTURA 2.2]** Visor de eventos con el 4688/Sysmon 1 del proceso malicioso.
> 📸 **[CAPTURA 2.3]** Salida de `Get-NetTCPConnection` mostrando la conexión a la IP externa.

### 2.4.3 Sistema operativo Linux

```bash
# Autenticación (Ubuntu)
sudo grep -E "Failed password|Accepted|sudo:" /var/log/auth.log | tail -50
sudo journalctl -u ssh --since "24 hours ago"

# Conexiones y procesos
sudo ss -tupn state established
sudo lsof -i -P -n | grep ESTABLISHED

# Persistencia y cambios recientes
sudo crontab -l; ls -la /etc/cron.*; systemctl list-unit-files --state=enabled
sudo find / -xdev -type f -mtime -2 -not -path "/proc/*" 2>/dev/null | head -50
last -a | head; lastb | head
```

> 📸 **[CAPTURA 2.4]** Salida de `ss -tupn` y `auth.log` en el servidor Linux.

### 2.4.4 Cortafuegos / proxy

| Qué buscar | Ejemplo |
|---|---|
| Conexiones salientes desde el equipo afectado | Origen = IP del equipo, destino externo, puertos y bytes |
| Destinos repetidos a intervalos regulares | Posible balizamiento (*beaconing*) |
| Volumen de salida inusual | Bytes enviados >> recibidos |
| Puertos no habituales | 4444, 8080, 8443, 53 con volumen alto (túnel DNS) |
| Horas atípicas | Actividad fuera del horario laboral |

```bash
# Si el cortafuegos es Linux con ufw/iptables
sudo grep "UFW BLOCK" /var/log/ufw.log | tail
sudo journalctl -k | grep -i "DST=203.0.113.45"
```

### 2.4.5 Tráfico de red

```bash
# Captura filtrada del equipo afectado
sudo tcpdump -i eth0 host 192.168.1.50 -w captura_equipo.pcap

# Análisis con tshark
tshark -r captura_equipo.pcap -q -z conv,tcp                       # conversaciones TCP
tshark -r captura_equipo.pcap -Y "dns" -T fields -e frame.time -e dns.qry.name | sort | uniq -c | sort -rn | head
tshark -r captura_equipo.pcap -Y "tls.handshake.type==1" -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

> 📸 **[CAPTURA 2.5]** Wireshark/tshark con las conexiones al destino sospechoso.

## 2.5 Investigación OSINT de IP y dominios

> Solo fuentes abiertas y pasivas. **No** se escanea, ataca ni se interactúa con la infraestructura del atacante. Para URL sospechosas se usan servicios de análisis (urlscan.io, VirusTotal), no el navegador corporativo.

### IoC del caso (ficticios)

| Tipo | Valor (defangeado) |
|---|---|
| IP | `203[.]0[.]113[.]45` |
| Dominio | `rrhh-empresa-portal[.]example` |
| URL | `hxxps://rrhh-empresa-portal[.]example/nomina.zip` |
| SHA-256 adjunto | *(se calcula en el apartado 3)* |

### Fuentes y técnica

| Fuente | Qué aporta |
|---|---|
| **WHOIS / RDAP** | Registrador, fecha de creación (dominios recientes = sospechosos), contacto |
| **VirusTotal** | Reputación de IP/dominio/hash; relaciones |
| **AbuseIPDB** | Reportes de abuso de la IP |
| **urlscan.io** | Captura y análisis seguro de una URL |
| **Shodan / Censys** | Servicios expuestos en la IP, certificados |
| **crt.sh** | Certificados emitidos para el dominio (Certificate Transparency) |
| **AlienVault OTX, Cisco Talos** | Inteligencia de amenazas |
| **ASN (bgp.he.net)** | Proveedor y rango de red |
| **DNS histórico (SecurityTrails, passive DNS)** | Resoluciones previas, infraestructura asociada |

```bash
whois 203.0.113.45
whois rrhh-empresa-portal.example
dig +short rrhh-empresa-portal.example A
dig +short rrhh-empresa-portal.example MX TXT
curl -s https://rdap.org/ip/203.0.113.45 | head -50
```

### Plantilla de resultados OSINT

| Indicador | Fuente | Resultado | Conclusión |
|---|---|---|---|
| 203.0.113.45 | VirusTotal | *X/Y motores lo marcan como malicioso* | Reputación negativa |
| 203.0.113.45 | AbuseIPDB | *N reportes, categorías…* | Infraestructura de C2 probable |
| Dominio | WHOIS | *Creado hace N días, registrador…* | Dominio recién registrado |
| Dominio | crt.sh | *Certificado emitido el…* | Preparado para la campaña |

> 📸 **[CAPTURA 2.6]** Resultado de VirusTotal/AbuseIPDB para la IP del laboratorio y salida de `whois`.

**Acciones derivadas:** bloquear IP y dominio en cortafuegos/DNS/proxy, buscar otros equipos que los hayan contactado y compartir IoC con el CSIRT (apartado 5).

## 2.6 Ficha de registro del incidente

**Código:** INC-2026-0001 · **Versión:** 1.0 · **Confidencialidad:** TLP:AMBER

### A. Datos generales

| Campo | Valor |
|---|---|
| Fecha y hora de detección | AAAA-MM-DD hh:mm (zona horaria) |
| Detectado por | Nombre / sistema (AV, SIEM, usuario) |
| Notificado por | |
| Responsable del incidente | |
| Equipo de respuesta | |
| Estado | ☐ Abierto ☐ En contención ☐ Erradicado ☐ Recuperado ☐ Cerrado |

### B. Clasificación

| Campo | Valor |
|---|---|
| Tipo (taxonomía) | Fraude (phishing) · Código dañino · Intrusión · Compromiso de la información |
| Nivel de peligrosidad | ☐ Bajo ☐ Medio ☐ Alto ☐ Muy alto ☐ Crítico |
| Nivel de impacto | ☐ Bajo ☐ Medio ☐ Alto ☐ Muy alto ☐ Crítico |
| Prioridad | ☐ P1 ☐ P2 ☐ P3 ☐ P4 |
| ¿Datos personales afectados? | ☐ Sí ☐ No ☐ Por determinar |
| Dimensiones afectadas | ☐ C ☐ I ☐ D ☐ A ☐ T |

### C. Descripción y alcance

| Campo | Valor |
|---|---|
| Resumen del incidente | |
| Vector de entrada | |
| Sistemas afectados (nombre, IP, SO, rol) | |
| Usuarios/cuentas afectados | |
| Servicios afectados | |
| Datos potencialmente afectados (tipo y nº de registros) | |

### D. Indicadores de compromiso

| Tipo | Valor | Fuente | Fecha |
|---|---|---|---|
| IP | | | |
| Dominio/URL | | | |
| Hash (SHA-256) | | | |
| Cuenta | | | |

### E. Cronología (bitácora)

| Fecha-hora | Acción / hecho | Autor | Evidencia asociada |
|---|---|---|---|
| | | | |

### F. Acciones realizadas

| Contención | Erradicación | Recuperación | Responsable | Fecha |
|---|---|---|---|---|
| | | | | |

### G. Notificaciones

| Destinatario | ¿Procede? | Fecha-hora | Responsable | Referencia |
|---|---|---|---|---|
| Dirección | | | | |
| INCIBE-CERT / CCN-CERT | | | | |
| AEPD (≤ 72 h desde que se tuvo conocimiento) | | | | |
| Afectados | | | | |
| Fuerzas y Cuerpos de Seguridad | | | | |

### H. Cierre y lecciones aprendidas

| Causa raíz | Medidas correctivas | Fecha de revisión | Aprobado por |
|---|---|---|---|
| | | | |

> 📸 **[CAPTURA 2.7]** Ficha cumplimentada con los datos del laboratorio (o ticket en GLPI/DFIR-IRIS).

## 2.7 Auditoría de la situación actual

Además de detectar, se audita el estado del bastionado para saber por qué el ataque tuvo éxito.

| Comprobación | Herramienta | Comando |
|---|---|---|
| Hardening Linux | Lynis | `sudo lynis audit system` |
| Cumplimiento Windows | OSConfig / CIS-CAT Lite | Ver guía CIS Benchmark |
| Salud del Directorio Activo | PingCastle | `PingCastle.exe --healthcheck` |
| Servicios y puertos expuestos | Nmap (solo red autorizada) | `sudo nmap -sV 192.168.56.0/24` |
| Configuración del correo | `dig` | `dig +short TXT empresa.com` (SPF, DMARC en `_dmarc.empresa.com`) |

> 📸 **[CAPTURA 2.8]** Informe de Lynis o PingCastle con el índice de partida.

## 2.8 Fuentes y referencias

- Guía Nacional de Notificación y Gestión de Ciberincidentes (CCN-CERT / INCIBE-CERT): https://www.ccn-cert.cni.es y https://www.incibe.es
- INCIBE – Taxonomía y recursos de gestión de incidentes: https://www.incibe.es
- MITRE ATT&CK: https://attack.mitre.org
- NIST SP 800-61 Rev. 3 (gestión de incidentes): https://csrc.nist.gov
- Microsoft – Eventos de seguridad de Windows (Security Auditing): https://learn.microsoft.com
- Documentación de Wazuh: https://documentation.wazuh.com
- Sysmon (Sysinternals): https://learn.microsoft.com/sysinternals
- VirusTotal, AbuseIPDB, urlscan.io, crt.sh, Shodan, Censys
- RFC 5737 (rangos de IP reservados para documentación)

> ⚠️ **Antes de entregar:** sustituye los enlaces generales por la página concreta de cada recurso, añade la fecha de consulta y confirma en la guía vigente la tabla de niveles y plazos.


---

# 3. Investigación y análisis forense

> **Reglas del laboratorio**
> - Trabaja solo en equipos y redes **autorizados** y aislados (red solo-anfitrión, instantánea «base limpia» antes de empezar).
> - **No uses malware real.** Para las pruebas utiliza el fichero de prueba **EICAR** (inofensivo, detectado por todos los antivirus) o un script benigno que simule el comportamiento (abrir una conexión a una IP del laboratorio a intervalos regulares).
> - Los indicadores (IP, dominio, hash, equipo) de este documento son **ficticios**; sustitúyelos por los de tu laboratorio.
> - Principio guía: **la investigación no debe alterar la evidencia.**

## 3.1 Evidencias a recopilar

### Orden de volatilidad (RFC 3227)

Se recoge primero lo que antes se pierde:

| Orden | Fuente | Volatilidad | Ejemplos |
|:-:|---|---|---|
| 1 | Registros de CPU, caché | Muy alta | No suele ser accesible |
| 2 | **Memoria RAM** | Muy alta | Procesos, conexiones, claves, malware en memoria |
| 3 | **Estado de red** | Alta | Conexiones activas, tabla ARP, caché DNS, rutas |
| 4 | **Procesos y sesiones** | Alta | Procesos en ejecución, usuarios conectados |
| 5 | **Sistema de ficheros / disco** | Media | Imagen forense, ficheros temporales, MFT |
| 6 | **Logs del sistema y aplicaciones** | Media | Visor de eventos, `auth.log`, Sysmon |
| 7 | **Dispositivos de red** | Media | Logs de cortafuegos, proxy, DNS, DHCP, VPN |
| 8 | **Correo** | Media | Mensaje original, logs de pasarela |
| 9 | **Copias de seguridad y archivos** | Baja | Copias previas al incidente (línea base) |

### Inventario de evidencias del caso

| ID | Evidencia | Origen | Método de captura | Prioridad |
|---|---|---|---|---|
| E01 | Volcado de RAM | Equipo del usuario afectado | WinPmem / DumpIt / Magnet RAM Capture | Máxima |
| E02 | Estado de red y procesos (volátil) | Equipo afectado | `netstat`, `Get-NetTCPConnection`, `tasklist` | Máxima |
| E03 | Imagen forense del disco | Equipo afectado | FTK Imager / `dc3dd` con bloqueo de escritura | Alta |
| E04 | Correo original (`.eml` con cabeceras completas) | Buzón + pasarela | Exportación sin reenviar | Alta |
| E05 | Adjunto / archivo malicioso | Correo y disco | Copia en contenedor cifrado + hash | Alta |
| E06 | Logs de seguridad Windows y Sysmon | Equipo, DC, servidor de ficheros | `wevtutil epl` | Alta |
| E07 | Logs de cortafuegos / proxy / DNS | Perímetro | Exportación del dispositivo | Alta |
| E08 | Captura de tráfico (`.pcap`) | Red / puerto espejo | `tcpdump` / Wireshark | Media |
| E09 | Logs de Linux (`auth.log`, `journalctl`) | Servidores Ubuntu | Copia con hash | Media |
| E10 | Artefactos de persistencia | Equipo afectado | KAPE / Velociraptor | Media |
| E11 | Registros de acceso a carpetas compartidas | Servidor de ficheros | Eventos 5140/5145 | Alta |
| E12 | Copias de seguridad previas | NAS / backup | Hash y montaje de solo lectura | Media |
| E13 | Declaraciones y cronología | Usuario, informática | Entrevista documentada | Media |

> 📸 **[CAPTURA 3.1]** Inventario de evidencias cumplimentado (hoja de cálculo o ticket).

## 3.2 Preservación de la integridad

### Principios

1. **No alterar el original:** trabajar sobre copias verificadas; el original queda sellado.
2. **Hash antes y después:** SHA-256 de cada evidencia en el momento de la adquisición y en cada traspaso.
3. **Bloqueo de escritura:** bloqueador hardware o montaje en solo lectura.
4. **Documentar todo:** quién, cuándo, cómo, con qué herramienta y versión.
5. **Sincronización horaria:** anotar la desviación del reloj del equipo respecto a una fuente fiable (NTP) y la zona horaria.
6. **Mínima intervención en el equipo vivo:** herramientas desde medio externo, y registrar cada comando ejecutado.

### Procedimiento de adquisición

**Equipo Windows afectado (vivo)** — se **aísla de la red sin apagarlo** (desconectar cable/Wi-Fi o aislar desde el EDR):

```powershell
# 1) Fecha, hora y zona horaria (anotar y comparar con la hora real)
Get-Date -Format o; Get-TimeZone

# 2) Datos volátiles (ejecutar desde USB de confianza y volcar a medio externo)
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv E02_conexiones.csv -NoTypeInformation
Get-Process | Select Id,ProcessName,Path,StartTime | Export-Csv E02_procesos.csv -NoTypeInformation
ipconfig /displaydns > E02_dns_cache.txt
arp -a > E02_arp.txt
query user > E02_sesiones.txt

# 3) Volcado de memoria (ejemplo con WinPmem)
.\winpmem_mini_x64.exe E01_ram.raw

# 4) Exportar logs
wevtutil epl Security E06_Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" E06_Sysmon.evtx

# 5) Hash de todo lo recogido
Get-ChildItem E0* | Get-FileHash -Algorithm SHA256 | Export-Csv hashes_adquisicion.csv -NoTypeInformation
```

**Imagen de disco** (equipo apagado de forma controlada tras capturar la RAM, o disco extraído y conectado a bloqueador de escritura):

```bash
# En estación forense Linux; /dev/sdb = disco origen (solo lectura)
sudo dc3dd if=/dev/sdb of=E03_disco.dd hash=sha256 log=E03_adquisicion.log
sha256sum E03_disco.dd | tee E03_disco.dd.sha256
# Trabajar siempre sobre una copia
cp --reflink=auto E03_disco.dd trabajo_disco.dd
```

**Servidor Linux:**

```bash
sudo cp -a /var/log /evidencias/E09_logs && cd /evidencias
find E09_logs -type f -exec sha256sum {} \; > E09_hashes.txt
# Memoria: AVML o LiME
sudo ./avml E09_ram.lime
```

> **Dilema habitual:** apagar el equipo antes de capturar la RAM destruye pruebas volátiles; capturar mal altera el estado. Por eso la **decisión y sus motivos se anotan** en la bitácora.

> 📸 **[CAPTURA 3.2]** Adquisición de RAM y exportación de logs con sus hashes.
> 📸 **[CAPTURA 3.3]** Imagen de disco con `dc3dd` o FTK Imager y verificación de hash.

### Almacenamiento seguro

- Contenedor cifrado (VeraCrypt/LUKS/7-Zip AES-256) y copia de trabajo separada de la copia maestra.
- Medios etiquetados y guardados en armario cerrado con registro de accesos.
- Almacenamiento de las copias maestras en solo lectura (`chattr +i`, medios WORM o compartidos de solo lectura).

## 3.3 Cadena de custodia

Documento que acredita **quién tuvo la evidencia, cuándo, dónde y con qué fin**, sin lagunas. Su ruptura puede restarle valor probatorio.

### Marco técnico y legal de referencia

| Referencia | Aporte |
|---|---|
| **ISO/IEC 27037** | Identificación, recogida, adquisición y preservación de evidencias digitales |
| **ISO/IEC 27041, 27042, 27043** | Aseguramiento del método, análisis e interpretación, principios de investigación |
| **UNE 71505 y UNE 71506** | Gestión de evidencias electrónicas y metodología de preservación y análisis forense (normas españolas) |
| **RFC 3227** | Directrices de recogida y archivo de evidencias |
| **NIST SP 800-86** | Integración de técnicas forenses en la respuesta a incidentes |
| **Ley 1/2000 de Enjuiciamiento Civil** (medios de prueba electrónicos) y **LECrim** | Admisión de documentos y soportes electrónicos como prueba |
| **Estatuto de los Trabajadores y doctrina sobre control empresarial** | El análisis de equipos de empleados debe ser proporcional y respetar su intimidad; conviene que exista política de uso aceptable y, si procede, presencia de un testigo |

> 📝 Revisa la numeración vigente de las normas UNE y los artículos concretos antes de citarlos en el documento final. Si el caso puede acabar en denuncia, conviene encargar la pericial a un perito informático.

### Formulario de cadena de custodia

**Caso:** INC-2026-0001 · **Evidencia:** E__ · **Descripción:** ____________________

| Campo | Valor |
|---|---|
| Origen (equipo, serie, ubicación) | |
| Fecha-hora de adquisición | |
| Adquirida por (nombre, cargo) | |
| Testigo | |
| Herramienta y versión | |
| Método (vivo / apagado / con bloqueador) | |
| SHA-256 original | |
| SHA-256 de la copia | |
| Soporte y nº de serie | |
| Lugar de almacenamiento | |

| Nº | Fecha-hora | Entrega (nombre y firma) | Recibe (nombre y firma) | Motivo | Estado del precinto | Hash verificado |
|:-:|---|---|---|---|---|:-:|
| 1 | | | | | | ☐ |
| 2 | | | | | | ☐ |

> 📸 **[CAPTURA 3.4]** Formulario de cadena de custodia cumplimentado para E01 y E03.

## 3.4 Investigación del correo electrónico

### Obtención del mensaje

Exportar el **mensaje original completo** (`.eml` o `.msg`), nunca una captura ni un reenvío. En Outlook: *Archivo → Propiedades → Encabezados de Internet*; en el servidor de correo, extraer el mensaje de la cola/buzón y calcular su hash.

### Cabeceras: qué se analiza

| Campo | Qué revisar | Señal de alarma |
|---|---|---|
| **From** | Nombre visible y dirección | Nombre de RR. HH. con dominio distinto o parecido (*typosquatting*) |
| **Return-Path / Envelope-From** | Remitente real del sobre | No coincide con `From` |
| **Reply-To** | A quién responderá la víctima | Dominio ajeno |
| **Received** (de abajo hacia arriba) | Ruta real, servidores e IP de origen | IP externa sospechosa, saltos inconsistentes |
| **Authentication-Results** | **SPF, DKIM, DMARC** | `fail`, `softfail`, `none` |
| **Message-ID** | Dominio generador | Dominio distinto al remitente |
| **Date / X-Mailer / User-Agent** | Zona horaria y cliente | Zona horaria incoherente |
| **Content-Type / adjuntos** | Tipos MIME y nombres | Doble extensión (`nomina.pdf.exe`), ZIP con contraseña, `.iso`, `.lnk` |

### Ejemplo de lectura (cabeceras ficticias)

```text
Return-Path: <bounce@mailer-xyz.example>
Received: from mail.mailer-xyz.example (mail.mailer-xyz.example [198.51.100.23])
        by mx.empresa.com; Mon, 09 Nov 2026 08:02:11 +0100
Authentication-Results: mx.empresa.com;
        spf=fail smtp.mailfrom=mailer-xyz.example;
        dkim=none;
        dmarc=fail header.from=empresa.com
From: "Recursos Humanos" <rrhh@empresa.com>
Reply-To: <rrhh-empresa-portal@rrhh-empresa-portal.example>
Subject: Documento sobre tu nómina - acción requerida
```

**Conclusión del ejemplo:** el `From` suplanta el dominio de la empresa, el sobre procede de otro dominio, SPF y DMARC fallan y la respuesta se desvía a un dominio externo. Evidencia de **suplantación (spoofing)** y de que los controles de la pasarela no rechazaron el mensaje.

```bash
# Extracción rápida de campos
grep -iE "^(From|Return-Path|Reply-To|Received|Authentication-Results|Message-ID|Subject):" mensaje.eml
# Verificar políticas del dominio legítimo
dig +short TXT empresa.com             # SPF
dig +short TXT _dmarc.empresa.com      # DMARC
```

Herramientas: Google Admin Toolbox *Messageheader*, MXToolbox *Email Header Analyzer*, `mu` / `mhonarc`, analizadores de cabeceras (solo con datos no sensibles).

### Acciones derivadas

- **Búsqueda del mismo mensaje** en todos los buzones (por remitente, asunto, hash del adjunto) y purga.
- **Listado de quién lo abrió, descargó o ejecutó** (logs de la pasarela y del endpoint).
- Bloqueo del remitente, dominio y URL; refuerzo de SPF/DKIM/DMARC con política `reject`.

> 📸 **[CAPTURA 3.5]** Cabeceras completas del correo con `Authentication-Results` resaltado.

## 3.5 Análisis del archivo malicioso

### Principios

Análisis **estático primero** (sin ejecutar) y **dinámico solo en sandbox aislado**. Nunca abrir el adjunto en el equipo de trabajo.

### Fase 1: identificación y hash

```bash
file nomina.zip
sha256sum nomina.zip
md5sum nomina.zip      # solo como identificador complementario
exiftool documento.docx
```
```powershell
Get-FileHash .\documento.docm -Algorithm SHA256
```

Se consulta el hash en VirusTotal (**buscar por hash; no subir ficheros con información corporativa o personal**).

### Fase 2: análisis estático

| Tipo | Herramienta | Comando / uso |
|---|---|---|
| Documento Office con macros | `olevba` (oletools), `oledump.py` | `olevba documento.docm` |
| PDF | `pdfid`, `pdf-parser` | `pdfid fichero.pdf` |
| Ejecutable Windows (PE) | `pestudio`, `die`, `capa` | Cabeceras, imports, secciones, entropía |
| Cadenas | `strings`, FLOSS | `strings -a -n 8 fichero \| less` |
| Script | Lectura manual, desofuscación | PowerShell codificado en Base64 (`-enc`) |

Indicios a buscar: macros con `AutoOpen`/`Document_Open`, `Shell`, `WScript.Shell`, `powershell -enc`, descarga de URL, imports como `VirtualAlloc`, `WriteProcessMemory`, `InternetOpen`, secciones con entropía alta (empaquetado).

### Fase 3: análisis dinámico (sandbox)

| Opción | Uso |
|---|---|
| ANY.RUN, Hybrid Analysis, Triage | Servicios en línea (solo con muestras sin datos sensibles) |
| CAPE / Cuckoo | Sandbox propio en el laboratorio |
| VM aislada con Process Monitor, Process Explorer, Regshot, Wireshark, FakeNet-NG | Observar procesos, cambios de registro/ficheros y conexiones |

Se documentan: procesos hijos, ficheros y claves de registro creados, persistencia (Run, tareas programadas, servicios), dominios e IP contactados y mutex.

### Fase 4: memoria con Volatility 3

```bash
vol -f E01_ram.raw windows.pslist
vol -f E01_ram.raw windows.pstree
vol -f E01_ram.raw windows.cmdline
vol -f E01_ram.raw windows.netscan
vol -f E01_ram.raw windows.malfind
```

### Fase 5: persistencia y cronología en el disco

| Artefacto | Qué aporta |
|---|---|
| Claves `Run/RunOnce`, tareas programadas, servicios | Persistencia |
| **Prefetch**, **Amcache**, **ShimCache** | Qué se ejecutó y cuándo |
| **$MFT / USN Journal** | Creación y borrado de ficheros |
| Historial del navegador y caché de Outlook | Origen de la descarga |
| **SRUM** | Uso de red por aplicación (indicio de exfiltración) |

Herramientas: KAPE + Eric Zimmerman Tools, Autopsy, Plaso (`log2timeline`) para línea temporal.

### Tabla de resultados (plantilla)

| Campo | Resultado |
|---|---|
| SHA-256 del adjunto | *(calcular)* |
| Tipo de fichero | |
| Detección en VirusTotal | *X/Y* |
| Comportamiento observado | |
| Persistencia | |
| C2 (IP/dominio) | |
| Familia/clasificación probable | |
| Técnicas ATT&CK | |

> 📸 **[CAPTURA 3.6]** Salida de `olevba`/`strings`/`pestudio` o informe de sandbox.
> 📸 **[CAPTURA 3.7]** Volatility: `windows.pslist` y `windows.netscan` con el proceso y la conexión sospechosos.

## 3.6 Análisis de conexiones sospechosas

### Qué se busca

| Patrón | Indicio | Cómo detectarlo |
|---|---|---|
| **Balizamiento (beaconing)** | Conexiones a intervalos casi regulares hacia el mismo destino (p. ej. cada 60 s con poca variación, *jitter*) | Análisis de intervalos y desviación típica |
| **Tamaños uniformes** | Peticiones pequeñas y repetitivas (latidos) | Estadística de bytes por conexión |
| **Destino poco común** | IP sin dominio, dominio recién creado, DGA | Reputación, edad del dominio, entropía del nombre |
| **Exfiltración** | Mucho más tráfico saliente que entrante, picos fuera de horario | Bytes enviados vs. recibidos |
| **Túnel DNS** | Consultas largas y numerosas a un mismo dominio, registros TXT | Longitud de `qname`, frecuencia |
| **Proceso inadecuado** | Un proceso que no debería usar red conecta a Internet | Sysmon 3, `netscan` |

### Procedimiento

```bash
# 1) Conexiones por destino
tshark -r captura.pcap -q -z conv,ip | head -20

# 2) Intervalos de las conexiones TLS hacia la IP sospechosa
tshark -r captura.pcap -Y "ip.dst==203.0.113.45 && tls.handshake.type==1" -T fields -e frame.time_epoch | \
  awk 'NR>1{print $1-prev} {prev=$1}'

# 3) Bytes salientes hacia esa IP
tshark -r captura.pcap -Y "ip.dst==203.0.113.45" -T fields -e frame.len | awk '{s+=$1} END{print s " bytes"}'

# 4) Peticiones DNS más frecuentes
tshark -r captura.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head
```

**Cálculo de regularidad (Python):**

```python
import statistics as st
intervalos = [60.1, 59.8, 60.3, 60.0, 59.9, 60.2]   # sustituir por los reales
media, desv = st.mean(intervalos), st.pstdev(intervalos)
print(f"media={media:.1f}s desviación={desv:.2f}s coef. variación={desv/media:.3f}")
# Un coeficiente de variación muy bajo sugiere comunicación automática (beaconing)
```

Con tráfico cifrado (HTTPS) no se ve el contenido: se analiza **metadatos** (IP, SNI, tamaños, frecuencia, huella JA3/JA4). Herramientas de apoyo: Zeek, RITA/AC-Hunter (detección de beaconing), Suricata.

### Relación con el volumen exfiltrado

Para estimar el alcance de la fuga se cruzan tres fuentes: bytes salientes del cortafuegos, eventos **5140/5145** (qué carpetas y ficheros leyó la cuenta comprometida) y SRUM/Sysmon (qué proceso transmitió). El resultado alimenta la decisión de **notificar a la AEPD** (apartado 5).

> 📸 **[CAPTURA 3.8]** Gráfico de E/S de Wireshark o salida de intervalos mostrando la regularidad.

## 3.7 Cálculo del hash SHA-256 y su relevancia forense

### Qué es y cómo funciona (visión matemática simplificada)

SHA-256 (familia SHA-2, estándar **FIPS 180-4**) produce una huella de **256 bits (64 caracteres hexadecimales)**:

1. **Relleno (padding):** se añade un bit `1`, ceros hasta que la longitud sea ≡ 448 mod 512 y, al final, la longitud original del mensaje en 64 bits. El resultado es un múltiplo de **512 bits**.
2. **Bloques:** se procesa cada bloque de 512 bits (16 palabras de 32 bits) y se **expande a 64 palabras** `W[0..63]`.
3. **Estado inicial:** ocho palabras `H0..H7` de 32 bits (derivadas de las raíces cuadradas de los 8 primeros números primos).
4. **64 rondas:** en cada ronda se actualizan las variables `a..h` con operaciones sobre palabras de 32 bits, usando constantes `K[0..63]` (derivadas de las raíces cúbicas de los 64 primeros primos):

   ```text
   T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
   T2 = Σ0(a) + Maj(a,b,c)
   (h,g,f,e,d,c,b,a) = (g,f,e,d+T1,c,b,a,T1+T2)       (todo suma módulo 2^32)
   Ch(x,y,z)  = (x AND y) XOR (NOT x AND z)
   Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
   Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
   Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
   ```
5. **Encadenamiento:** al terminar el bloque se suman las variables a `H0..H7`; el estado final concatenado es el hash.

### Propiedades que importan en forense

| Propiedad | Significado | Utilidad |
|---|---|---|
| Determinista | Mismo fichero → mismo hash | Verificar que una copia es idéntica |
| Efecto avalancha | Cambiar 1 bit cambia ~50 % del hash | Detectar cualquier alteración |
| Resistencia a preimagen | No se puede reconstruir el fichero desde el hash | Compartir IoC sin exponer contenido |
| Resistencia a colisiones | Inviable encontrar dos ficheros con el mismo hash | Un hash identifica un fichero de forma práctica única |

> MD5 y SHA-1 tienen colisiones demostradas: no se deben usar como única garantía de integridad. Se recomienda **SHA-256** (y puede añadirse un segundo algoritmo).

### Vectores de prueba (para validar tu herramienta)

| Entrada | SHA-256 |
|---|---|
| Cadena vacía | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `abc` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |

```bash
printf "" | sha256sum
printf "abc" | sha256sum
```
*(Si tu salida no coincide con la tabla, la herramienta o la entrada no son correctas; ojo con el salto de línea de `echo`.)*

### Práctica de laboratorio

```bash
# 1) Fichero de prueba y su hash
echo "Evidencia de prueba - INC-2026-0001" > evidencia.txt
sha256sum evidencia.txt | tee evidencia.txt.sha256

# 2) Verificación de integridad
sha256sum -c evidencia.txt.sha256          # evidencia.txt: OK

# 3) Alteración mínima y nueva verificación
echo "." >> evidencia.txt
sha256sum -c evidencia.txt.sha256          # evidencia.txt: FAILED

# 4) Hash del fichero EICAR (solo para prueba; el antivirus puede bloquearlo)
sha256sum eicar.com
```
```powershell
Get-FileHash .\evidencia.txt -Algorithm SHA256
(Get-FileHash .\evidencia.txt).Hash -eq (Get-Content .\evidencia.txt.sha256).Split(' ')[0].ToUpper()
```

### Usos en este incidente

| Uso | Ejemplo |
|---|---|
| **Integridad de evidencias** | Hash en la adquisición, tras cada copia y en cada traspaso de custodia |
| **Identificación del malware** | Buscar el hash del adjunto en VirusTotal y en los EDR de todos los equipos |
| **Caza de amenazas** | Buscar en la red ficheros con el mismo SHA-256 |
| **IoC compartible** | Entregar el hash al CSIRT (INCIBE-CERT/CCN-CERT) |
| **Informe pericial** | Acreditar que lo analizado es idéntico a lo adquirido |

> 📸 **[CAPTURA 3.9]** `sha256sum` del fichero, verificación `OK` y `FAILED` tras la modificación.
> 📸 **[CAPTURA 3.10]** `Get-FileHash` en PowerShell y comparación con los vectores de prueba.

## 3.8 Línea temporal del incidente (plantilla)

| Hora (UTC+1) | Evento | Fuente | Evidencia |
|---|---|---|---|
| T0 | Entrega del correo a la bandeja | Pasarela | E04 |
| T0+x | Apertura del adjunto | Outlook / Sysmon 1 | E06 |
| T0+x | Ejecución del archivo malicioso | 4688 / Sysmon 1 | E06, E01 |
| T0+x | Primera conexión a 203.0.113.45 | Sysmon 3 / cortafuegos | E07, E08 |
| T0+x | Intentos de acceso a carpetas compartidas | 4625 / 5140 | E11 |
| T0+x | Alerta del antivirus | Defender 1116 | E06 |
| T0+x | Detección por informática | Ticket | E13 |

## 3.9 Conclusiones del análisis (modelo)

- **Vector:** phishing con suplantación del dominio corporativo y fallos de SPF/DKIM/DMARC no bloqueados en la pasarela.
- **Ejecución y persistencia:** *(completar con los hallazgos reales)*.
- **Comunicación externa:** *(IP/dominio, frecuencia, patrón de balizamiento)*.
- **Alcance de datos:** *(carpetas, nº de ficheros y registros, estimación de volumen)*.
- **Evidencias custodiadas:** E01-E13 con hash y cadena de custodia.
- **Hipótesis pendiente de confirmar:** exfiltración efectiva de datos personales.

## 3.10 Fuentes y referencias

- RFC 3227 – Guidelines for Evidence Collection and Archiving: https://www.rfc-editor.org/rfc/rfc3227
- NIST SP 800-86 – Guide to Integrating Forensic Techniques into Incident Response: https://csrc.nist.gov
- NIST FIPS 180-4 – Secure Hash Standard: https://csrc.nist.gov
- ISO/IEC 27037:2012 y UNE 71505 / 71506 (evidencias electrónicas)
- CCN-CERT – Guías CCN-STIC de análisis forense y gestión de incidentes: https://www.ccn-cert.cni.es
- INCIBE – Guías de análisis forense y gestión de incidentes: https://www.incibe.es
- Documentación de Volatility 3: https://volatility3.readthedocs.io
- Eric Zimmerman Tools y KAPE: https://ericzimmerman.github.io
- oletools (olevba): https://github.com/decalage2/oletools
- MITRE ATT&CK: https://attack.mitre.org
- Microsoft – Encabezados de Internet / autenticación de correo (SPF, DKIM, DMARC): https://learn.microsoft.com
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)

> ⚠️ **Antes de entregar:** sustituye los enlaces generales por las páginas concretas, añade fecha de consulta, completa los resultados reales de tu laboratorio y confirma la numeración de las normas UNE y los artículos legales citados.

