# 4. Respuesta y recuperación

## 4.1 Procedimiento operativo estándar (SOP)

### Ficha del procedimiento

| Campo | Valor |
|---|---|
| Código | PR-SEG-010 · Respuesta a incidentes de malware y compromiso de cuentas |
| Versión / fecha | 1.0 / AAAA-MM-DD |
| Aprobado por | Dirección (responsable de seguridad como autor) |
| Alcance | Estaciones de trabajo, servidores Windows/Linux, Directorio Activo, correo y red |
| Disparador | Alerta de antivirus/EDR confirmada, reporte de un usuario o conexión a IoC conocido |
| Referencias | NIST SP 800-61, Guía Nacional de Notificación de Ciberincidentes, CCN-STIC 817 (gestión de ciberincidentes, ENS) |

### Roles (matriz RACI)

| Actividad | Dirección | Resp. seguridad | Sistemas (N2) | Soporte (N1) | Comunicación | Usuario |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Declarar incidente y nivel | I | **A/R** | C | R | I | I |
| Aislar equipos | I | A | **R** | R | – | I |
| Bloqueo perimetral | I | A | **R** | – | – | – |
| Revocar credenciales | I | A | **R** | C | – | I |
| Erradicar y reconstruir | I | A | **R** | C | – | – |
| Restaurar servicios | I | A | **R** | C | I | I |
| Reanudar la operación (decisión) | **A** | R | C | I | I | I |
| Comunicación interna/externa | A | R | C | – | **R** | I |

*(R = ejecuta · A = responde del resultado · C = consultado · I = informado. Una sola «A» por fila.)*

### Visión general: seis fases

```text
Preparación → Identificación → CONTENCIÓN → ERRADICACIÓN → RECUPERACIÓN → Lecciones aprendidas
 (previo)       (apdos. 2-3)     (4.1.1-4.1.2)  (4.1.3-4.1.4)    (4.2)           (4.5)
```

### Cronograma de actuación (objetivos orientativos)

| Plazo | Acción | Responsable |
|---|---|---|
| T+0 a T+15 min | Confirmar alerta, abrir ticket, aislar el equipo afectado, avisar al responsable de seguridad | N1 / N2 |
| T+15 min a T+1 h | Captura de evidencia volátil, bloqueo de IoC, deshabilitar la cuenta, búsqueda de otros equipos | N2 / Seguridad |
| T+1 h a T+4 h | Restablecimiento de credenciales, purga del correo, ampliación del alcance, notificación a dirección | Seguridad |
| T+4 h a T+24 h | Erradicación y reconstrucción de equipos, revisión de persistencia, decisión de notificación | Sistemas / Seguridad |
| T+24 h a T+72 h | Recuperación escalonada y vigilancia reforzada. **Reloj RGPD: 72 h desde que se tiene constancia de la brecha** (ver apartado 5) | Sistemas / Dirección |
| T+14 días | Reunión de lecciones aprendidas y plan de mejora | Todos |

### 4.1.1 Aislamiento de los equipos afectados (sin perder la memoria RAM)

**Regla de oro: aislar, no apagar.** Apagar o reiniciar destruye procesos, conexiones y claves en memoria.

| Método (de menos a más intrusivo) | Cuándo | Cómo |
|---|---|---|
| **Aislamiento desde el EDR** | Si hay EDR (p. ej. Defender for Endpoint) | Acción «Isolate device» (mantiene el canal con la consola) |
| **Cuarentena en VLAN o puerto del switch** | Red gestionable | Mover el puerto a una VLAN sin salida o deshabilitarlo (`shutdown`) |
| **Regla de cortafuegos local** | Sin EDR | Bloqueo de todo el tráfico salvo gestión |
| **Desconexión física** | Último recurso | Quitar cable de red y desactivar Wi-Fi (no apagar, no suspender, no hibernar) |

```powershell
# Aislamiento local en Windows: bloquear todo el tráfico saliente y entrante
New-NetFirewallRule -DisplayName "INC-ISOLATE-OUT" -Direction Outbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "INC-ISOLATE-IN"  -Direction Inbound  -Action Block -Profile Any
# (Permitir solo la IP de la estación forense si se necesita captura remota)
New-NetFirewallRule -DisplayName "INC-ALLOW-FORENSE" -Direction Outbound -Action Allow -RemoteAddress 192.168.1.200

# Alternativa: desactivar adaptadores (el equipo sigue encendido)
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
```
```bash
# Aislamiento de un servidor Linux sin apagarlo (ufw)
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow out to 192.168.1.200     # solo estación forense
sudo ufw allow in from 192.168.1.200 to any port 22 proto tcp
sudo ufw enable
```

**Después del aislamiento:**

1. Verificar con un `ping`/conexión de prueba que el equipo ya no sale a la red.
2. Etiquetar el equipo físicamente («INC-2026-0001 – NO APAGAR / NO USAR»).
3. Capturar RAM y estado de red (apartado 3, E01 y E02).
4. Registrar hora exacta del aislamiento en la bitácora.

**Búsqueda de otros equipos afectados** (alcance):

```powershell
# Buscar el proceso/fichero malicioso en toda la red (por hash, con EDR o Velociraptor); alternativa básica por WinRM:
Invoke-Command -ComputerName (Get-ADComputer -Filter * | Select -Expand Name) -ScriptBlock {
  Get-ChildItem C:\Users -Recurse -Include nomina*.* -ErrorAction SilentlyContinue |
  Get-FileHash -Algorithm SHA256 | Where-Object Hash -eq '<SHA256_DEL_ADJUNTO>'
}
# Quién ha contactado con la IP maliciosa (logs de cortafuegos/proxy o Sysmon 3)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match '203\.0\.113\.45' } | Select TimeCreated, Message
```

> <img width="905" height="515" alt="image" src="https://github.com/user-attachments/assets/0b96a623-3e80-4145-8625-bc34709b8843" />

### 4.1.2 Bloqueo perimetral de conexiones maliciosas

Se bloquea en **varias capas** (defensa en profundidad) y con **vigencia y justificación** anotadas.

| Capa | Acción | Ejemplo |
|---|---|---|
| Cortafuegos perimetral | Bloqueo de la IP de C2 (entrada y salida) y de su rango si procede | `deny out to 203.0.113.45` |
| DNS | *Sinkhole* o bloqueo del dominio malicioso | Zona ficticia que resuelve a `0.0.0.0` |
| Proxy/filtro web | Categorizar y bloquear URL y dominio | Lista de bloqueo |
| Correo | Bloquear remitente, dominio y hash del adjunto; purgar mensajes | Regla de transporte + búsqueda y eliminación |
| EDR/AV | Añadir hash a lista de bloqueo (IoC personalizado) | Indicador «block & remediate» |
| Cortafuegos interno | Impedir tráfico lateral (SMB 445, RDP 3389, WinRM 5985/5986) entre estaciones | Reglas entre VLAN |

```powershell
# Windows Server DNS: sinkhole del dominio malicioso
Add-DnsServerPrimaryZone -Name "rrhh-empresa-portal.example" -ZoneFile "rrhh-empresa-portal.example.dns"
Add-DnsServerResourceRecordA -ZoneName "rrhh-empresa-portal.example" -Name "@" -IPv4Address "0.0.0.0"
Add-DnsServerResourceRecordA -ZoneName "rrhh-empresa-portal.example" -Name "*" -IPv4Address "0.0.0.0"

# Windows Defender Firewall: bloqueo saliente de la IP de C2 (en servidores y estaciones por GPO)
New-NetFirewallRule -DisplayName "BLOCK-C2-203.0.113.45" -Direction Outbound -RemoteAddress 203.0.113.45 -Action Block
```
```bash
# Linux (ufw)
sudo ufw insert 1 deny out to 203.0.113.45
sudo ufw insert 1 deny in from 203.0.113.45
# Equivalente con nftables
sudo nft add rule inet filter output ip daddr 203.0.113.45 drop
# Registrar los intentos bloqueados
sudo ufw logging medium
```

**Mejoras de arquitectura derivadas** (medidas permanentes, no solo del incidente):

- Política de salida **por defecto denegada** (solo se permite lo necesario) y filtrado de DNS.
- Segmentación en VLAN (oficina, servidores, planta/IoT, invitados) con reglas entre zonas.
- Inspección TLS selectiva/proxy para tráfico saliente de estaciones.

> 📸 **[CAPTURA 4.2]** Reglas de bloqueo (cortafuegos y DNS) y el log con el primer intento denegado.
>
> 

### 4.1.3 Revocación de credenciales comprometidas

Se asume que **toda cuenta que haya iniciado sesión en el equipo comprometido está expuesta** (credenciales y tokens en memoria).

| Orden | Acción | Detalle |
|:-:|---|---|
| 1 | Deshabilitar la cuenta del usuario afectado y cerrar sus sesiones | Evita uso inmediato |
| 2 | Restablecer contraseña de **todas las cuentas que iniciaron sesión** en el equipo | Incluidos administradores que hayan accedido |
| 3 | Revocar sesiones y tokens de la nube/correo/VPN | Cierre de sesión global y revocación de *refresh tokens* |
| 4 | Revisar y restablecer **cuentas de servicio** potencialmente expuestas | Contraseñas largas y únicas; preferible gMSA |
| 5 | **Contraseña del administrador local** única por equipo | Windows LAPS |
| 6 | Si hay indicio de compromiso del dominio: **doble reset de `krbtgt`** | Dos veces, con espera entre ellas superior a la vida máxima del ticket |
| 7 | Rotar claves SSH, API keys y secretos de aplicaciones accedidos desde el equipo | Servidores Linux, repositorios |
| 8 | Activar o reforzar **MFA** (sobre todo VPN, correo y administración) | Preferible resistente a phishing (FIDO2) |
| 9 | Revisar reglas de reenvío de correo y delegaciones, OAuth y aplicaciones autorizadas | Persistencia típica en correo |

```powershell
# 1) Deshabilitar cuenta y forzar cambio
Disable-ADAccount -Identity jperez
Set-ADUser -Identity jperez -ChangePasswordAtLogon $true

# 2) Restablecer contraseña con valor aleatorio largo (el usuario recibirá una temporal por canal alternativo)
Add-Type -AssemblyName System.Web
$pw = ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(24,4)) -AsPlainText -Force
Set-ADAccountPassword -Identity jperez -Reset -NewPassword $pw

# 3) Identificar quién inició sesión en el equipo comprometido (eventos 4624 tipo 2/3/10)
Get-WinEvent -ComputerName PC-RRHH-07 -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-3)} |
  Select TimeCreated, @{n='Usuario';e={$_.Properties[5].Value}}, @{n='Tipo';e={$_.Properties[8].Value}}

# 4) Restablecer la contraseña del administrador local gestionada por Windows LAPS
Reset-LapsPassword            # en el equipo, o por GPO/Entra según el modo de LAPS

# 5) Doble reset de krbtgt (SOLO ante compromiso de dominio; usar el script oficial de Microsoft y planificarlo)
#    Primer reset → esperar > duración máxima de ticket (por defecto 10 h) y replicación → segundo reset
```
```bash
# Linux: bloquear usuario, cerrar sesiones y rotar claves
sudo usermod -L usuario && sudo pkill -KILL -u usuario
sudo passwd -l usuario
sudo rm ~/.ssh/authorized_keys     # tras copiar como evidencia; regenerar claves
```

> 📸 **[CAPTURA 4.3]** Cuenta deshabilitada, contraseña restablecida y fallo de inicio de sesión posterior (evento 4625/4768 con error).

### 4.1.4 Erradicación de la amenaza

Objetivo: eliminar **toda** la presencia del atacante, no solo el fichero detectado.

| Paso | Acción |
|:-:|---|
| 1 | Con la evidencia ya preservada, **identificar toda la persistencia**: claves `Run/RunOnce`, tareas programadas, servicios nuevos, suscripciones WMI, carpetas de inicio, cuentas nuevas, reglas de correo |
| 2 | **Reconstruir** el equipo comprometido desde imagen limpia (*gold image*), no «desinfectar» (no se puede garantizar la limpieza) |
| 3 | Restaurar solo **datos** (no ejecutables) desde copia verificada y analizarlos con antimalware |
| 4 | Aplicar parches, línea base de seguridad y EDR **antes** de reconectar |
| 5 | Buscar los mismos IoC (hash, IP, dominio, clave de registro) en **toda** la infraestructura |
| 6 | Revisar el DC: cuentas nuevas, cambios de pertenencia a grupos, GPO modificadas, tareas programadas |
| 7 | Verificar la desaparición de actividad en logs durante un periodo de vigilancia reforzada (≥ 14 días) |

```powershell
# Persistencia: revisión rápida
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} | Select TaskName, TaskPath, State
Get-CimInstance Win32_Service | Where-Object {$_.PathName -notmatch 'Windows|Program Files'} | Select Name, PathName, StartMode
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-ADUser -Filter * -Properties whenCreated | Where-Object whenCreated -gt (Get-Date).AddDays(-7) | Select Name, whenCreated
Get-ADGroupMember "Domain Admins" | Select Name
```
```bash
# Linux: persistencia
sudo crontab -l; ls -la /etc/cron.* /var/spool/cron/crontabs
systemctl list-unit-files --state=enabled | grep -vi "systemd\|ssh\|cron\|rsyslog"
sudo find / -xdev -newermt "2026-11-01" -type f -perm -4000 2>/dev/null   # SUID nuevos
```

**Criterio reconstruir vs. limpiar:**

| Situación | Decisión |
|---|---|
| Estación con malware que establece C2 y ejecución de código | **Reconstruir** |
| Servidor con acceso del atacante confirmado | **Reconstruir** y rotar secretos |
| Controlador de dominio con indicios de compromiso | Valorar **reconstrucción** del DC (o del bosque) con asistencia especializada |
| Equipo que solo recibió el correo sin abrirlo | Purgar correo y vigilar |

> <img width="907" height="281" alt="image" src="https://github.com/user-attachments/assets/ce69c5aa-ffe5-40bc-8e2e-b126f5c9a33f" />

## 4.2 Plan de recuperación segura de servicios

### Principios

1. **Recuperar desde un punto limpio:** la copia debe ser **anterior** a la fecha de compromiso (T0 de la cronología).
2. **Orden por criticidad:** primero lo que sostiene a lo demás (identidad, red, DNS), luego servicios de negocio.
3. **Probar antes de poner en producción:** restaurar en entorno aislado y verificar.
4. **Reconectar con vigilancia reforzada.**
5. **La dirección decide cuándo se reanuda**, con el riesgo residual documentado.

### Prioridad y objetivos (RTO/RPO)

| Orden | Servicio | RTO (tiempo de recuperación) | RPO (pérdida máxima de datos) | Dependencias |
|:-:|---|---|---|---|
| 1 | Red, DNS, DHCP | 2 h | 24 h | Switches, cortafuegos |
| 2 | Directorio Activo / autenticación | 4 h | 4 h | Red, DNS |
| 3 | Servidor de ficheros (datos de clientes) | 8 h | 24 h | AD |
| 4 | Correo | 8 h | 24 h | AD, DNS |
| 5 | Aplicaciones de negocio / web | 24 h | 24 h | AD, BD |
| 6 | Estaciones de trabajo | 24-48 h | – | AD, imagen limpia |

*(Valores de ejemplo: la dirección los fija según el análisis de impacto en el negocio, BIA.)*

### Regla 3-2-1 y su evolución

| Elemento | Requisito | Aplicación en la empresa |
|---|---|---|
| **3** copias de los datos | Original + 2 copias | Producción + copia local + copia externa |
| **2** soportes distintos | Discos, NAS, cinta, nube | NAS local + almacenamiento en nube/cinta |
| **1** copia fuera de las instalaciones | Protege ante incendio, robo y ransomware | Nube con credenciales independientes o cinta fuera de sede |
| **+1** copia inmutable/offline (3-2-1-1-0) | No modificable ni borrable | *Object Lock* (WORM), cinta desconectada, instantáneas inmutables |
| **0** errores | Verificación periódica | Prueba de restauración mensual con hash |

**Reglas de robustez de las copias:**

- Credenciales de backup **separadas** del dominio y con MFA.
- La consola de backup no es accesible desde las estaciones.
- Cifradas (AES-256) y con la clave guardada fuera de la infraestructura.
- Retención escalonada (diaria/semanal/mensual) para poder volver a un punto anterior a la infección.
- El NAS **no** debe estar montado de forma permanente con permisos de escritura desde los servidores.

```bash
# Ejemplo con restic (laboratorio): copia cifrada, verificación y restauración de prueba
export RESTIC_REPOSITORY=/mnt/backup/restic   # en producción: repositorio remoto con Object Lock
export RESTIC_PASSWORD_FILE=/root/.restic_pass
restic init
restic backup /srv/datos --tag diario
restic check                                  # integridad del repositorio
restic snapshots
restic restore latest --target /tmp/restauracion_prueba
diff -r /srv/datos /tmp/restauracion_prueba && echo "RESTAURACION OK"

# Inmutabilidad local en ficheros críticos de backup (ext4)
sudo chattr +i /mnt/backup/restic/config
```
```powershell
# Windows Server: copia de estado del sistema y verificación
wbadmin start systemstatebackup -backupTarget:E: -quiet
wbadmin get versions
# Verificación de integridad de lo restaurado (hash contra el manifiesto)
Get-FileHash .\datos_restaurados\* -Algorithm SHA256 | Export-Csv restauracion_hashes.csv
```

### Procedimiento de restauración paso a paso

| Paso | Acción | Verificación |
|:-:|---|---|
| 1 | Confirmar la fecha de compromiso y elegir la copia **anterior** | Cronología (apdo. 3) |
| 2 | Escanear la copia con antimalware y buscar IoC antes de restaurar | Sin detecciones |
| 3 | Restaurar en **red aislada** (entorno de pruebas) | Servicio arranca y datos coherentes |
| 4 | Aplicar parches y línea base de seguridad al sistema restaurado | Informe de cumplimiento (Lynis/CIS) |
| 5 | Credenciales y secretos **nuevos** antes de reconectar | Sin reutilización de los comprometidos |
| 6 | Reconectar de forma **escalonada** (piloto → servicios → usuarios) | Monitorización reforzada |
| 7 | Validación funcional con el responsable del servicio | Acta de aceptación |
| 8 | Vigilancia reforzada (≥ 14 días) con alertas sobre IoC | Sin reaparición |
| 9 | Cierre del incidente y registro de la recuperación | Bitácora completada |

> <img width="907" height="331" alt="image" src="https://github.com/user-attachments/assets/88d87df3-19d1-41fc-9c23-3294a886fb59" />

### Gestión de la presión de la dirección

Si la dirección exige **reactivar de inmediato**, se presenta el compromiso: servicios mínimos esenciales en entorno segregado y con monitorización, y el resto cuando se cumplan los criterios de salida:

| Criterio de reanudación (checklist) | ☐ |
|---|:-:|
| Persistencia eliminada y equipo/servidor reconstruido | ☐ |
| IoC bloqueados y sin tráfico hacia ellos durante N horas | ☐ |
| Credenciales rotadas (usuarios, servicio, admin, `krbtgt` si procede) | ☐ |
| Restauración desde copia limpia verificada | ☐ |
| Monitorización reforzada activa | ☐ |
| Riesgo residual aceptado **por escrito** por la dirección | ☐ |

## 4.3 Demostración práctica de la eficacia de las contramedidas

Se verifica con evidencia que cada medida **funciona**: se compara el estado **antes** (incidente simulado) y **después** (con la contramedida).

### Montaje de la prueba (laboratorio)

1. En una VM de «equipo afectado» se ejecuta un **script benigno** que simula balizamiento: abre una conexión a `203.0.113.45` (IP ficticia, o a una VM del laboratorio que haga de C2) cada 60 s.
2. Se captura el tráfico y se comprueba la conexión (estado «antes»).
3. Se aplica cada contramedida y se repite la comprobación (estado «después»).

```bash
# Script benigno de simulación de baliza (laboratorio, hacia una VM de pruebas 192.168.56.30)
while true; do curl -s -m 3 http://192.168.56.30:8080/ping >/dev/null; sleep 60; done
```

### Tabla de pruebas antes/después

| # | Contramedida | Prueba (antes) | Prueba (después) | Evidencia | Resultado esperado |
|:-:|---|---|---|---|---|
| 1 | Aislamiento del equipo | `ping`/`curl` a la red: responde | Sin conectividad; RAM intacta (proceso sigue vivo) | `Get-Process`, `ping` | Aislado, sin pérdida de volátiles |
| 2 | Bloqueo perimetral de IP | `tshark` muestra conexiones salientes a la IP | Log del cortafuegos con `DROP` y sin respuesta | `ufw.log`, pcap | Bloqueado y registrado |
| 3 | Sinkhole DNS | `nslookup` devuelve la IP real | `nslookup` devuelve `0.0.0.0` | Captura de consulta | Dominio neutralizado |
| 4 | Revocación de cuenta | Inicio de sesión correcto de `jperez` | Fallo al iniciar sesión (4625 / error Kerberos) | Visor de eventos | Credencial inservible |
| 5 | LAPS / contraseñas únicas | Misma contraseña de admin local en varios equipos | Contraseñas distintas y rotadas | `Get-LapsADPassword` | Sin reutilización lateral |
| 6 | Erradicación | Persistencia presente (tarea/Run) | Revisión de persistencia sin hallazgos | Salida de comandos | Sin persistencia |
| 7 | Restauración desde backup | Datos eliminados/cifrados (simulado) | Restauración OK, hashes idénticos | `restic check`, `diff`, `Get-FileHash` | Integridad demostrada |
| 8 | Detección | Sin alerta | Alerta en Wazuh al repetirse el IoC | Dashboard | Detección en minutos |
| 9 | Bastionado | Índice de Lynis/CIS inicial | Índice mejorado tras aplicar la línea base | Informe antes/después | Mejora medible |

### Métricas de efectividad de la respuesta

| Métrica | Fórmula | Objetivo |
|---|---|---|
| MTTD (tiempo medio de detección) | Hora de detección − hora del primer indicio | Reducir |
| MTTC (tiempo hasta contención) | Hora de aislamiento − hora de detección | < 1 h |
| MTTR (tiempo de recuperación) | Hora de restauración − hora de inicio | Dentro del RTO |
| % equipos con contramedida aplicada | Equipos conformes / total | 100 % |
| Restauraciones correctas | Pruebas OK / pruebas realizadas | 100 % |

> <img width="806" height="282" alt="image" src="https://github.com/user-attachments/assets/3a26cf08-5235-42e8-9338-240ad95592a6" />

> <img width="908" height="272" alt="image" src="https://github.com/user-attachments/assets/6cb9892b-3fd6-4539-b7e0-82a3554477de" />

> 📸 **[CAPTURA 4.8]** Informe de Lynis o CIS-CAT antes y después del bastionado.

## 4.4 Medidas para evitar nuevos incidentes

Las lecciones del incidente se traducen en un plan priorizado (criterios del plan de securización: riesgo reducido, coste y esfuerzo, obligación legal, dependencias y economía circular).

| ID | Medida | Causa que corrige | Tipo | Plazo | Coste |
|---|---|---|---|---|---|
| M1 | Endurecer SPF/DKIM/DMARC a `reject` y filtrado de adjuntos | Suplantación de RR. HH. | Preventiva | 15 d | Bajo |
| M2 | Desplegar EDR en todos los equipos | Detección tardía | Detectiva | 30 d | Medio |
| M3 | MFA en VPN, correo y administración | Credenciales robadas | Preventiva | 30 d | Bajo |
| M4 | Windows LAPS y fin de la cuenta de administrador compartida | Movimiento lateral | Preventiva | 30 d | 0 € |
| M5 | Permisos por rol en carpetas con datos de clientes | Acceso amplio | Preventiva | 30 d | 0 € |
| M6 | Copias 3-2-1-1-0 con prueba mensual | Dependencia de un NAS en la misma red | Correctiva | 30 d | Medio |
| M7 | Segmentación por VLAN y salida denegada por defecto | Red plana | Preventiva | 60 d | Medio |
| M8 | SIEM Wazuh con alertas sobre los IoC y casos de uso | Visibilidad | Detectiva | 60 d | Bajo (reutilizando hardware) |
| M9 | Bloqueo de macros y de ejecución desde carpetas de usuario (AppLocker/WDAC) | Ejecución del adjunto | Preventiva | 60 d | Bajo |
| M10 | Formación y simulacros de phishing trimestrales | Factor humano | Preventiva | Continuo | Bajo |
| M11 | Procedimiento de incidentes y simulacro anual | Falta de respuesta formal | Organizativa | 90 d | Bajo |
| M12 | Parcheo por criticidad y revisión mensual | Vulnerabilidades | Preventiva | 60 d | 0 € |

## 4.5 Ciberresiliencia: anticipación, resistencia, recuperación y evolución

La **ciberresiliencia** es la capacidad de la organización de **seguir cumpliendo su misión ante un ataque**, y de adaptarse tras él. Se apoya en los cuatro objetivos del marco de referencia (anticipar, resistir, recuperar, evolucionar), compatibles con las funciones del NIST CSF 2.0.

| Pilar | Qué significa | Aplicación al incidente | Medidas concretas |
|---|---|---|---|
| **Anticipación** | Prever amenazas y estar preparado antes del ataque | Se carecía de procedimientos y de visibilidad | Análisis de riesgos anual, inteligencia de amenazas (INCIBE-CERT, CCN-CERT), formación y simulacros de phishing, plan de respuesta y contactos en papel |
| **Resistencia** | Evitar o limitar el impacto mientras el ataque ocurre | El adjunto se ejecutó y hubo movimiento lateral | MFA, mínimo privilegio, EDR, segmentación, bloqueo de adjuntos y macros, parcheo, filtrado de salida |
| **Recuperación** | Restablecer los servicios y los datos con rapidez y seguridad | Aislamiento, reconstrucción y restauración desde copias | Copias 3-2-1-1-0 probadas, RTO/RPO definidos, imágenes limpias, orden de reactivación |
| **Evolución** | Aprender y mejorar tras cada incidente | Cambios tras la reunión de lecciones aprendidas | Revisión posincidente sin culpables, actualización del análisis de riesgos y del procedimiento, nuevas reglas de detección con los IoC, métricas y mejora continua |

### Ciclo de mejora posincidente

1. **Reunión de lecciones aprendidas** en un máximo de 14 días, con acta y acciones asignadas.
2. **Análisis de causa raíz** (por qué falló cada capa: correo, usuario, endpoint, red, detección).
3. **Actualizar** análisis de riesgos, políticas y este procedimiento.
4. **Añadir** los IoC a las listas de bloqueo y las reglas de detección.
5. **Simulacro** (ejercicio de mesa) para validar los cambios.
6. **Informe final** a la dirección con coste del incidente, riesgo residual y plan de inversión.

### Plantilla de informe de cierre

| Campo | Contenido |
|---|---|
| Resumen ejecutivo | Qué pasó, impacto y estado |
| Cronología | Detección, contención, erradicación, recuperación (con horas) |
| Causa raíz | Factores técnicos, organizativos y humanos |
| Impacto | Sistemas, datos, personas, tiempo de parada, coste estimado |
| Qué funcionó / qué no | Controles efectivos y fallidos |
| Acciones correctivas | Responsable, plazo y estado |
| Riesgo residual | Aceptado por la dirección (firma y fecha) |

## 4.6 Fuentes y referencias

- NIST SP 800-61 Rev. 3 – Incident Response Recommendations: https://csrc.nist.gov
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- Guía Nacional de Notificación y Gestión de Ciberincidentes (CCN-CERT / INCIBE-CERT): https://www.ccn-cert.cni.es y https://www.incibe.es
- CCN-STIC 817 – Gestión de ciberincidentes (ENS): https://www.ccn-cert.cni.es
- INCIBE – Guías de gestión de incidentes y copias de seguridad: https://www.incibe.es
- CISA – #StopRansomware Guide: https://www.cisa.gov
- Microsoft – Windows LAPS; Guía de recuperación de Active Directory y restablecimiento de `krbtgt`: https://learn.microsoft.com
- Documentación de restic: https://restic.readthedocs.io
- CIS Controls v8.1 (11: recuperación de datos; 17: respuesta a incidentes): https://www.cisecurity.org
- Real Decreto 311/2022 (ENS), medidas de continuidad y respuesta: https://www.boe.es

---

# 5. Notificación y organismos de respuesta

> **Nota metodológica:** las referencias normativas y de organismos de este apartado se contrastaron con fuentes oficiales y secundarias consultadas el **12-11-2026** (AEPD, INCIBE-CERT, CCN-CERT, ENISA, BOE). Los datos del incidente (fechas, horas, nombres, cifras) son **ficticios o marcadores** `[entre corchetes]`. La normativa cambia: antes de entregar, vuelve a comprobar cada enlace y la vigencia de cada norma.

## 5.1 Modelo de comunicación interna del incidente

### Principios

1. **Un solo portavoz** y un único mensaje coordinado (responsable de seguridad + comunicación).
2. **Canal alternativo fuera de banda** (teléfono, mensajería corporativa externa o reunión presencial): el correo puede estar comprometido.
3. **Necesidad de conocer:** cada público recibe solo la información que necesita; los detalles técnicos y los IoC se restringen (clasificación TLP).
4. **Mensajes verificables y sin especulación:** se distingue entre *hechos confirmados*, *hipótesis* y *acciones*.
5. **Cadencia fija** de actualizaciones (p. ej. cada 2 horas en fase crítica) y registro de cada comunicación en la bitácora.
6. **Nunca** se culpa al empleado que abrió el adjunto (cultura sin culpa).

### Matriz de comunicación

| Público | Cuándo | Contenido | Canal | Responsable |
|---|---|---|---|---|
| Comité de crisis (dirección, seguridad, sistemas, legal/DPD, comunicación) | Inmediato (T+1 h) y cada 2 h | Estado, impacto, decisiones que requieren aprobación | Reunión/llamada | Resp. de seguridad |
| Dirección general | Tras clasificar | Resumen ejecutivo, riesgo legal, decisiones pendientes | Informe breve + llamada | Resp. de seguridad |
| Delegado de Protección de Datos (DPD) / asesoría jurídica | Inmediato si hay datos personales | Datos posiblemente afectados, plazos RGPD | Llamada + correo cifrado | Resp. de seguridad |
| Empleados (general) | Tras contener | Qué ocurre, qué hacer y qué no | Canal alternativo / aviso en persona | Comunicación |
| Empleados destinatarios del phishing | T+1-2 h | Instrucción concreta de no abrir/reportar | Teléfono / mensajería | Soporte N1 |
| Clientes afectados | Si procede (art. 34 RGPD) | Hechos, riesgos y medidas recomendadas | Comunicación individual | Dirección + DPD |
| Proveedores/terceros afectados | Si les afecta | Indicadores y acciones | Contacto directo | Resp. de seguridad |
| Autoridades y CSIRT | Según 5.2 y 5.3 | Notificaciones formales | Canales oficiales | Resp. de seguridad / DPD |

### Plantilla 1: comunicación inicial a la dirección

> **Asunto:** [CONFIDENCIAL – TLP:AMBER] Incidente de seguridad INC-2026-[0001]: informe inicial
>
> **Fecha y hora:** [dd/mm/aaaa hh:mm] · **Estado:** [Contención en curso]
>
> **Qué ha pasado (hechos confirmados):** Varios empleados han recibido un correo fraudulento que simula proceder de Recursos Humanos. Un usuario ha ejecutado un archivo adjunto malicioso en su equipo. Informática ha detectado conexiones sospechosas hacia IP externas, alertas del antivirus e intentos de acceso a carpetas compartidas.
>
> **Qué sospechamos (hipótesis no confirmadas):** Posible extracción de datos personales de clientes.
>
> **Impacto actual:** Un equipo comprometido [confirmado]; [N] equipos en revisión; servicios [operativos / degradados].
>
> **Acciones realizadas:** Aislamiento del equipo, bloqueo de la IP/dominio, revocación de credenciales, preservación de evidencias.
>
> **Decisiones que necesitamos de la dirección:** (1) autorizar [la notificación a la AEPD/INCIBE-CERT]; (2) autorizar la reconstrucción de equipos; (3) designar portavoz.
>
> **Próxima actualización:** [hh:mm]. **Contacto:** [nombre, móvil].

### Plantilla 2: comunicación a todos los empleados

> **Asunto:** Aviso importante de seguridad: lee este mensaje
>
> Hemos detectado un correo fraudulento que aparenta venir de Recursos Humanos, con asunto «[asunto]». **No es legítimo.**
>
> **Qué debes hacer:**
> - Si lo has recibido y **no lo has abierto**: no lo abras ni lo reenvíes; avisa a Informática (ext. [XXXX]).
> - Si **lo has abierto o has hecho clic**: desconecta el cable de red/Wi-Fi, **no apagues el equipo** y llama ya a Informática.
> - No compartas tu contraseña con nadie; Informática nunca te la pedirá por correo.
>
> Es posible que te pidamos cambiar tu contraseña en las próximas horas. Gracias por tu colaboración: **avisar pronto ayuda a todos.**
>
> Más información: [canal alternativo]. Responsable: [nombre].

### Plantilla 3: comunicación a clientes afectados (si procede, art. 34 RGPD)

> **Asunto:** Información sobre un incidente de seguridad que puede afectar a tus datos
>
> Te escribimos para informarte de que el [fecha] detectamos un incidente de seguridad en nuestros sistemas que **puede haber afectado a datos personales tuyos** ([categorías: nombre, correo, teléfono…]).
>
> **Qué ha pasado:** [descripción breve y clara]. **Posibles consecuencias:** [p. ej. recepción de correos fraudulentos].
>
> **Qué hemos hecho:** [medidas]. **Qué te recomendamos:** desconfiar de mensajes que mencionen este incidente, no facilitar contraseñas y [cambiar tu contraseña si usas la misma en otros servicios].
>
> **Contacto:** [DPD, correo, teléfono]. Hemos [notificado/vamos a notificar] el incidente a la Agencia Española de Protección de Datos.

> <img width="805" height="355" alt="image" src="https://github.com/user-attachments/assets/1395e5b5-519f-4a16-8dd1-24719dd0c627" />

## 5.2 Notificación de una brecha de datos personales a la AEPD

### Qué es una brecha de datos personales

Según la AEPD, es un incidente de seguridad que ocasiona la **destrucción, pérdida o alteración**, accidental o ilícita, de datos personales, o la **comunicación o acceso no autorizados** a ellos (art. 4.12 RGPD). El caso describe un posible **acceso y extracción no autorizados** de datos de clientes: encaja en la definición (brecha de **confidencialidad**).

### Cuándo y cómo se notifica (art. 33 RGPD)

| Aspecto | Regla |
|---|---|
| Obligado | El **responsable del tratamiento** (la empresa). Si interviene un **encargado**, este debe avisar al responsable **sin dilación** |
| Autoridad | **AEPD** si el único establecimiento está en España (u otra autoridad autonómica competente, p. ej. en Cataluña, País Vasco o Andalucía en su ámbito) |
| Plazo | **Sin dilación indebida y, de ser posible, ≤ 72 h desde que se tiene constancia** de la brecha |
| Cómputo | Se cuentan las horas **naturales**, incluidos fines de semana y festivos |
| Excepción | No se notifica si es **improbable** que la brecha entrañe riesgo para derechos y libertades; **debe documentarse** la decisión |
| Información incompleta | Se permite notificar **por fases** (art. 33.4): notificación inicial y, después, modificaciones |
| Retraso | Si se supera el plazo, hay que **justificar** los motivos |
| Registro | Toda brecha, notificada o no, se **documenta** (art. 33.5): hechos, efectos y medidas |
| Vía | **Formulario electrónico de la Sede Electrónica de la AEPD**; identificación con certificado electrónico o Cl@ve |
| Ayuda | Herramienta **Asesora Brecha** (decidir si notificar a la AEPD) y **Comunica-Brecha RGPD** (decidir si comunicar a los afectados) |

**¿Cuándo corre el reloj?** Desde que la empresa tiene **constancia razonable** de que ha ocurrido una brecha de datos personales, no desde que termina el análisis forense. En el caso, la constancia se sitúa cuando el análisis confirma (o hace razonablemente probable) el acceso a datos personales de clientes; se anota la hora exacta en la ficha del incidente (apartado 2.6).

### Contenido mínimo de la notificación (art. 33.3)

1. **Naturaleza de la brecha:** categorías y número aproximado de interesados y de registros afectados.
2. **Contacto** del DPD o de otro punto de contacto.
3. **Posibles consecuencias** de la brecha.
4. **Medidas adoptadas o propuestas** para remediarla y mitigar sus efectos.

### Árbol de decisión aplicado al caso

| Pregunta | Respuesta en el caso | Consecuencia |
|---|---|---|
| ¿Hay datos personales implicados? | Sí (clientes) | Es una posible brecha RGPD |
| ¿Se ha producido acceso, pérdida o alteración no autorizados? | Acceso a carpetas con datos y conexiones salientes sospechosas | Hay brecha, al menos probable |
| ¿Es improbable que haya riesgo para los afectados? | No: datos identificativos de clientes, posible exfiltración | **Notificar a la AEPD en ≤ 72 h** |
| ¿El riesgo es **alto** para los afectados? (identidad, fraude, datos financieros o sensibles, volumen) | Depende de las categorías y del volumen exfiltrado | Si **alto**: además **comunicar a los afectados** (art. 34) |
| ¿Había medidas que hagan ininteligibles los datos (cifrado fuerte)? | Valorar | Si los datos estaban cifrados y la clave no se ha visto comprometida, puede reducir el riesgo |

**Factores para valorar la gravedad** (guías de la AEPD y del Comité Europeo de Protección de Datos): tipo y sensibilidad de los datos, volumen, facilidad de identificación, gravedad de las consecuencias, personas vulnerables, naturaleza del responsable y número de afectados.

### Cronología recomendada de notificación

| Hora | Acción |
|---|---|
| T0 | Constancia de la posible brecha: se registra la hora y se avisa al DPD |
| T0 + 24 h | Evaluación de riesgo documentada (hechos, datos y personas afectadas) |
| T0 + 48 h | Borrador del formulario con la información disponible; decisión de la dirección |
| **≤ T0 + 72 h** | **Presentación en la Sede Electrónica de la AEPD** (aunque sea incompleta, indicando que se ampliará) |
| Después | Notificación modificada con nueva información; comunicación a afectados si riesgo alto |

### Consecuencias del incumplimiento

El RGPD prevé sanciones administrativas por infringir las obligaciones de los arts. 33 y 34 (art. 83.4: hasta 10 millones de euros o el 2 % del volumen de negocio anual global, la cifra mayor). Además, si la brecha deriva de medidas de seguridad insuficientes (art. 32), también puede sancionarse. *(Confirma el texto vigente de los arts. 83 RGPD y 73-74 LOPDGDD antes de citarlos.)*

### Otras notificaciones que pueden proceder

| Destinatario | ¿Procede? |
|---|---|
| **INCIBE-CERT** | Recomendable para recibir apoyo; **obligatorio** solo si la entidad es operador crítico, de servicios esenciales o proveedor de servicios digitales (RD-ley 12/2018 y RD 43/2021), o entidad esencial/importante cuando NIS2 esté transpuesta |
| **Fuerzas y Cuerpos de Seguridad** | Si hay indicios de delito (acceso ilícito, estafa, extorsión): denuncia ante Policía Nacional o Guardia Civil (unidades especializadas en delitos informáticos) |
| **Aseguradora (ciberseguro)** | Si existe póliza, avisar en el plazo contractual |
| **Clientes/proveedores** | Si sus datos o sistemas se ven afectados o lo exige el contrato |
| **Regulador sectorial** | Si la empresa es de un sector regulado (financiero, sanitario, telecomunicaciones) |

> <img width="807" height="332" alt="image" src="https://github.com/user-attachments/assets/5568786a-9b25-44ef-b3d7-8944d13f23db" />

## 5.3 Organismos CERT/CSIRT

### Conceptos

Un **CSIRT/CERT** (*Computer Security Incident Response Team*) es un equipo que recibe, analiza y responde a incidentes de seguridad para una **comunidad de referencia** (*constituency*). Sus servicios típicos (marco de servicios de FIRST): gestión de incidentes, análisis y coordinación, alerta temprana, gestión de vulnerabilidades, difusión de buenas prácticas y formación. **No sustituyen** a la empresa: apoyan, orientan y coordinan.

### Mapa de organismos en España

| Equipo | Organismo | Comunidad de referencia |
|---|---|---|
| **INCIBE-CERT** | INCIBE (Ministerio para la Transformación Digital) | Ciudadanía, **empresas y entidades de derecho privado**, operadores de servicios esenciales y RedIRIS |
| **CCN-CERT** | Centro Criptológico Nacional (CNI) | **Sector público**, empresas y organizaciones de interés estratégico y sistemas con información clasificada |
| **ESPDEF-CERT** | Mando Conjunto del Ciberespacio | Ámbito de la **defensa** |
| CERT sectoriales/autonómicos | p. ej. CSIRT-CV, CESICAT, Andalucía CERT | Administraciones y sectores propios |

### Equipo 1: INCIBE-CERT (principal para esta empresa)

| Aspecto | Descripción |
|---|---|
| Naturaleza | CSIRT de referencia para **ciudadanos y entidades de derecho privado**, operado por INCIBE |
| Funciones principales | Recibir y analizar incidentes; **apoyar en la respuesta**; contacto con proveedores de Internet y otros CERT nacionales e internacionales para limitar el incidente; alertas y avisos; vigilancia de amenazas; guías y buenas prácticas; coordinación en incidentes a gran escala |
| Qué **no** hace | Sustituir al responsable del sistema ni realizar su gestión interna del incidente |
| Cómo contactar | Formulario de «Reporta tu incidente» en incibe.es/incibe-cert; **línea de ayuda 017** (gratuita y confidencial); servicios para empresas colaboradoras a través del Portal de Servicios a Entidades Privadas (PSE; información en `servicios@incibe-cert.es`) |
| Qué aportar | Descripción del incidente, cronología, sistemas afectados, **IoC** (IP, dominios, hashes), cabeceras del correo, logs relevantes |
| Qué recibe la empresa | Orientación técnica para contener y erradicar, análisis de IoC, coordinación con terceros (hosting, registradores, otros CERT) y recomendaciones |
| Caso aplicable | Reportar el phishing, la IP/dominio de C2 y el hash del adjunto para su bloqueo y para proteger a otras entidades |

### Equipo 2: CCN-CERT

| Aspecto | Descripción |
|---|---|
| Naturaleza | **CERT gubernamental nacional**, del Centro Criptológico Nacional (CCN-CNI) |
| Comunidad | Sector público y entidades obligadas por el **ENS**, empresas de interés estratégico y sistemas clasificados |
| Funciones | Gestión de ciberincidentes del sector público; **alerta temprana y vigilancia** (SAT, sondas); análisis de malware y amenazas; guías **CCN-STIC** (p. ej. CCN-STIC 817 de gestión de ciberincidentes); formación y concienciación; coordinación nacional e internacional |
| Herramientas | **LUCIA** (gestión y notificación de ciberincidentes), **CLARA** (cumplimiento técnico), **PILAR** (análisis de riesgos), **REYES** (intercambio de inteligencia), **INES** (informe del estado de la seguridad) |
| Notificación | Las entidades del ámbito del ENS notifican por **LUCIA** según la Instrucción Técnica de Seguridad de notificación de incidentes |
| ¿Cuándo recurrir? | Si la empresa **presta servicios al sector público** o sus sistemas se rigen por el ENS; si no, su vía principal es INCIBE-CERT |

### Equipo 3 (internacional): red de CSIRT de la UE (CSIRTs Network) y ENISA

| Aspecto | Descripción |
|---|---|
| Naturaleza | Red de **CSIRT nacionales designados por los Estados miembros y CERT-EU**; la Comisión Europea participa como observadora; **ENISA** ejerce la **secretaría** y presta apoyo a la coordinación |
| Misión | Intercambiar información, generar confianza y, cuando es posible, **coordinar la respuesta** ante incidentes, especialmente **transfronterizos** |
| Papel para la empresa | No atiende directamente a empresas privadas: se accede **a través del CSIRT nacional (INCIBE-CERT)**, que escala y coordina con los equipos homólogos de otros países |
| Cuándo es útil | Si la infraestructura del atacante, el hosting o el registrador están en otro país de la UE, o si hay víctimas en varios Estados |

### Otras redes y comunidades internacionales de referencia

| Organización | Función |
|---|---|
| **FIRST** (Forum of Incident Response and Security Teams) | Comunidad mundial de equipos de respuesta; publica el marco de servicios CSIRT y facilita cooperación |
| **TF-CSIRT / Trusted Introducer** | Foro europeo de CSIRT, SOC y otros equipos |
| **CERT/CC** (Carnegie Mellon) | Coordinación de vulnerabilidades y análisis |
| **CISA** (EE. UU.) | Avisos y guías (#StopRansomware); catálogo KEV |
| **Europol EC3** | Cooperación policial en cibercrimen (a través de las Fuerzas y Cuerpos de Seguridad) |

### Tabla comparativa de los equipos investigados

| Criterio | INCIBE-CERT | CCN-CERT | CSIRTs Network (ENISA) |
|---|---|---|---|
| Ámbito | España, privado y ciudadanía | España, sector público y estratégico | Unión Europea |
| ¿Puede acudir esta empresa directamente? | **Sí** | Solo si presta servicios al sector público / ENS | No: a través de INCIBE-CERT |
| Tipo de ayuda | Respuesta, análisis de IoC, coordinación, alertas | Respuesta, herramientas, guías, alerta temprana | Coordinación transfronteriza |
| Canal | Web, 017, PSE | LUCIA y canales del CCN | Entre CSIRT nacionales |
| Coste | Gratuito | Gratuito (para su comunidad) | N/A |

### Qué se comparte con un CSIRT y cómo

| Elemento | Tratamiento |
|---|---|
| IoC (IP, dominio, hash) | Se envían «defangeados» y con contexto (cuándo y cómo se observaron) |
| Correo original | Cabeceras completas y adjunto, en contenedor cifrado y con hash |
| Logs | Solo los necesarios, minimizando datos personales |
| Clasificación TLP | **TLP:AMBER** (distribución limitada) por defecto |
| Contacto técnico | Persona de guardia disponible en horario de crisis |

> <img width="806" height="367" alt="image" src="https://github.com/user-attachments/assets/8f8944d0-fa32-4e11-9501-8bbd67cf3557" />

> <img width="803" height="330" alt="image" src="https://github.com/user-attachments/assets/f428f9b7-aa0e-4e7d-b406-be671038db92" />

## 5.4 Responsables y plazos (resumen)

| Notificación | Responsable | Aprobador | Plazo | Vía |
|---|---|---|---|---|
| Comité de crisis | Resp. de seguridad | Dirección | Inmediato | Llamada/reunión |
| **AEPD** | **DPD / Resp. de seguridad** | **Dirección** | **≤ 72 h desde la constancia** | Sede Electrónica |
| Afectados (alto riesgo) | Dirección + DPD | Dirección | Sin dilación indebida | Individual |
| INCIBE-CERT | Resp. de seguridad | Resp. de seguridad | Lo antes posible | Web/017 |
| Fuerzas de seguridad | Dirección/Legal | Dirección | Cuando haya indicios de delito | Denuncia |
| Aseguradora | Dirección | Dirección | Según póliza | Contacto del seguro |

*(La matriz RACI de actuación se corresponde con la de la UD1: la dirección aprueba la notificación a la AEPD; el responsable de seguridad la ejecuta.)*

## 5.5 Fuentes y referencias

- AEPD – Notificación de brechas de datos personales a la autoridad de control: https://www.aepd.es/es/derechos-y-deberes/cumple-tus-deberes/medidas-de-cumplimiento/brechas-de-seguridad
- AEPD – Nuevo formulario de notificación de brechas (notificación por fases): https://www.aepd.es/prensa-y-comunicacion/notas-de-prensa/nuevo-formulario-notificacion-brechas-datos-personales
- AEPD – Asesora Brecha y Comunica-Brecha RGPD: https://www.aepd.es/prensa-y-comunicacion/notas-de-prensa/la-aepd-lanza-una-herramienta-para-ayudar-los-responsables
- AEPD – Guía para la notificación de brechas de datos personales: https://www.aepd.es/guias/guia-brechas-seguridad.pdf
- Reglamento (UE) 2016/679 (RGPD), arts. 4.12, 32, 33, 34 y 83: https://eur-lex.europa.eu
- INCIBE-CERT – Respuesta a incidentes: https://www.incibe.es/incibe-cert/incidentes/respuesta-incidentes
- INCIBE-CERT – Servicios: https://www.incibe.es/incibe-cert/servicios
- INCIBE – Reporta tu incidente: https://www.incibe.es/empresas/te-ayudamos/reporta-tu-incidente
- Guía Nacional de Notificación y Gestión de Ciberincidentes: https://www.incibe.es/incibe-cert/blog/conoces-guia-nacional-notificacion-y-gestion-ciberincidentes
- CCN-CERT – Portal y soluciones (LUCIA, CLARA, PILAR, REYES): https://www.ccn-cert.cni.es
- CCN-STIC 817 – Gestión de ciberincidentes (ENS): https://www.ccn-cert.cni.es
- Orden/Resolución sobre notificación de incidentes en el ENS (ITS): https://www.boe.es (BOE-A-2018-5370)
- ENISA – CSIRTs Network: https://www.enisa.europa.eu/topics/eu-cyber-crisis-and-incident-management/csirts-network
- FIRST – CSIRT Services Framework: https://www.first.org
- TF-CSIRT: https://tf-csirt.org
- Real Decreto-ley 12/2018 y Real Decreto 43/2021 (seguridad de redes y sistemas de información): https://www.boe.es
- Directiva (UE) 2022/2555 (NIS2): https://eur-lex.europa.eu
- Real Decreto 311/2022 (ENS): https://www.boe.es

---

# 6. Simulación de crisis (ejercicio de mesa)

## 6.1 Ficha del ejercicio

| Campo | Contenido |
|---|---|
| Tipo | Ejercicio de mesa (*tabletop exercise*) de respuesta a incidentes |
| Duración | 45-60 min (+ 15 min de debate y cierre) |
| Escenario | Phishing «de Recursos Humanos» → ejecución de adjunto → C2 → sospecha de exfiltración de datos de clientes |
| Objetivos | (1) Validar el procedimiento PR-SEG-010 (apartado 4). (2) Practicar la toma de decisiones bajo presión. (3) Comprobar los plazos de notificación (apartado 5). (4) Detectar lagunas del plan |
| Alcance | Toma de decisiones y comunicación; **no** se ejecutan acciones reales sobre sistemas |
| Reglas | Sin culpables; las decisiones se **justifican** con hechos, riesgo y procedimiento; se registra todo en la bitácora; ante la duda, se prioriza **preservar evidencias y contener** |

### Participantes (roles)

| Rol | Persona (ficticia) | Responsabilidad en el ejercicio |
|---|---|---|
| **Director del incidente / Resp. de seguridad** | Marta Ríos | Coordina, decide la clasificación y propone acciones |
| **Sistemas / N2 (técnico de respuesta)** | Luis Cano | Contiene, investiga y recupera |
| **Soporte N1** | Eva Soto | Recibe avisos, registra tickets, atiende a usuarios |
| **DPD / Legal** | Andrés Vidal | Evalúa la brecha RGPD y los plazos |
| **Comunicación** | Irene Pardo | Portavoz y mensajes internos/externos |
| **Dirección general** | Carlos Núñez | Aprueba decisiones y acepta el riesgo residual |
| **Moderador / «Control»** (voz del escenario) | — | Introduce las circunstancias nuevas (*injects*) |

### Material de partida

- Ficha del incidente INC-2026-0001 (apartado 2.6) y bitácora abierta.
- IoC: IP `203[.]0[.]113[.]45`, dominio `rrhh-empresa-portal[.]example`, hash del adjunto `[SHA-256]`.
- Equipo comprometido confirmado: `PC-RRHH-07` (usuario `jperez`), aislado.
- Estado inicial: gravedad **Crítica** (provisional), reloj RGPD **aún sin constancia confirmada**.

## 6.2 Línea temporal y circunstancias nuevas (*injects*)

| Hora | Elemento | Tipo |
|---|---|---|
| 08:15 | Situación inicial y primeras decisiones | Base |
| 08:40 | **INJECT 1:** Se descubre **otro equipo infectado** | Alcance |
| 09:05 | **INJECT 2:** Aparecen **indicios de extracción de información** | Datos / legal |
| 09:30 | **INJECT 3:** El atacante **mantiene acceso** a la infraestructura | Persistencia |
| 09:50 | **INJECT 4:** La **dirección exige recuperar los servicios inmediatamente** | Presión |
| 10:10 | Cierre, decisiones finales y lecciones aprendidas | Cierre |

## 6.3 Guion de la reunión

### Escena 0: apertura (08:15)

**Marta (Director):** Buenos días. Abro el incidente **INC-2026-0001**, nivel **Crítico provisional**, prioridad **P1**. Hechos confirmados: un empleado ejecutó un adjunto de un correo que suplanta a RR. HH.; el antivirus alertó; hay conexiones salientes a `203[.]0[.]113[.]45`; hubo intentos de acceso a carpetas compartidas. Hipótesis sin confirmar: exfiltración de datos de clientes. Reglas: **aislar, no apagar; bitácora desde el minuto uno; canal alternativo fuera del correo.** Luis, ¿estado?

**Luis (Sistemas):** `PC-RRHH-07` está **aislado de la red desde las 08:07** y sigue encendido. Tengo capturados RAM y estado de red; hashes calculados y cadena de custodia abierta (E01-E03). La IP y el dominio están **bloqueados** en cortafuegos y DNS. Cuenta `jperez` deshabilitada y contraseña restablecida.

**Eva (N1):** He recibido 11 avisos más de empleados que recibieron el mismo correo. Nueve no lo abrieron; dos dicen que sí.

**Marta:**  Eva, llama a esos dos ahora (no por correo) y pídeles que desconecten el equipo sin apagarlo. ✅ Luis, purga el mensaje de todos los buzones y busca el hash del adjunto en la red. Andrés, quedas avisado: hay posible acceso a datos personales.

**Andrés (DPD):** Anotado. Todavía **no hay constancia** de brecha de datos personales; la **registro como posible** y empiezo a preparar la evaluación del art. 33.

---

### Escena 1: INJECT 1: «Otro equipo infectado» (08:40)

**[Control]:** *Luis recibe una alerta de Wazuh: `PC-CONT-12` (equipo de Contabilidad) lleva ejecutando desde las 07:52 un proceso `svchost.exe` en `%APPDATA%` que se conecta cada 60 s al mismo dominio. El usuario era uno de los dos que abrió el correo. Además, entre `PC-RRHH-07` y `PC-CONT-12` hay tráfico SMB reciente.*

**Luis:** Esto cambia el alcance. No es solo un equipo: hay **segundo equipo comprometido** y posible **movimiento lateral** por SMB.

**Marta:**  ¿Qué sabemos del movimiento lateral?  ¿Qué credenciales usó?

**Luis:** En el DC veo un 4624 tipo 3 de `jperez` hacia `PC-CONT-12` a las 07:58 y un 4672 de una cuenta con privilegios. Podría haber usado credenciales cacheadas.

**Marta:**  **Decisiones:**
1. Aislar `PC-CONT-12` **sin apagarlo** y capturar su RAM antes de nada.
2. **Ampliar la búsqueda** de IoC a toda la red (hash, IP, dominio, tareas programadas, SMB entre estaciones).
3. **Reevaluar el nivel:** se confirma **Crítico** (más de un equipo + cuenta privilegiada).
4. Tratar como **comprometidas todas las cuentas** que iniciaron sesión en ambos equipos; incluye a la cuenta administradora implicada.
5. Informar a la dirección en 15 minutos.

**Justificación técnica y táctica**

| Decisión | Por qué |
|---|---|
| Aislar, no apagar | La RAM contiene procesos, claves y conexiones que se perderían |
| Ampliar la búsqueda | Un segundo equipo indica que la entrada no era un caso único; hay que acotar el alcance real |
| Reclasificar | El nivel lo marca el mayor entre peligrosidad e impacto; el movimiento lateral con privilegios eleva el riesgo para el AD |
| Tratar cuentas como comprometidas | Las credenciales en memoria pueden haberse extraído; sin revocarlas, la contención es ilusoria |
| Bloquear SMB entre estaciones | Corta la propagación lateral sin impactar a servidores |

---

### Escena 2: INJECT 2: «Indicios de extracción de información» (09:05)

**[Control]:** *Wazuh y el cortafuegos muestran que, entre las 02:10 y las 03:40 de la madrugada, un proceso en `PC-RRHH-07` envió unos **2,3 GB** hacia `203[.]0[.]113[.]45` por HTTPS. El servidor de ficheros registra eventos 5145 con la cuenta `jperez` sobre la carpeta `\\SRV-FICH\Clientes` (~38.000 ficheros leídos).*

**Andrés (DPD):** Esto ya es **constancia razonable** de que hubo acceso a datos personales de clientes. **El reloj de las 72 horas empieza a contar desde las 09:05 de hoy.** Los datos de la carpeta incluyen nombre, DNI, dirección, correo y teléfono; no veo tarjetas ni datos de salud.

**Marta:**  ¿Qué sabemos del contenido exacto?

**Luis:** Los 5145 indican qué ficheros se **leyeron**, no necesariamente cuáles salieron. El volumen de 2,3 GB es compatible con una parte importante de la carpeta.

**Carlos (Dirección):** ¿Tenemos que decírselo a la AEPD? ¿Y a los clientes? ¿Nos pueden multar?

**Andrés:** Debemos **notificar a la AEPD en ≤ 72 h** salvo que sea improbable el riesgo; aquí **no es improbable**. Se puede hacer **por fases**. La comunicación a los clientes (art. 34) depende de si el riesgo es **alto**: con DNI + dirección + contacto, hay riesgo de suplantación y *phishing* dirigido, así que **lo más prudente es prepararla**.

**Marta:**  **Decisiones:**
1. **Registrar la hora de constancia (09:05)** en la ficha y fijar el límite de notificación a la AEPD en **[fecha de hoy] 09:05 + 72 h** (calcula la fecha límite real).
2. Andrés prepara el **formulario de la AEPD** con la información disponible; **notificación inicial** antes de las 24-48 h y ampliación posterior.
3. **Preservar los logs** (cortafuegos, 5145, Sysmon, pcap) con hash: serán la base para cuantificar el alcance.
4. **Comunicar al CSIRT** (INCIBE-CERT) con los IoC; **valorar denuncia** a Policía Nacional/Guardia Civil.
5. Preparar el **comunicado a clientes** (plantilla 3) para su envío cuando la dirección lo apruebe.
6. Avisar a la **aseguradora** si hay ciberseguro.

**Justificación técnica, legal y táctica**

| Decisión | Por qué |
|---|---|
| Fijar la hora de constancia | El plazo del art. 33 corre desde que se tiene constancia, no desde el fin del forense; hay que acreditar la fecha |
| Notificar por fases | El art. 33.4 lo permite; es mejor una notificación inicial incompleta que una tardía |
| Conservar logs con hash | Permiten acotar categorías y número de afectados (contenido obligatorio de la notificación) |
| Preparar la comunicación a afectados | Si el riesgo es alto, deben poder protegerse; prepararla evita improvisar |
| Avisar al CSIRT | Ayuda a bloquear la infraestructura del atacante y a proteger a otras víctimas |
| Denuncia | Hay indicios de delito (acceso ilícito y posible revelación de datos) |

**Carlos (Dirección):** Entendido. Autorizo la notificación a la AEPD y a INCIBE-CERT. Sobre los clientes, lo decidimos cuando Andrés cuantifique el alcance, pero **prepárenlo hoy**.

---

### Escena 3: INJECT 3: «El atacante mantiene el acceso» (09:30)

**[Control]:** *Pese al bloqueo, a las 09:22 aparece un **inicio de sesión VPN correcto** desde una IP extranjera (`198[.]51[.]100[.]77`) con la cuenta de **otra usuaria** (`mgarcia`), que no recibió el phishing. En el DC aparece una **tarea programada nueva** creada a las 04:05 en `SRV-FICH` y una **cuenta de dominio nueva** (`svc_backup2`) añadida a «Administradores». El tráfico a la IP bloqueada ha cesado, pero Wazuh detecta DNS hacia un dominio nuevo (`cdn-sync[.]example`).*

**Luis:** El atacante **sigue dentro**. Tiene credenciales de otra cuenta, persistencia en el servidor de ficheros y una cuenta administradora creada por él. Y ya no usa la IP que bloqueamos: ha **cambiado de infraestructura**.

**Marta:**  Si actuamos por piezas, avisamos al atacante y puede borrar huellas o acelerar.  Si no actuamos, mantiene el acceso. ¿Qué hacemos?

**Luis:** Propongo una **expulsión coordinada**: se prepara todo y se ejecuta **de una vez**. Mientras, vigilancia pasiva y sin tocar nada que lo alerte.

**Marta:**  **Decisiones:**
1. **Evaluar el DC como posiblemente comprometido:** nueva cuenta administradora + tarea programada + credenciales. Se activa la hipótesis de **compromiso del dominio**.
2. **Preparar la expulsión coordinada** (ventana corta, p. ej. 30-45 min) con estas acciones simultáneas:
   - deshabilitar `svc_backup2` y `mgarcia`, **revocar sesiones VPN** y exigir MFA;
   - eliminar la tarea programada **tras copiarla como evidencia**;
   - **bloquear** el nuevo dominio y la IP VPN de origen;
   - **restablecer contraseñas** de todas las cuentas privilegiadas y de servicio;
   - **doble reset de `krbtgt`** (con espera entre ambos), planificado y comunicado.
3. **Capturar evidencias del DC y del servidor de ficheros** (RAM, logs, tareas, registro) **antes** de la expulsión.
4. **Contratar/solicitar apoyo externo** (equipo DFIR especializado y consulta a INCIBE-CERT) por la posible afectación del DC.
5. **Vigilancia reforzada** 24×7 durante la expulsión y los 14 días siguientes.
6. Revisar **copias de seguridad**: ¿están accesibles desde las cuentas comprometidas? Verificar que son **offline/inmutables**.

**Justificación técnica y táctica**

| Decisión | Por qué |
|---|---|
| Hipótesis de compromiso de dominio | Una cuenta administradora creada por el atacante implica control de privilegios; sin cubrirlo, cualquier restauración es insegura |
| Expulsión coordinada | La contención por piezas alerta al adversario y favorece nuevas puertas traseras; hacerlo a la vez reduce su margen de reacción |
| Evidencias antes de actuar | La expulsión modifica el estado; sin captura previa se pierden pruebas para el forense y la notificación |
| `krbtgt` doble reset | Invalida tickets Kerberos falsificados (*golden ticket*); se hace solo ante sospecha de compromiso del DC y con planificación |
| Apoyo externo | La empresa no tiene capacidad de DFIR de dominio; un error en el DC tiene impacto en toda la organización |
| Verificar copias | Si el atacante llegó al backup, restaurar desde ellas reinfectaría |

---

### Escena 4: INJECT 4: «La dirección exige recuperar los servicios inmediatamente» (09:50)

**[Control]:** *Carlos recibe llamadas de ventas: la tienda online y el servidor de ficheros están degradados por el aislamiento. Un cliente importante amenaza con cancelar. Carlos entra en la sala.*

**Carlos (Dirección):** Llevamos horas sin facturar. Quiero **todo reactivado ya**. Restauremos desde copia, ¡hoy! Aislar es una cosa, pero no podemos parar el negocio.

**Marta:** Entiendo la presión y la compartimos. Pero **si reactivamos ahora, repetimos el incidente**: el atacante sigue dentro y aún no hemos erradicado. Propongo una **recuperación escalonada con criterios de salida**.

**Carlos:** ¿Cuánto tiempo?

**Luis:** Con la expulsión coordinada esta tarde, los servicios mínimos podrían reactivarse en **4-8 h**; el servidor de ficheros, en **24 h** tras reconstruirlo desde copia limpia.

**Marta:**  **Decisiones:**
1. **No se restaura nada hasta completar la expulsión y la erradicación** en el segmento afectado.
2. **Servicios por prioridad** (apartado 4.2): red/DNS → AD → **ficheros** → correo → web. Se reactivan **solo cuando cumplan el checklist de salida**.
3. **Plan de continuidad** inmediato: la web pasa a **página estática de mantenimiento** y pedidos por teléfono/correo alternativo; ventas usa un **fichero temporal de solo lectura**, sin datos personales sensibles.
4. Restaurar **solo desde copias anteriores a la fecha de compromiso**, escaneadas y en red aislada.
5. **Riesgo residual por escrito:** Carlos firma que acepta el calendario y los riesgos si decide acelerar.
6. **Un solo portavoz** (Irene) para clientes y prensa; mensaje con hechos y calendario.

**Justificación técnica y táctica**

| Decisión | Por qué |
|---|---|
| No restaurar antes de erradicar | Restaurar con el atacante dentro devuelve el control al adversario y expone otra vez los datos |
| Orden por dependencias | Sin red, DNS e identidad, el resto de servicios no puede funcionar de forma segura |
| Plan alternativo para el negocio | Reduce el impacto económico mientras se hace bien la recuperación; responde a la presión sin comprometer la seguridad |
| Copia anterior al compromiso | Garantiza que lo restaurado está limpio; se fija con la cronología del apartado 3 |
| Riesgo residual firmado | La decisión de aceptar el riesgo es de la dirección, nunca «de palabra» |
| Un portavoz | Evita mensajes contradictorios y filtraciones |

**Checklist de reanudación acordado**

| Criterio | ☐ |
|---|:-:|
| Expulsión coordinada ejecutada y sin actividad del atacante durante [N] h | ☐ |
| Equipos/servidores comprometidos **reconstruidos** | ☐ |
| Credenciales rotadas (usuarios, servicio, admin, `krbtgt`) | ☐ |
| Restauración desde copia **limpia verificada** (hash) | ☐ |
| Monitorización reforzada y alertas sobre IoC activas | ☐ |
| Notificaciones legales en curso (AEPD / CSIRT) | ☐ |
| Riesgo residual aceptado por la dirección **por escrito** | ☐ |

**Carlos:** De acuerdo: prefiero 24 horas con un plan a 24 días con otro incidente. Firmo el calendario.

---

### Escena 5: cierre (10:10)

**Marta:** Resumen de decisiones: (1) alcance ampliado a un segundo equipo y reclasificación a Crítico; (2) constancia de brecha a las 09:05 y notificación a la AEPD en plazo, por fases; (3) expulsión coordinada del atacante con hipótesis de compromiso del dominio y apoyo externo; (4) recuperación escalonada con checklist y riesgo residual firmado. **Próximos pasos:** ejecutar la expulsión, notificar, restaurar por prioridad y celebrar la reunión de lecciones aprendidas en **14 días**.

## 6.4 Registro de decisiones (plantilla y ejemplo)

| ID | Hora | Situación | Decisión | Responsable | Justificación | Evidencia / procedimiento |
|---|---|---|---|---|---|---|
| D1 | 08:20 | Aviso inicial | Aislar y bloquear IoC | Luis | Contener sin perder RAM | PR-SEG-010 §4.1.1-4.1.2 |
| D2 | 08:55 | Segundo equipo | Aislar, ampliar búsqueda, reclasificar | Marta | Alcance y movimiento lateral | Apdo. 2.1, 4.1.1 |
| D3 | 09:20 | Exfiltración | Fijar constancia y preparar AEPD | Andrés | Art. 33 RGPD, 72 h | Apdo. 5.2 |
| D4 | 09:50 | Acceso persistente | Expulsión coordinada + apoyo externo | Marta | Evitar reentrada | Apdo. 4.1.3-4.1.4 |
| D5 | 10:10 | Presión de la dirección | Recuperación escalonada | Carlos/Marta | Evitar reinfección | Apdo. 4.2 |

> <img width="802" height="388" alt="image" src="https://github.com/user-attachments/assets/b3635fe5-361c-41b1-b593-da4f4aca130e" />

> <img width="805" height="301" alt="image" src="https://github.com/user-attachments/assets/a06028cd-9642-4d01-a96f-2f41db8594ff" />

> <img width="806" height="408" alt="image" src="https://github.com/user-attachments/assets/98d69a9d-7f2b-456d-a689-415e6fe19abd" />

## 6.5 Mensajes finales de comunicación

### Comunicado a la dirección tras el ejercicio

> **Asunto:** [TLP:AMBER] INC-2026-0001 · Resumen de decisiones y plan de 24 horas
>
> Se ha confirmado compromiso de **dos estaciones**, una cuenta privilegiada y **acceso persistente** del atacante. Hay indicios de **extracción de datos de clientes** (≈2,3 GB). La brecha se ha registrado el [fecha] a las 09:05; **notificaremos a la AEPD antes del [fecha límite]**. Estamos preparando la expulsión coordinada y la recuperación escalonada; el calendario estimado es de **[4-8] h para servicios mínimos** y **24 h** para ficheros. Se necesita su **firma de aceptación de riesgo residual**.

### Mensaje para clientes (nota de prensa interna/externa, si procede)

> Hemos detectado un incidente de ciberseguridad que ha afectado temporalmente a algunos de nuestros servicios. Estamos trabajando con especialistas y con las autoridades competentes. Informaremos individualmente a las personas cuyos datos personales puedan haberse visto afectados. Mientras tanto, desconfíe de mensajes que mencionen este incidente y no facilite contraseñas por correo ni teléfono.

## 6.6 Evaluación del ejercicio

| Criterio | Cómo se valora | Peso orientativo |
|---|---|:-:|
| Clasificación y reclasificación | Nivel justificado y revisado cuando cambian los hechos | 15 % |
| Contención y erradicación | Aislar sin apagar, expulsión coordinada, evidencias previas | 25 % |
| Cumplimiento legal | Constancia, plazo de 72 h, contenido de la notificación, art. 34 | 20 % |
| Gestión de la presión | Argumentos ante la dirección, plan alternativo, riesgo residual firmado | 20 % |
| Comunicación | Portavoz único, mensajes claros, canal alternativo | 10 % |
| Registro y trazabilidad | Bitácora completa, decisiones con justificación | 10 % |

### Errores típicos que el ejercicio debe evitar (y cómo)

| Error | Consecuencia | Corrección en este guion |
|---|---|---|
| Apagar equipos infectados | Pérdida de evidencia volátil | Aislar y capturar RAM (D1) |
| Contener por piezas | El atacante se adapta y persiste | Expulsión coordinada (D4) |
| Esperar al fin del forense para notificar | Incumplimiento del plazo RGPD | Fijar constancia y notificar por fases (D3) |
| Restaurar de inmediato | Reinfección | Criterios de salida (D5) |
| Decidir el riesgo residual «de palabra» | Falta de responsabilidad y de evidencia | Aceptación firmada |
| Culpar al empleado | Se oculta el siguiente incidente | Cultura sin culpa |

## 6.7 Defensa oral: preguntas probables y respuestas modelo

| Pregunta | Respuesta breve |
|---|---|
| ¿Por qué no apagaste el equipo infectado? | Porque se pierden procesos, conexiones y claves en memoria; aislar corta la comunicación y conserva la evidencia (RFC 3227). |
| ¿Cuándo empieza a contar el plazo de 72 h? | Desde la constancia razonable de la brecha de datos personales, no desde el fin del análisis; se documenta la hora y se puede notificar por fases. |
| ¿Por qué una expulsión coordinada y no bloquear según aparecen los hallazgos? | Evita alertar al atacante y dar tiempo a crear nuevas puertas; se prepara y se ejecuta a la vez, tras capturar evidencias. |
| ¿Por qué el doble reset de `krbtgt`? | Invalida los tickets Kerberos que el atacante pudiera haber falsificado; solo se hace ante sospecha de compromiso del DC y con espera entre resets. |
| ¿Qué haces si la dirección insiste en restaurar ya? | Explico el riesgo de reinfección, ofrezco servicios mínimos y alternativas, y pido la aceptación **por escrito** del riesgo residual. |
| ¿Hay que avisar a los clientes? | Si el riesgo es **alto** (DNI, dirección y contacto permiten suplantación), sí, sin dilación indebida (art. 34); se prepara en paralelo. |
| ¿Qué hace INCIBE-CERT por vosotros? | Orienta técnicamente, analiza IoC y coordina con otros equipos y proveedores; no sustituye a la empresa. |
| ¿Qué cambiarías en el plan tras el ejercicio? | Reglas de detección de nuevas cuentas privilegiadas y de VPN anómalo, copia inmutable verificada y contrato previo con un equipo DFIR. |

## 6.8 Lecciones aprendidas del ejercicio (modelo)

| Hallazgo | Causa | Acción correctiva | Responsable | Plazo |
|---|---|---|---|---|
| Un segundo equipo se detectó con retraso | Sin EDR en todos los equipos | Desplegar EDR y reglas de detección | Sistemas | 30 d |
| Credenciales reutilizadas permitieron movimiento lateral | Sin LAPS ni MFA en privilegiados | LAPS, MFA y modelo de administración por niveles | Sistemas | 30 d |
| Dudas sobre cuándo empieza el plazo de 72 h | Sin criterio documentado | Añadir al procedimiento el criterio de constancia y el responsable | DPD | 15 d |
| Alta presión de la dirección sin criterios previos | Sin RTO/RPO ni checklist acordados | Acordar RTO/RPO y checklist de reanudación | Dirección | 30 d |
| Faltan contactos y apoyo externo | Sin contrato DFIR ni contactos en papel | Contrato marco y lista impresa de contactos | Seguridad | 45 d |

## 6.9 Fuentes y referencias

- NIST SP 800-61 Rev. 3 – Incident Response: https://csrc.nist.gov
- NIST SP 800-84 – Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities: https://csrc.nist.gov
- CISA – Tabletop Exercise Packages (CTEP): https://www.cisa.gov
- INCIBE – Guías de gestión de incidentes y ejercicios de crisis: https://www.incibe.es
- CCN-CERT / CCN-STIC 817 – Gestión de ciberincidentes (ENS): https://www.ccn-cert.cni.es
- Guía Nacional de Notificación y Gestión de Ciberincidentes: https://www.incibe.es/incibe-cert
- AEPD – Guía para la notificación de brechas de datos personales (art. 33 y 34 RGPD): https://www.aepd.es
- RFC 3227 – Directrices para la recogida y archivo de evidencias: https://www.rfc-editor.org/rfc/rfc3227
- MITRE ATT&CK (persistencia, movimiento lateral, exfiltración): https://attack.mitre.org
- Apartados 2-5 de este documento (clasificación, evidencias, SOP y notificación)

