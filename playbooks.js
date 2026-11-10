// Protocolos de respuesta a incidentes (funcionan sin el modelo).
// Estructura basada en las fases de NIST SP 800-61: detectar, contener, erradicar, recuperar y aprender.
const PLAYBOOKS = [
  {
    id: "malware",
    title: "Malware o virus en un equipo",
    level: "Alta",
    desc: "Comportamiento extraño, archivos desconocidos o amenaza detectada.",
    phases: [
      ["Detectar y evaluar", [
        "Anota qué ves, cuándo empezó y qué hizo el usuario justo antes (descarga, adjunto, USB).",
        "Revisa si el antivirus detectó algo: nombre de la amenaza, ruta del archivo y acción tomada.",
        "Identifica qué otros equipos, cuentas o carpetas compartidas pueden estar afectados.",
      ]],
      ["Contener", [
        "Desconecta el equipo de la red (cable o Wi‑Fi). Déjalo encendido para no perder datos en memoria.",
        "Retira USB y discos externos, y no los uses en otros equipos.",
        "Cambia las contraseñas desde OTRO dispositivo limpio, nunca desde el infectado.",
        "Avisa al responsable de seguridad o a informática.",
      ]],
      ["Erradicar", [
        "Actualiza el antivirus y ejecuta un análisis completo. En Windows, como administrador: `Update-MpSignature` y `Start-MpScan -ScanType FullScan`.",
        "Para un análisis sin conexión en Windows: `Start-MpWDOScan` (reinicia el equipo).",
        "En Linux con ClamAV: `sudo freshclam` y `sudo clamscan -r --infected /home`.",
        "Revisa programas de inicio, tareas programadas y extensiones del navegador.",
        "Si no puedes garantizar que está limpio, reinstala el sistema desde un medio fiable.",
      ]],
      ["Recuperar", [
        "Restaura los archivos desde una copia de seguridad anterior a la infección.",
        "Aplica todas las actualizaciones del sistema y de los programas.",
        "Reconecta a la red y vigila el equipo durante los siguientes días.",
      ]],
      ["Después", [
        "Averigua cómo entró (adjunto, descarga, vulnerabilidad) y corrige esa causa.",
        "Documenta cronología, impacto y acciones realizadas.",
      ]],
    ],
  },
  {
    id: "ransomware",
    title: "Ransomware (archivos cifrados)",
    level: "Crítica",
    desc: "Archivos que no se abren, extensiones raras o una nota pidiendo un rescate.",
    phases: [
      ["Detectar y evaluar", [
        "Haz una foto o captura de la nota de rescate, y anota el nombre de la nueva extensión de los archivos.",
        "Identifica qué equipos y recursos compartidos están cifrados y cuáles siguen sanos.",
        "Comprueba que tus copias de seguridad existen y NO están cifradas ni conectadas a la red afectada.",
      ]],
      ["Contener", [
        "Aísla YA los equipos afectados: desconecta el cable de red y el Wi‑Fi. Si no puedes aislarlos, apágalos.",
        "Desconecta también discos externos, NAS y unidades de red.",
        "Deshabilita las cuentas que puedan estar implicadas y cambia las credenciales de administración desde un equipo limpio.",
        "No borres la nota ni los archivos cifrados: pueden servir para identificar la variante.",
      ]],
      ["Escalar y notificar", [
        "Avisa a la dirección y al responsable de seguridad.",
        "Contacta con INCIBE-CERT (línea 017) y denuncia ante Policía Nacional o Guardia Civil.",
        "Si hay datos personales afectados, valora notificar a la AEPD en un máximo de 72 horas.",
        "Antes de pensar en pagar, consulta con especialistas: el pago no garantiza recuperar los datos.",
      ]],
      ["Erradicar", [
        "Identifica la variante y consulta si existe un descifrador gratuito en nomoreransom.org.",
        "Busca cómo entraron (correo, acceso remoto expuesto, credenciales robadas) y ciérralo.",
        "Reinstala los equipos afectados desde una imagen limpia en lugar de limpiarlos.",
      ]],
      ["Recuperar", [
        "Restaura desde copias limpias, empezando por los sistemas más críticos.",
        "Cambia TODAS las contraseñas y claves que pudieran estar expuestas.",
        "Reconecta por fases y vigila de cerca durante varias semanas.",
      ]],
      ["Después", [
        "Mantén copias offline o inmutables y pruébalas periódicamente.",
        "Documenta el incidente y revisa el plan de respuesta.",
      ]],
    ],
  },
  {
    id: "phishing",
    title: "Phishing (correo o enlace sospechoso)",
    level: "Alta",
    desc: "Has recibido un mensaje sospechoso, o has hecho clic o dado tus datos.",
    phases: [
      ["Detectar y evaluar", [
        "No hagas más clics ni respondas al mensaje.",
        "Determina qué ocurrió: ¿solo lo recibiste, hiciste clic, abriste un adjunto o introdujiste credenciales?",
        "Guarda el mensaje original (con cabeceras) como evidencia antes de borrarlo.",
      ]],
      ["Contener", [
        "Si introdujiste credenciales: cambia esa contraseña YA desde un dispositivo seguro y cierra todas las sesiones abiertas.",
        "Activa la verificación en dos pasos en esa cuenta, y cambia la contraseña en otros servicios donde la repitas.",
        "Si abriste un adjunto o instalaste algo: trátalo como malware y desconecta el equipo de la red.",
        "Informa al equipo de TI y reenvía el mensaje por el canal oficial de reporte.",
      ]],
      ["Erradicar", [
        "Pide que se borre el mensaje de los demás buzones y que se bloquee el remitente y las URL.",
        "Revisa reglas de reenvío automático y aplicaciones con acceso a tu cuenta, y elimina lo que no reconozcas.",
        "Ejecuta un análisis completo del antivirus si hubo adjunto o descarga.",
      ]],
      ["Recuperar", [
        "Revisa la actividad reciente de la cuenta (inicios de sesión, mensajes enviados).",
        "Si se envió correo desde tu cuenta, avisa a tus contactos de que no abran esos mensajes.",
      ]],
      ["Después", [
        "Informa a tu equipo del intento para que lo reconozcan.",
        "Valora usar llaves de seguridad o aplicaciones de autenticación en lugar de SMS.",
      ]],
    ],
  },
  {
    id: "cuenta",
    title: "Cuenta comprometida",
    level: "Alta",
    desc: "Inicios de sesión extraños, mensajes que no enviaste o contraseña cambiada.",
    phases: [
      ["Detectar y evaluar", [
        "Revisa el historial de inicios de sesión: ubicaciones, dispositivos y horas inusuales.",
        "Busca cambios que no hiciste: contraseña, correo de recuperación, reglas de reenvío, firma.",
        "Determina a qué más da acceso esa cuenta (otros servicios, datos, pagos).",
      ]],
      ["Contener", [
        "Cambia la contraseña desde un dispositivo limpio. Usa una larga y única.",
        "Cierra todas las sesiones y revoca los tokens y aplicaciones conectadas.",
        "Activa la verificación en dos pasos, mejor con app o llave que con SMS.",
        "Si no puedes entrar, usa el proceso de recuperación del servicio o contacta con su soporte.",
      ]],
      ["Erradicar", [
        "Elimina reglas de reenvío, dispositivos de confianza y correos de recuperación que no reconozcas.",
        "Cambia las contraseñas de otras cuentas donde usaras la misma, empezando por correo y banca.",
        "Analiza con antivirus los dispositivos desde los que accedías por si hay un programa espía.",
      ]],
      ["Recuperar", [
        "Avisa a tus contactos si se enviaron mensajes en tu nombre.",
        "Revisa movimientos bancarios o compras si la cuenta estaba vinculada a pagos.",
      ]],
      ["Después", [
        "Usa un gestor de contraseñas para tener una distinta en cada servicio.",
        "Activa alertas de inicio de sesión en tus cuentas importantes.",
      ]],
    ],
  },
  {
    id: "brecha",
    title: "Fuga o brecha de datos personales",
    level: "Crítica",
    desc: "Datos enviados a quien no debía, publicados o accedidos sin permiso.",
    phases: [
      ["Detectar y evaluar", [
        "Determina qué datos se expusieron, de cuántas personas, desde cuándo y cómo ocurrió.",
        "Anota la fecha y hora exactas en que tuviste conocimiento de la brecha: arranca el plazo legal.",
        "Valora el riesgo para las personas afectadas (datos de salud, financieros, identidad).",
      ]],
      ["Contener", [
        "Corta el acceso: retira lo publicado, revoca credenciales o enlaces compartidos, cierra el fallo.",
        "Conserva las evidencias y los registros (logs) antes de cambiar nada.",
        "Avisa al delegado de protección de datos (DPD) y a la dirección.",
      ]],
      ["Notificar", [
        "Si hay riesgo para las personas, notifica a la AEPD en un máximo de 72 horas desde que lo supiste (art. 33 RGPD).",
        "Si el riesgo es alto, informa también a los afectados de forma clara (art. 34 RGPD).",
        "Si no notificas, documenta igualmente la brecha y los motivos de la decisión.",
      ]],
      ["Erradicar y recuperar", [
        "Corrige la causa: permisos mal configurados, error humano, vulnerabilidad o acceso ilícito.",
        "Restablece los accesos de forma segura y comprueba que no quedan datos expuestos.",
      ]],
      ["Después", [
        "Registra la brecha en el registro interno de incidentes.",
        "Revisa formación, permisos y cifrado para evitar que se repita.",
      ]],
    ],
  },
  {
    id: "perdido",
    title: "Dispositivo perdido o robado",
    level: "Alta",
    desc: "Portátil, móvil, tablet o USB extraviado con acceso a datos o cuentas.",
    phases: [
      ["Detectar y evaluar", [
        "Anota qué dispositivo era, cuándo y dónde se perdió, y si estaba bloqueado y cifrado.",
        "Haz una lista de las cuentas y datos a los que daba acceso.",
      ]],
      ["Contener", [
        "Intenta localizarlo y bloquearlo (Encontrar mi dispositivo en Android o Windows, Buscar en Apple).",
        "Cambia las contraseñas de las cuentas y cierra las sesiones abiertas en ese dispositivo.",
        "Si contiene datos sensibles y no está cifrado, borra su contenido de forma remota.",
        "En un móvil, pide a la operadora que bloquee la SIM y el IMEI.",
        "Avisa a TI para revocar certificados, VPN y accesos.",
      ]],
      ["Notificar", [
        "Si fue un robo, presenta denuncia.",
        "Si había datos personales sin cifrar, trátalo como posible brecha y sigue ese protocolo.",
      ]],
      ["Recuperar y después", [
        "Configura un dispositivo nuevo y restaura desde copia de seguridad.",
        "Activa el cifrado de disco y el bloqueo automático en todos tus equipos.",
      ]],
    ],
  },
  {
    id: "intrusion",
    title: "Acceso no autorizado o intrusión",
    level: "Crítica",
    desc: "Alguien accede a un servidor, red o sistema sin permiso.",
    phases: [
      ["Detectar y evaluar", [
        "Revisa los registros en busca de accesos inusuales. En Linux: `last` y `sudo journalctl -p warning -n 100`. En Windows: `Get-WinEvent -LogName Security -MaxEvents 50`.",
        "Busca cuentas nuevas, procesos desconocidos y conexiones sospechosas (`ss -tup` en Linux, `netstat -ano` en Windows).",
        "Delimita qué sistemas y datos han podido verse afectados.",
      ]],
      ["Contener", [
        "Aísla el sistema comprometido de la red, sin apagarlo si es posible.",
        "Deshabilita las cuentas implicadas y bloquea en el cortafuegos las IP atacantes.",
        "Haz una copia o instantánea (snapshot) del sistema antes de tocarlo. NO borres registros.",
      ]],
      ["Erradicar", [
        "Identifica cómo entraron (vulnerabilidad, credenciales débiles, servicio expuesto) y ciérralo.",
        "Elimina cuentas, claves SSH, tareas y servicios que haya creado el atacante.",
        "Cambia todas las contraseñas, claves API y certificados del sistema.",
      ]],
      ["Recuperar", [
        "Si hay dudas sobre la integridad, reconstruye el sistema desde una imagen limpia.",
        "Aplica parches, endurece la configuración y refuerza la monitorización.",
      ]],
      ["Después", [
        "Si hay datos personales afectados, sigue el protocolo de brecha (notificación a la AEPD en 72 h).",
        "Valora avisar a INCIBE-CERT y presentar denuncia.",
        "Documenta la cronología y las lecciones aprendidas.",
      ]],
    ],
  },
  {
    id: "ddos",
    title: "Denegación de servicio (DDoS)",
    level: "Media",
    desc: "Web o servicio muy lento o caído por un volumen anormal de tráfico.",
    phases: [
      ["Detectar y evaluar", [
        "Confirma que no es un fallo propio ni un pico legítimo de visitas.",
        "Revisa el origen, el tipo de tráfico y qué servicio está afectado.",
      ]],
      ["Contener", [
        "Contacta con tu proveedor de hosting o de internet para que ayude a filtrar el tráfico.",
        "Activa la protección anti‑DDoS de tu CDN o proveedor, si la tienes.",
        "Aplica límites de peticiones (rate limiting) y bloquea temporalmente las IP o rangos más agresivos.",
      ]],
      ["Recuperar", [
        "Restablece el servicio de forma gradual y vigila el tráfico.",
        "Comunica la incidencia a los usuarios si el servicio estuvo caído un tiempo relevante.",
      ]],
      ["Después", [
        "Revisa si el ataque ocultaba otro incidente (intrusión, extorsión).",
        "Prepara un plan: protección anti‑DDoS, capacidad y contactos de emergencia.",
      ]],
    ],
  },
  {
    id: "fraude",
    title: "Fraude o suplantación de identidad",
    level: "Alta",
    desc: "Petición urgente de pago, cambio de cuenta bancaria o alguien que se hace pasar por un directivo.",
    phases: [
      ["Detectar y evaluar", [
        "Desconfía de las peticiones urgentes, confidenciales o que cambian un IBAN.",
        "Verifica la petición por otro canal, llamando a un número que ya conocías (no al del mensaje).",
        "Revisa el remitente real: dominio parecido, cabeceras y respuesta a otra dirección.",
      ]],
      ["Contener", [
        "Si ya se hizo un pago: contacta con tu banco inmediatamente para intentar frenar o recuperar la transferencia. Cada hora cuenta.",
        "Bloquea el remitente y avisa a quienes pudieron recibir el mismo mensaje.",
        "Conserva los correos y justificantes como evidencia.",
      ]],
      ["Notificar", [
        "Presenta denuncia ante Policía Nacional o Guardia Civil.",
        "Informa a TI y a la dirección, y avisa a INCIBE-CERT si afecta a una organización.",
      ]],
      ["Después", [
        "Establece un procedimiento de verificación doble para pagos y cambios de datos bancarios.",
        "Forma al personal en este tipo de engaños.",
      ]],
    ],
  },
  {
    id: "antivirus",
    title: "Alerta del antivirus",
    level: "Media",
    desc: "El antivirus ha detectado, bloqueado o puesto en cuarentena algo.",
    phases: [
      ["Detectar y evaluar", [
        "Lee la alerta: nombre de la amenaza, ruta del archivo, acción tomada (bloqueado, en cuarentena, sin resolver).",
        "Piensa qué estabas haciendo: ¿descarga, adjunto, USB, programa nuevo?",
        "Para verificar el archivo sin subirlo, calcula su huella: `Get-FileHash archivo -Algorithm SHA256` en Windows o `sha256sum archivo` en Linux, y búscala en VirusTotal.",
      ]],
      ["Contener", [
        "Si no se resolvió automáticamente, desconecta el equipo de la red y trátalo como malware.",
        "No restaures nada de la cuarentena hasta confirmar que es un falso positivo.",
      ]],
      ["Erradicar", [
        "Actualiza el antivirus y ejecuta un análisis completo.",
        "Comprueba si la amenaza reaparece tras reiniciar: indicaría persistencia.",
        "Revisa si otros equipos recibieron el mismo archivo.",
      ]],
      ["Después", [
        "Si es un falso positivo, repórtalo al fabricante.",
        "Si fue real, sigue el protocolo de malware y anota el origen.",
      ]],
    ],
  },
];

const ESCALATION = [
  ["INCIBE-CERT", "Respuesta a incidentes para ciudadanos y empresas. Línea gratuita de ayuda en ciberseguridad: 017. Web: incibe.es"],
  ["CCN-CERT", "Administraciones públicas y organizaciones de su ámbito. Web: ccn-cert.cni.es"],
  ["AEPD", "Notificación de brechas de datos personales, en un máximo de 72 horas. Web: aepd.es"],
  ["Policía Nacional o Guardia Civil", "Denuncia de fraude, extorsión, ransomware y acceso ilícito. Conserva las evidencias."],
];
