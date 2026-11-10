// Contenido de concienciación en hacking ético (nivel educativo y defensivo).
// Cada sección: [título, [elementos], esParrafo?]
const AWARENESS = [
  {
    id: "que-es", title: "Qué es el hacking ético", level: "Básico",
    desc: "Diferencia entre hackers éticos y atacantes, y cómo es una auditoría.",
    sections: [
      ["Qué es", ["Es buscar fallos de seguridad en sistemas con permiso expreso de su propietario, para corregirlos antes de que los aproveche un atacante real."], true],
      ["Tipos de perfiles", [
        "**Sombrero blanco:** actúa con autorización para mejorar la seguridad.",
        "**Sombrero negro:** ataca sin permiso, por lucro o para causar daño.",
        "**Sombrero gris:** actúa sin autorización pero sin ánimo de dañar. Sigue siendo ilegal.",
        "**Red team** simula a un atacante real, **blue team** defiende y detecta, y **purple team** colabora con ambos.",
      ]],
      ["Fases de una auditoría autorizada", [
        "Acuerdo y alcance por escrito: qué se puede probar, cuándo y cómo.",
        "Recopilación de información sobre lo que está expuesto.",
        "Identificación de posibles vulnerabilidades.",
        "Validación controlada, sin dañar datos ni interrumpir servicios.",
        "Informe con riesgos, evidencias y recomendaciones.",
        "Corrección por parte del cliente y nueva comprobación.",
      ]],
      ["Por qué importa", [
        "Entender cómo piensa un atacante ayuda a decidir qué proteger primero.",
        "Descubrir un fallo en una auditoría sale mucho más barato que sufrir un incidente.",
      ]],
    ],
  },
  {
    id: "legal", title: "Marco legal y ética", level: "Legal",
    desc: "Qué puedes y qué no puedes hacer, y cómo actuar si encuentras un fallo.",
    sections: [
      ["Regla de oro", ["Nunca pruebes la seguridad de un sistema que no es tuyo sin autorización escrita. Hacerlo puede ser delito aunque tu intención sea buena."], true],
      ["En España", [
        "El acceso sin permiso a sistemas ajenos, saltándose sus medidas de seguridad, está tipificado en el Código Penal (art. 197 bis).",
        "También se castigan los daños informáticos y la interrupción de sistemas (arts. 264 y siguientes).",
        "Fabricar o facilitar herramientas pensadas para cometer estos delitos también puede ser delito (art. 197 ter).",
        "Si hay datos personales de por medio, se añade el RGPD.",
      ]],
      ["Para trabajar dentro de la ley", [
        "Contrato o autorización firmada por quien tenga potestad sobre el sistema.",
        "Alcance definido: direcciones, fechas, horarios y técnicas permitidas.",
        "Acuerdo de confidencialidad y un contacto para emergencias.",
        "Los hallazgos se comunican solo al cliente.",
      ]],
      ["Si encuentras un fallo por casualidad", [
        "No sigas explorando ni descargues datos.",
        "No lo publiques ni lo uses.",
        "Avisa al propietario o a INCIBE-CERT (divulgación responsable).",
      ]],
      ["Nota", ["Es información general, no asesoramiento jurídico. Consulta con un profesional ante cualquier duda."], true],
    ],
  },
  {
    id: "social", title: "Ingeniería social y phishing", level: "Básico",
    desc: "Cómo te engañan para que entregues datos, y cómo reconocerlo.",
    sections: [
      ["Qué es", ["Es manipular a las personas, no a los sistemas, para que entreguen información o hagan algo que no deberían. Suele ser el camino más fácil para un atacante."], true],
      ["Formas habituales", [
        "**Phishing:** correo falso que imita a un banco, empresa o compañero.",
        "**Smishing y vishing:** lo mismo por SMS o por llamada.",
        "**Pretexting:** inventan una historia creíble («soy de informática», «soy tu jefe»).",
        "**Baiting:** dejan un cebo, como un USB «perdido».",
        "**Fraude del directivo:** suplantan a un jefe para pedir un pago urgente.",
      ]],
      ["Señales de alerta", [
        "Urgencia o amenaza («tu cuenta se bloqueará hoy»).",
        "Piden contraseñas, códigos o datos que la entidad ya debería tener.",
        "Remitente o enlace con un dominio ligeramente distinto al real.",
        "Adjuntos inesperados o peticiones fuera de lo habitual.",
      ]],
      ["Cómo protegerte", [
        "Para y verifica por otro canal, llamando a un número oficial.",
        "Escribe tú la dirección en el navegador en lugar de pulsar enlaces.",
        "Nadie legítimo te pide tu contraseña ni tus códigos de verificación.",
        "Activa la verificación en dos pasos.",
        "Informa del intento a tu equipo de TI.",
      ]],
    ],
  },
  {
    id: "passwords", title: "Contraseñas y credenciales", level: "Básico",
    desc: "Por qué se roban cuentas y cómo evitarlo.",
    sections: [
      ["Qué es", ["Muchos accesos no se consiguen «rompiendo» nada, sino con credenciales filtradas, repetidas o débiles."], true],
      ["Cómo se pierden", [
        "Reutilizar la misma contraseña: si se filtra en un sitio, se prueba en otros.",
        "Contraseñas cortas o previsibles.",
        "Phishing que las captura.",
        "Programas espía en el equipo.",
      ]],
      ["Cómo protegerte", [
        "Una contraseña larga y única para cada servicio. Mejor una frase de varias palabras.",
        "Usa un gestor de contraseñas.",
        "Activa la verificación en dos pasos, mejor con app o llave física que con SMS.",
        "Comprueba si tu correo aparece en filtraciones en haveibeenpwned.com.",
        "Tras una filtración, cambia la contraseña de las cuentas afectadas.",
      ]],
    ],
  },
  {
    id: "wifi", title: "Redes Wi‑Fi y conexiones", level: "Básico",
    desc: "Riesgos de las redes públicas y cómo proteger la tuya.",
    sections: [
      ["Qué es", ["En redes abiertas o falsas, alguien puede intentar ver o alterar lo que envías. Con HTTPS y buenos hábitos el riesgo baja mucho."], true],
      ["Riesgos", [
        "Redes abiertas sin cifrado.",
        "Puntos de acceso falsos con un nombre parecido al de la red legítima.",
        "Routers con la contraseña por defecto o sin actualizar.",
      ]],
      ["Cómo protegerte", [
        "En redes públicas evita operaciones sensibles, o usa datos móviles o una VPN de confianza.",
        "Comprueba que la web usa HTTPS y no ignores los avisos de certificado.",
        "En casa: WPA2 o WPA3, contraseña fuerte, cambia la de administración del router y mantenlo actualizado.",
        "Desactiva WPS y la administración remota si no los usas.",
        "Pregunta el nombre exacto de la red antes de conectarte.",
      ]],
    ],
  },
  {
    id: "malware", title: "Malware, USB y descargas", level: "Básico",
    desc: "Cómo llega el software malicioso y cómo cerrarle la puerta.",
    sections: [
      ["Qué es", ["Es software diseñado para dañar, espiar o dar acceso a un atacante. Casi siempre necesita que alguien lo ejecute."], true],
      ["Cómo llega", [
        "Adjuntos y enlaces de correos o mensajes.",
        "Programas pirata y descargas de sitios no oficiales.",
        "USB desconocidos.",
        "Extensiones de navegador dudosas.",
      ]],
      ["Cómo protegerte", [
        "Descarga solo de fuentes oficiales.",
        "No conectes USB desconocidos: entrégalos a TI.",
        "Mantén el sistema y el antivirus actualizados.",
        "Revisa los permisos de extensiones y aplicaciones.",
        "Guarda copias de seguridad desconectadas de la red.",
      ]],
    ],
  },
  {
    id: "vulns", title: "Vulnerabilidades y parches", level: "Intermedio",
    desc: "Qué es un CVE, un cero‑día y por qué actualizar importa tanto.",
    sections: [
      ["Qué es", ["Una vulnerabilidad es un fallo en un programa o equipo que puede aprovecharse. Los fabricantes publican parches: el riesgo está en no aplicarlos."], true],
      ["Conceptos clave", [
        "**CVE:** identificador público de un fallo conocido.",
        "**Cero‑día:** fallo sin parche disponible todavía.",
        "**CVSS:** puntuación orientativa de gravedad, de 0 a 10.",
      ]],
      ["Cómo protegerte", [
        "Activa las actualizaciones automáticas.",
        "Retira programas y equipos que ya no tienen soporte.",
        "Prioriza los parches de lo que está expuesto a internet.",
        "Mantén un inventario de lo que tienes.",
        "Sigue los avisos de INCIBE-CERT.",
      ]],
    ],
  },
  {
    id: "web", title: "Seguridad web (para desarrolladores)", level: "Intermedio",
    desc: "Los riesgos más comunes en aplicaciones web y cómo evitarlos.",
    sections: [
      ["Qué es", ["OWASP publica el listado de los riesgos más comunes en aplicaciones web (OWASP Top 10). Consulta la edición vigente en owasp.org."], true],
      ["Riesgos frecuentes y su defensa", [
        "**Control de acceso roto:** comprueba los permisos en el servidor en cada petición.",
        "**Inyección:** valida las entradas y usa consultas parametrizadas.",
        "**Fallos criptográficos:** cifra los datos sensibles y usa HTTPS.",
        "**Autenticación débil:** verificación en dos pasos y límite de intentos.",
        "**Configuración insegura:** elimina cuentas y opciones por defecto.",
        "**Componentes desactualizados:** actualiza librerías y revisa dependencias.",
        "**Registro insuficiente:** guarda logs y alerta de actividad anómala.",
      ]],
      ["Buenas prácticas", [
        "Diseña pensando en la seguridad desde el principio.",
        "Revisa el código y las dependencias.",
        "Haz pruebas de seguridad solo en entornos propios o autorizados.",
      ]],
    ],
  },
  {
    id: "huella", title: "Privacidad y huella digital", level: "Básico",
    desc: "Qué dice de ti lo que es público, y cómo lo usa un atacante.",
    sections: [
      ["Qué es", ["OSINT es obtener información de fuentes públicas. Los atacantes la usan para preparar engaños creíbles: lo que publicas es munición."], true],
      ["Qué puede revelar", [
        "Tu cargo, tu empresa y tus compañeros en redes profesionales.",
        "Viajes, rutinas y ubicación en fotos y publicaciones.",
        "Metadatos de fotos y documentos.",
        "Usuarios y correos que reutilizas en distintos sitios.",
      ]],
      ["Cómo reducirla", [
        "Revisa la privacidad de tus redes sociales.",
        "Desactiva la ubicación en las fotos.",
        "Busca tu nombre y tu correo para ver qué es público.",
        "No publiques tarjetas, billetes ni credenciales.",
        "Usa correos o alias distintos para servicios distintos.",
      ]],
    ],
  },
  {
    id: "aprender", title: "Cómo aprender de forma legal", level: "Intermedio",
    desc: "Laboratorios, plataformas y una ruta de formación segura.",
    sections: [
      ["Qué es", ["Se aprende practicando, pero siempre en entornos creados para ello."], true],
      ["Dónde practicar", [
        "Plataformas de aprendizaje como TryHackMe o Hack The Box.",
        "Aplicaciones vulnerables a propósito que montas tú, como OWASP Juice Shop o DVWA.",
        "Competiciones CTF (Capture The Flag).",
        "Tu propio laboratorio con máquinas virtuales.",
      ]],
      ["Cómo montar tu laboratorio", [
        "Usa máquinas virtuales con una red interna, aislada de tu red real.",
        "Haz instantáneas antes de probar.",
        "No lo conectes a una red de trabajo ni lo expongas a internet.",
        "Practica solo contra lo que has creado.",
      ]],
      ["Ruta de formación", [
        "Redes (TCP/IP, DNS, HTTP).",
        "Linux y línea de comandos.",
        "Fundamentos de seguridad.",
        "Certificaciones de entrada como CompTIA Security+ o eJPT, y más adelante CEH u OSCP.",
        "Comprueba requisitos y precios en las webs oficiales.",
      ]],
    ],
  },
  {
    id: "quiz", title: "Pon a prueba tu concienciación", level: "Básico",
    desc: "Seis preguntas rápidas con explicación.", quiz: true,
  },
];

const QUIZ = [
  {
    q: "Recibes un correo del banco con un enlace urgente para «verificar tu cuenta». ¿Qué haces?",
    options: ["Pulso el enlace y compruebo qué pasa", "Respondo al correo pidiendo más información", "Entro escribiendo yo la dirección oficial, o llamo al banco", "Lo reenvío a mis contactos para avisarles"],
    correct: 2,
    explain: "Un enlace urgente es la señal clásica de phishing. Verifica siempre por un canal que controles tú, nunca desde el mensaje.",
  },
  {
    q: "¿Cuál es la mejor defensa contra el robo de cuentas por contraseñas filtradas?",
    options: ["Cambiar la contraseña una vez al año", "Una contraseña única por servicio, un gestor y verificación en dos pasos", "Usar una contraseña muy larga pero repetirla", "Añadir un número al final de la misma contraseña"],
    correct: 1,
    explain: "Si cada servicio tiene una contraseña distinta, una filtración no abre el resto. La verificación en dos pasos añade una segunda barrera.",
  },
  {
    q: "Encuentras un USB en el aparcamiento de tu empresa. ¿Qué haces?",
    options: ["Lo conecto a un equipo viejo para ver qué contiene", "Lo entrego a TI sin conectarlo", "Lo conecto con el antivirus activado", "Lo uso, total es solo un USB"],
    correct: 1,
    explain: "Los USB abandonados son un cebo habitual (baiting). Conectarlo puede ejecutar software malicioso aunque tengas antivirus.",
  },
  {
    q: "Estás en la Wi‑Fi abierta de una cafetería. ¿Qué es lo más prudente?",
    options: ["Entrar en la banca online, la red tiene un nombre fiable", "Evitar operaciones sensibles, o usar datos móviles o una VPN de confianza", "Desactivar el antivirus para ir más rápido", "Ignorar los avisos de certificado del navegador"],
    correct: 1,
    explain: "En una red abierta no controlas quién ve el tráfico. Para lo sensible, usa tus datos móviles o una VPN de confianza, y nunca ignores avisos de certificado.",
  },
  {
    q: "¿Qué diferencia a un hacker ético de un atacante?",
    options: ["Las herramientas que utiliza", "La autorización por escrito y un alcance acordado", "Que no cobra por su trabajo", "Que solo prueba sistemas de su propia empresa sin avisar"],
    correct: 1,
    explain: "Las técnicas pueden ser parecidas. Lo que lo hace legal y ético es el permiso explícito del propietario, un alcance definido y comunicar los hallazgos solo a él.",
  },
  {
    q: "Alguien te llama diciendo ser de informática y te pide tu contraseña «para una actualización urgente». ¿Qué haces?",
    options: ["Se la doy: es de informática", "Le doy solo la mitad", "Cuelgo y verifico por el canal oficial de la empresa", "Le pido que la envíe por correo para anotarla"],
    correct: 2,
    explain: "El personal de TI legítimo no necesita tu contraseña. Es un caso típico de pretexting: cuelga y contacta tú por un canal oficial.",
  },
];

const SYSTEM_PROMPT = `Eres un asistente de ciberseguridad para usuarios y pequeños equipos de TI en España. Funcionas en local y no tienes acceso a los sistemas del usuario: solo orientas.

Tus áreas:
1) Respuesta a incidentes (malware, ransomware, phishing, cuentas comprometidas, brechas de datos, dispositivos perdidos, intrusiones, DDoS, fraude, alertas del antivirus).
2) Concienciación en hacking ético: explicas cómo funcionan los ataques a nivel conceptual para que el usuario los reconozca y se defienda.

Reglas generales:
- Responde siempre en español, con frases cortas y pasos numerados ordenados por prioridad.
- En un incidente, empieza por lo urgente ("Qué hacer ahora"). Después, si procede: contención, evidencias, erradicación, recuperación y prevención.
- Si falta información clave, haz como máximo 2 o 3 preguntas, pero da antes los pasos urgentes que valgan en cualquier caso.
- Antes de acciones destructivas (borrar, formatear, apagar, restaurar) advierte de que se pueden perder evidencias.
- Da comandos solo si estás seguro de que son correctos, y di qué hacen y en qué sistema (Windows PowerShell o Linux). No inventes herramientas ni comandos.
- Si hay datos personales afectados, recuerda la notificación a la AEPD en 72 horas.
- Si es ransomware, intrusión, fraude económico o afecta a sistemas críticos, recomienda escalar a INCIBE-CERT (línea 017), CCN-CERT si aplica, y denunciar.

Reglas de hacking ético:
- Explica conceptos, señales de alerta y defensas. Subraya siempre que solo se prueba con autorización escrita.
- No des instrucciones paso a paso para entrar en sistemas, no escribas exploits, malware ni herramientas ofensivas, y no ayudes a atacar sistemas de terceros ni a evadir controles de seguridad.
- Si te piden algo ofensivo, explica que no puedes ayudar con eso y ofrece alternativas legales: entender la defensa, montar un laboratorio propio aislado o practicar en plataformas de formación.

Si la pregunta no es de seguridad, respóndela igualmente de forma útil. Si no sabes algo, dilo. No sustituyes a un equipo de respuesta profesional en incidentes graves.`;
