import { useState, useRef } from 'react'
import './App.css'

// ─── Helpers ────────────────────────────────────────────────────────────────

function norm(str) {
  return (str || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
}

function containsAny(text, keywords) {
  const n = norm(text)
  return keywords.filter(kw => n.includes(norm(kw)))
}

// ─── Detectors ──────────────────────────────────────────────────────────────

function detectarRemitenteSospechoso(remitente) {
  if (!remitente.trim()) return null

  const freeDomains = [
    'gmail.com', 'hotmail.com', 'yahoo.com', 'yahoo.es', 'outlook.com',
    'live.com', 'icloud.com', 'aol.com', 'protonmail.com', 'zoho.com',
    'mail.com', 'yandex.com', 'msn.com', 'me.com',
  ]
  const suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.info', '.biz', '.pw', '.cc']
  const brands = ['microsoft', 'google', 'apple', 'paypal', 'amazon', 'netflix', 'banco', 'bbva', 'santander', 'facebook', 'instagram']

  const emailMatch = remitente.match(/<([^>]+)>/) || remitente.match(/([^\s]+@[^\s]+)/)
  const email = emailMatch ? emailMatch[1].toLowerCase() : remitente.toLowerCase()
  const domainMatch = email.match(/@(.+)$/)
  if (!domainMatch) return null
  const domain = domainMatch[1]

  if (freeDomains.includes(domain)) {
    return {
      id: 'remitente_sospechoso',
      nombre: 'Remitente sospechoso',
      icono: 'alternate_email',
      descripcion: `El correo proviene de un dominio de correo gratuito (${domain}), inusual para comunicaciones corporativas oficiales.`,
      peso: 20,
      severidad: 'alta',
    }
  }

  const hasSuspiciousTld = suspiciousTlds.some(tld => domain.endsWith(tld))
  if (hasSuspiciousTld) {
    return {
      id: 'remitente_sospechoso',
      nombre: 'Remitente sospechoso',
      icono: 'alternate_email',
      descripcion: `El dominio del remitente (${domain}) usa una extensión poco confiable frecuentemente asociada a phishing.`,
      peso: 20,
      severidad: 'alta',
    }
  }

  for (const brand of brands) {
    if (domain.includes(brand) && domain !== `${brand}.com` && domain !== `${brand}.es` && domain !== `${brand}.net`) {
      return {
        id: 'remitente_sospechoso',
        nombre: 'Remitente sospechoso',
        icono: 'alternate_email',
        descripcion: `El dominio "${domain}" intenta imitar la marca "${brand}" pero no es el dominio oficial. Posible suplantación.`,
        peso: 20,
        severidad: 'alta',
      }
    }
  }

  const displayNameMatch = remitente.match(/^(.+?)\s*</)
  if (displayNameMatch) {
    const displayName = norm(displayNameMatch[1])
    for (const brand of brands) {
      if (displayName.includes(brand) && !domain.includes(brand)) {
        return {
          id: 'remitente_sospechoso',
          nombre: 'Remitente sospechoso',
          icono: 'alternate_email',
          descripcion: `El nombre del remitente menciona "${brand}" pero el dominio del correo (${domain}) no corresponde. Señal clásica de suplantación.`,
          peso: 20,
          severidad: 'alta',
        }
      }
    }

    // Nombre de pantalla contiene números (ej. "Planillas 472") — inusual para entidad oficial
    const rawDisplay = displayNameMatch[1].trim()
    if (/\d/.test(rawDisplay)) {
      return {
        id: 'remitente_sospechoso',
        nombre: 'Remitente sospechoso',
        icono: 'alternate_email',
        descripcion: `El nombre del remitente ("${rawDisplay}") contiene números, lo cual es inusual para una entidad oficial o corporativa. Puede ser un sistema de envío masivo disfrazado.`,
        peso: 20,
        severidad: 'alta',
      }
    }

    // Nombre reclama ser entidad gubernamental/judicial pero dominio es comercial
    const govTerms = ['juzgado','tribunal','fiscalia','ministerio','alcaldia','gobernacion',
                      'dian','ugpp','notaria','rama judicial','corte','judicatura','colpensiones',
                      'supersociedades','superintendencia','procuraduria','contraloria']
    const govClaim = govTerms.find(t => displayName.includes(t))
    const isGovDomain = domain.endsWith('.gov.co') || domain.endsWith('.gov') || domain.includes('judicial')
    if (govClaim && !isGovDomain) {
      return {
        id: 'remitente_sospechoso',
        nombre: 'Remitente sospechoso',
        icono: 'alternate_email',
        descripcion: `El nombre dice ser "${govClaim.toUpperCase()}" pero el correo llega desde "${domain}", un dominio comercial. Las entidades estatales colombianas usan dominios .gov.co.`,
        peso: 20,
        severidad: 'alta',
      }
    }
  }

  return null
}

function detectarUrgencia(asunto, cuerpo) {
  const keywords = [
    // ── Español ──
    'urgente', 'urgentemente', 'inmediatamente', 'ahora mismo', 'de inmediato',
    'expira', 'expirara', 'caduca', 'caducara', 'ultima oportunidad',
    'actue ya', 'actue ahora', 'importante', 'accion requerida',
    'responda hoy', 'vence hoy', 'vence en', 'plazo', 'limite de tiempo',
    'tiempo limitado', '24 horas', '48 horas', 'horas para', 'ultimo aviso',
    'su cuenta sera', 'su acceso sera bloqueado', 'suspendida', 'eliminada',
    'bloqueada', 'verificacion inmediata', 'responder de inmediato',
    'amenaza judicial', 'proceso penal', 'proceso civil', 'demanda', 'citacion',
    'comparecer', 'juicio', 'embargo', 'mandamiento de pago', 'primera instancia',
    'segunda instancia', 'emplazamiento', 'requerimiento judicial',
    'orden judicial', 'proceso de demanda', 'notificacion judicial',
    'sera detenido', 'arresto', 'multa', 'sancion', 'penalidad',
    'proceso disciplinario', 'investigacion penal', 'accion legal',
    // ── English ──
    'urgent', 'urgently', 'immediately', 'right now', 'asap', 'as soon as possible',
    'expires', 'expiring', 'expiration', 'last chance', 'act now', 'act immediately',
    'action required', 'immediate action required', 'respond today', 'due today',
    'time sensitive', 'time-sensitive', 'limited time', 'final notice', 'final warning',
    'your account will be', 'account suspended', 'account blocked', 'account terminated',
    'account will be closed', 'account has been compromised', 'verify immediately',
    'confirm immediately', 'legal action', 'criminal charges', 'lawsuit', 'court order',
    'subpoena', 'arrest warrant', 'penalty', 'fine imposed', 'legal proceedings',
    'debt collection', 'failure to respond', 'will result in', 'within 24 hours',
    'within 48 hours', 'you must', 'you are required', 'mandatory',
  ]
  const found = containsAny(`${asunto} ${cuerpo}`, keywords)
  if (found.length === 0) return null

  return {
    id: 'urgencia',
    nombre: 'Sentido de urgencia artificial',
    icono: 'alarm',
    descripcion: `El correo usa lenguaje de presión para forzar una acción rápida: "${found.slice(0, 3).join('", "')}"${found.length > 3 ? ' y más' : ''}.`,
    peso: 15,
    severidad: 'media',
  }
}

function detectarCredenciales(cuerpo) {
  const keywords = [
    // ── Español ──
    'contrasena', 'clave de acceso', 'nombre de usuario', 'numero de cuenta',
    'verificar', 'verifique', 'verificacion', 'confirmar datos',
    'confirme sus datos', 'actualizar datos', 'datos bancarios',
    'tarjeta de credito', 'tarjeta de debito', 'numero de tarjeta',
    'cvv', 'cvc', 'pin', 'codigo pin', 'datos de acceso',
    'inicie sesion', 'iniciar sesion', 'haga clic aqui para confirmar',
    'ingrese sus datos', 'proporcione sus datos', 'informacion personal',
    'autenticacion', 'credenciales',
    // ── English ──
    'password', 'passwd', 'username', 'user name', 'account number',
    'social security number', 'date of birth', 'credit card number',
    'bank account', 'routing number', 'billing information', 'billing info',
    'sign in', 'log in', 'login', 'click here to verify', 'verify your account',
    'confirm your account', 'update your information', 'personal information',
    'identity verification', 'two-factor authentication', '2fa code',
    'verification code', 'one-time password', 'enter your password',
    'reset your password', 'account credentials', 'security code',
  ]
  const found = containsAny(cuerpo, keywords)

  // Patrón "CLAVE ACCESO: XXXX" — cebo para abrir archivo/enlace malicioso
  // (proporcionar una "clave" convence al usuario de que el contenido es legítimo)
  const claveAccesoMatch = /clave\s*(?:de\s*)?acceso\s*[:=]\s*\S+/i.test(cuerpo)
                        || /contrase[ñn]a\s*[:=]\s*\S+/i.test(cuerpo)
                        || /password\s*[:=]\s*\S+/i.test(cuerpo)
                        || /access\s*(?:key|code|password)\s*[:=]\s*\S+/i.test(cuerpo)

  if (claveAccesoMatch) {
    return {
      id: 'credenciales',
      nombre: 'Cebo de acceso con clave incluida',
      icono: 'lock_open',
      descripcion: 'ALERTA: El correo proporciona una "CLAVE ACCESO" para abrir un archivo o enlace. Esta táctica —característica del fraude judicial— busca generar confianza falsa y lograr que la víctima descargue malware.',
      peso: 45,
      severidad: 'alta',
    }
  }

  if (found.length < 2) return null

  return {
    id: 'credenciales',
    nombre: 'Solicitud de datos sensibles',
    icono: 'lock_open',
    descripcion: `El correo solicita información confidencial: "${found.slice(0, 3).join('", "')}"${found.length > 3 ? ` y ${found.length - 3} más` : ''}. Las empresas legítimas nunca piden esto por correo.`,
    peso: 25,
    severidad: 'alta',
  }
}

function detectarEnlacesSospechosos(cuerpo) {
  const urlRegex = /https?:\/\/[^\s<>"'\]\[)]+|www\.[^\s<>"'\]\[)]+/gi
  const urls = cuerpo.match(urlRegex) || []
  if (urls.length === 0) return null

  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd', 'tiny.cc']
  const suspTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.info', '.biz', '.pw']
  const brands = ['microsoft', 'google', 'apple', 'paypal', 'amazon', 'netflix', 'banco', 'bbva', 'santander']

  const issues = []

  for (const url of urls) {
    const lower = url.toLowerCase()

    if (shorteners.some(s => lower.includes(s))) {
      issues.push(`URL acortada: ${url}`)
      continue
    }
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower)) {
      issues.push(`URL con dirección IP: ${url}`)
      continue
    }
    if (lower.startsWith('http://')) {
      issues.push(`Conexión no segura (http://): ${url}`)
      continue
    }
    const domainPart = lower.replace(/https?:\/\//, '').split('/')[0]
    if (suspTlds.some(tld => domainPart.endsWith(tld))) {
      issues.push(`Dominio sospechoso: ${domainPart}`)
      continue
    }
    for (const brand of brands) {
      if (domainPart.includes(brand) && !domainPart.endsWith(`${brand}.com`) && !domainPart.endsWith(`${brand}.es`)) {
        issues.push(`Dominio que imita a ${brand}: ${domainPart}`)
        break
      }
    }
    if (url.includes('@')) {
      issues.push(`URL con "@" (truco de engaño): ${url}`)
    }
  }

  if (issues.length === 0) return null

  return {
    id: 'enlaces_sospechosos',
    nombre: 'Enlaces sospechosos',
    icono: 'link_off',
    descripcion: `Se encontraron ${issues.length} enlace(s) sospechoso(s): ${issues[0]}${issues.length > 1 ? ` (y ${issues.length - 1} más)` : ''}.`,
    peso: 20,
    severidad: 'alta',
  }
}

function detectarAdjuntoInesperado(cuerpo, tieneAdjunto) {
  // ── Patrón crítico: descarga de "proceso" judicial falso ──────────────────
  // Los organismos judiciales colombianos reales NUNCA envían citaciones
  // con enlaces de descarga por correo electrónico.
  const descargaProcesoRegex = /descargar?\s+(?:el\s+)?proceso|descargue\s+(?:el\s+)?proceso|descargar?\s+(?:la\s+)?citaci[oó]n|abrir?\s+(?:el\s+)?proceso|ver\s+(?:el\s+)?proceso|download\s+(?:the\s+)?(?:process|legal\s+document|case\s+file|court\s+document|lawsuit\s+file)/i
  if (descargaProcesoRegex.test(cuerpo)) {
    return {
      id: 'adjunto_inesperado',
      nombre: 'Descarga de proceso judicial falso',
      icono: 'file_present',
      descripcion: 'ALERTA: El correo invita a "DESCARGAR PROCESO". Los juzgados colombianos reales notifican en persona o por correo certificado, nunca mediante enlaces de descarga. Esto es una trampa para instalar malware.',
      peso: 45,
      severidad: 'alta',
    }
  }

  const keywords = [
    // ── Español ──
    'adjunto', 'archivo adjunto', 'ver adjunto', 'abrir adjunto',
    'descarga', 'descargar', 'abra el archivo', 'revisar documento',
    'documento adjunto', 'factura adjunta', 'comprobante adjunto',
    'descargar documento', 'descargar soporte', 'abrir citacion',
    'descargar notificacion', 'ver notificacion', 'descargue el documento',
    // ── English ──
    'attachment', 'see attached', 'open attachment', 'attached file',
    'download', 'click to download', 'open the file', 'review the document',
    'attached document', 'attached invoice', 'attached receipt', 'attached report',
    'download file', 'download document', 'open the document', 'view attachment',
    'please find attached', 'find the attached', 'enclosed document',
    // ── Extensiones maliciosas ──
    '.exe', '.zip', '.docm', '.xlsm', '.vbs', '.bat',
    '.cmd', '.rar', '.7z', '.iso', '.apk', '.scr', '.pif', '.hta',
  ]
  const found = containsAny(cuerpo, keywords)

  if (!tieneAdjunto && found.length === 0) return null

  const desc = tieneAdjunto && found.length > 0
    ? `El correo tiene archivos adjuntos y menciona: "${found[0]}". Los adjuntos inesperados pueden contener malware.`
    : tieneAdjunto
    ? 'El correo incluye archivos adjuntos no solicitados. Nunca abra adjuntos de remitentes desconocidos.'
    : `El cuerpo menciona archivos o descargas: "${found[0]}". Verifique si esperaba este contenido.`

  return {
    id: 'adjunto_inesperado',
    nombre: 'Adjunto inesperado',
    icono: 'file_present',
    descripcion: desc,
    peso: 15,
    severidad: 'media',
  }
}

function detectarSaludoGenerico(cuerpo) {
  const patterns = [
    // ── Español ──
    'estimado cliente', 'apreciado cliente', 'estimado usuario', 'apreciado usuario',
    'a quien corresponda', 'a quien pueda interesar', 'estimado/a', 'estimado(a)',
    'hola usuario', 'buen dia usuario', 'a nuestros clientes',
    'estimado miembro', 'apreciado miembro',
    'a su prospecto', 'al ciudadano', 'al contribuyente', 'al interesado',
    'al demandado', 'al imputado', 'al notificado', 'al destinatario',
    'estimado ciudadano', 'apreciado ciudadano', 'estimado contribuyente',
    'se comunica al', 'se le informa al', 'se notifica al',
    // ── English ──
    'dear customer', 'dear user', 'dear valued customer', 'dear valued member',
    'dear account holder', 'dear member', 'dear subscriber', 'dear client',
    'dear sir', 'dear madam', 'dear sir or madam', 'dear sir/madam',
    'hello user', 'hello there', 'greetings', 'to whom it may concern',
    'to our customers', 'to our valued customers', 'to all employees',
    'dear friend', 'dear beneficiary', 'dear winner', 'dear applicant',
  ]
  const start = norm(cuerpo.slice(0, 250))
  const match = patterns.find(p => start.includes(norm(p)))
  if (!match) return null

  return {
    id: 'saludo_generico',
    nombre: 'Saludo genérico',
    icono: 'person_off',
    descripcion: `El correo usa un saludo impersonal ("${match}") en lugar de su nombre real. Las empresas legítimas suelen usar su nombre completo.`,
    peso: 10,
    severidad: 'baja',
  }
}

function detectarErroresRedaccion(cuerpo) {
  const errors = []

  const accentErrors = [
    { wrong: /\binformacion\b/g, label: 'información' },
    { wrong: /\bverificacion\b/g, label: 'verificación' },
    { wrong: /\batencion\b/g, label: 'atención' },
    { wrong: /\bactualizacion\b/g, label: 'actualización' },
    { wrong: /\bconfirmacion\b/g, label: 'confirmación' },
    { wrong: /\bnotificacion\b/g, label: 'notificación' },
    { wrong: /\bproteccion\b/g, label: 'protección' },
    { wrong: /\badministracion\b/g, label: 'administración' },
    { wrong: /\btransaccion\b/g, label: 'transacción' },
    { wrong: /\bautorizacion\b/g, label: 'autorización' },
    { wrong: /\bsuspension\b/g, label: 'suspensión' },
    { wrong: /\bsolucion\b/g, label: 'solución' },
    { wrong: /\btambien\b/g, label: 'también' },
    { wrong: /\bopcion\b/g, label: 'opción' },
  ]

  const bodyNorm = norm(cuerpo)
  for (const { wrong, label } of accentErrors) {
    if (wrong.test(bodyNorm)) {
      errors.push(`"${label}"`)
      wrong.lastIndex = 0
    }
  }

  if (/haga\s+click/i.test(cuerpo)) errors.push('"haga click" (debería ser "clic")')
  if (/[a-z][0-9][a-z]/i.test(cuerpo)) errors.push('sustitución de letras por números')
  if (/\s{3,}/.test(cuerpo)) errors.push('espacios irregulares')
  // ── Patrones de redacción típicos en phishing en inglés ──
  if (/\bkindly\s+(?:revert|respond|confirm|verify|update|provide|send|click)\b/i.test(cuerpo))
    errors.push('"kindly + acción" (indicador frecuente de phishing en inglés)')
  if (/\bdo\s+the\s+needful\b/i.test(cuerpo))
    errors.push('"do the needful" (expresión característica de phishing masivo)')
  if (/\bplease\s+be\s+(?:advised|informed|noted)\b/i.test(cuerpo))
    errors.push('"please be advised/informed" (formalidad artificial)')
  if (/\byour\s+(?:account|password|details?)\s+(?:has|have)\s+been\s+(?:compromised|hacked|accessed|stolen)\b/i.test(cuerpo))
    errors.push('afirmación de compromiso de cuenta sin evidencia')
  if (/\bwe\s+(?:noticed|detected|observed)\s+(?:unusual|suspicious|unauthorized)\b/i.test(cuerpo))
    errors.push('"we noticed unusual activity" (gancho clásico de phishing en inglés)')

  // Palabras judiciales con tilde faltante frecuentes en phishing
  const judicialAccents = [
    { wrong: /\bcitacion\b/g, label: 'citación' },
    { wrong: /\bnotificacion\b/g, label: 'notificación' },
    { wrong: /\bjudicatura\b/g, label: 'judicatura (uso incorrecto)' },
    { wrong: /\bsabado\b/g, label: 'sábado' },
    { wrong: /\bmiercoles\b/g, label: 'miércoles' },
    { wrong: /\bjueves\b/g, label: 'jueves (verificar contexto)' },
    { wrong: /\bcodigo\b/g, label: 'código' },
    { wrong: /\barticulo\b/g, label: 'artículo' },
  ]
  for (const { wrong, label } of judicialAccents) {
    if (wrong.test(bodyNorm)) { errors.push(`"${label}"`); wrong.lastIndex = 0 }
  }

  // Números de proceso/juicio artificialmente largos o con formato sospechoso
  // Ej: "2024071064255663" o "20240710-5427-572301-87"
  if (/\b\d{14,}\b/.test(cuerpo)) errors.push('número de proceso de longitud inusual')
  if (/\b\d{8,}-\d{4,}-\d{6,}-\d{2,}\b/.test(cuerpo)) errors.push('número de expediente con formato no oficial')

  // "a su prospecto" — calco del inglés "prospect", no es español legal correcto
  if (/a su prospecto/i.test(cuerpo)) errors.push('"a su prospecto" (expresión ajena al español jurídico)')

  if (errors.length < 2) return null

  return {
    id: 'errores_redaccion',
    nombre: 'Errores de redacción',
    icono: 'spellcheck',
    descripcion: `Se detectaron ${errors.length} errores típicos de correos traducidos o generados automáticamente: ${errors.slice(0, 2).join(', ')}.`,
    peso: 10,
    severidad: 'baja',
  }
}

function detectarSuplantacion(remitente, asunto, cuerpo) {
  const brandKeywords = [
    'microsoft', 'windows', 'office 365', 'azure', 'google', 'gmail',
    'apple', 'icloud', 'paypal', 'amazon', 'netflix', 'spotify', 'dropbox',
    'banco', 'bbva', 'santander', 'banamex', 'bancomer', 'hsbc', 'citibank',
    'scotiabank', 'banorte', 'inbursa', 'facebook', 'instagram', 'whatsapp',
    // Entidades judiciales y gubernamentales (Colombia y región)
    'juzgado', 'tribunal', 'fiscalia', 'fiscalía', 'rama judicial',
    'judicatura', 'corte suprema', 'consejo de estado', 'juez',
    'ministerio', 'dian', 'ugpp', 'colpensiones', 'alcaldia', 'gobernacion',
    'supersociedades', 'superintendencia', 'procuraduria', 'contraloria',
    'notaria', 'camara de comercio', 'policia nacional', 'ejercito nacional',
    'registraduria', 'icbf', 'invima', 'dane',
    // Vocabulario legal que implica suplantación de autoridad
    'proceso penal', 'proceso civil', 'primera instancia', 'segunda instancia',
    'mandamiento de pago', 'orden de embargo', 'citacion judicial',
    'constitucion', 'codigo penal', 'codigo civil', 'ley 100',
  ]
  const execRoles = [
    // ── Español ──
    'ceo', 'director general', 'director ejecutivo', 'gerente general',
    'vicepresidente', 'presidente', 'jefe de', 'responsable de',
    'director de finanzas', 'director de rrhh', 'recursos humanos',
    'departamento de it', 'soporte tecnico', 'equipo de seguridad',
    'administrador del sistema', 'helpdesk', 'mesa de ayuda',
    // ── English ──
    'chief executive officer', 'chief financial officer', 'cfo', 'cto',
    'chief technology officer', 'chief operating officer', 'coo',
    'it support', 'technical support', 'security team', 'security department',
    'help desk', 'system administrator', 'sysadmin', 'it department',
    'hr department', 'human resources department', 'finance department',
    'accounting department', 'payroll department', 'compliance team',
  ]
  const execActions = [
    // ── Español ──
    'transferencia urgente', 'transferir fondos', 'pago urgente',
    'necesito que realices', 'te pido que', 'estoy en reunion',
    'no puedo hablar ahora', 'realiza el pago', 'haz una transferencia',
    'deposita', 'envia dinero', 'compra tarjetas', 'gift card',
    // ── English ──
    'wire transfer', 'transfer funds', 'urgent payment', 'i need you to',
    'need you to', 'please transfer', 'purchase gift cards', 'buy gift cards',
    'make a payment', 'send money', 'deposit funds', 'in a meeting',
    'cant talk right now', 'process this payment', 'handle this for me',
    'keep this confidential', 'do not share this', 'time sensitive matter',
    'process the transfer', 'execute the payment',
  ]

  const allText = norm(`${remitente} ${asunto} ${cuerpo}`)

  const foundBrand = brandKeywords.find(b => allText.includes(norm(b)))
  const foundRole = execRoles.find(r => allText.includes(norm(r)))
  const foundAction = execActions.find(a => allText.includes(norm(a)))

  if (!foundBrand && !(foundRole && foundAction)) return null

  const desc = foundBrand
    ? `El correo menciona la marca "${foundBrand}" pero puede no provenir de ellos. Verifique siempre el remitente oficial.`
    : `El correo simula ser de un ejecutivo ("${foundRole}") pidiendo una acción urgente ("${foundAction}"). Fraude del CEO clásico.`

  return {
    id: 'suplantacion_marca',
    nombre: 'Suplantación de marca o ejecutivo',
    icono: 'gpp_bad',
    descripcion: desc,
    peso: 25,
    severidad: 'alta',
  }
}

// ─── Detector 9: Correlación Remitente ↔ Contenido ──────────────────────────

const BRAND_MAP = {
  microsoft:  ['microsoft', 'office 365', 'office365', 'windows', 'azure', 'outlook', 'teams', 'onedrive'],
  google:     ['google', 'gmail', 'workspace', 'drive', 'youtube', 'google docs'],
  apple:      ['apple', 'icloud', 'itunes', 'app store', 'macbook', 'iphone'],
  paypal:     ['paypal', 'pay pal'],
  amazon:     ['amazon', 'aws', 'prime', 'kindle'],
  netflix:    ['netflix'],
  spotify:    ['spotify'],
  dropbox:    ['dropbox'],
  facebook:   ['facebook', 'meta', 'instagram', 'whatsapp'],
  banco:      ['banco', 'bancario', 'cuenta bancaria', 'transferencia bancaria', 'banca en linea'],
  bbva:       ['bbva', 'bancomer'],
  santander:  ['santander', 'openbank'],
  haceb:      ['haceb', 'haceb.com'],
  judicial:   ['juzgado', 'tribunal', 'fiscalia', 'judicatura', 'rama judicial',
               'corte suprema', 'juez', 'primera instancia', 'proceso penal',
               'proceso civil', 'citacion judicial', 'mandamiento de pago',
               'court order', 'subpoena', 'lawsuit', 'legal notice', 'case number',
               'court hearing', 'district court', 'federal court', 'legal action'],
  gobierno:   ['ministerio', 'dian', 'ugpp', 'colpensiones', 'alcaldia',
               'gobernacion', 'supersociedades', 'procuraduria', 'contraloria',
               'notaria', 'policia nacional', 'registraduria',
               'irs', 'internal revenue', 'social security administration',
               'department of', 'bureau of', 'federal agency', 'government notice'],
  planillas:  ['planillas', 'nomina', 'liquidacion de nomina', 'pago de nomina',
               'colilla de pago', 'desprendible', 'payroll', 'pay stub', 'salary slip'],
}

function detectarCorrelacionRemitenteContenido(remitente, asunto, cuerpo) {
  if (!remitente.trim()) return null

  // ── Parse sender ────────────────────────────────────────────────────────────
  const emailMatch = remitente.match(/<([^>]+)>/) || remitente.match(/([^\s]+@[^\s]+)/)
  const email       = emailMatch ? emailMatch[1].toLowerCase() : remitente.toLowerCase()
  const domainMatch = email.match(/@(.+)$/)
  const domain      = domainMatch ? domainMatch[1] : ''
  // Display name: try "Name <email>" format first, then strip email from plain string
  const displayRaw  = (
    remitente.match(/^(.+?)\s*</)?.[1]?.trim()           // "Nombre <email@...>"
    || remitente.replace(/\S+@\S+/g, '').trim()           // "Nombre Apellido email@..." → "Nombre Apellido"
    || ''
  )
  const emailLocal  = email.split('@')[0]                  // e.g. "rrhh" from rrhh@empresa.com
  const displayNorm = norm(`${displayRaw} ${emailLocal}`)  // combine display + local part
  const senderFull  = norm(`${domain} ${displayRaw} ${emailLocal}`)

  const freeDomains = ['gmail.com','hotmail.com','yahoo.com','yahoo.es','outlook.com',
                       'live.com','icloud.com','aol.com','protonmail.com','mail.com']

  // ── Identify brand claimed by sender ───────────────────────────────────────
  let senderBrand = null
  for (const [brand, kws] of Object.entries(BRAND_MAP)) {
    if (kws.some(kw => senderFull.includes(norm(kw)))) { senderBrand = brand; break }
  }

  // ── Identify dominant brand in body + subject ───────────────────────────────
  const bodyFull = norm(`${asunto} ${cuerpo}`)
  let bodyBrand = null, maxHits = 0
  for (const [brand, kws] of Object.entries(BRAND_MAP)) {
    const hits = kws.filter(kw => bodyFull.includes(norm(kw))).length
    if (hits > maxHits) { maxHits = hits; bodyBrand = brand }
  }

  // ── Extract closing signature line (first 80 chars after valediction) ───────
  const sigMatch  = cuerpo.match(/(?:atentamente|saludos cordiales|saludos|cordialmente|regards|el equipo|equipo de)\s*[,:\n]+\s*(.{3,80})/i)
  const sigText   = sigMatch ? norm(sigMatch[1]) : ''
  let sigBrand    = null
  for (const [brand, kws] of Object.entries(BRAND_MAP)) {
    if (kws.some(kw => sigText.includes(norm(kw)))) { sigBrand = brand; break }
  }

  // ── Extract greeting organization (first 150 chars) ─────────────────────────
  const greetingText = norm(cuerpo.slice(0, 150))
  let greetingBrand = null
  for (const [brand, kws] of Object.entries(BRAND_MAP)) {
    if (kws.some(kw => greetingText.includes(norm(kw)))) { greetingBrand = brand; break }
  }

  // ── Department / role keywords ──────────────────────────────────────────────
  const deptRRHH     = ['rrhh','recursos humanos','hr department','human resources','nomina','talento humano']
  const deptIT       = ['soporte tecnico','soporte ti','it department','helpdesk','mesa de ayuda','sistemas','infraestructura']
  const deptFinanzas = ['finanzas','contabilidad','finance','tesoreria','facturacion','cobranza']
  const deptDirec    = ['director general','ceo','gerente general','direccion general','presidencia']

  const isRRHH     = deptRRHH.some(d => displayNorm.includes(d))
  const isIT       = deptIT.some(d => displayNorm.includes(d))
  const isFinanzas = deptFinanzas.some(d => displayNorm.includes(d))
  const isDirec    = deptDirec.some(d => displayNorm.includes(d))

  // Body topic keywords
  const hasCredRequest   = [
    'contrasena','password','verificar cuenta','datos de acceso','inicie sesion',
    'log in','sign in','reset password','verify account','account credentials','enter your password',
  ].some(t => bodyFull.includes(t))
  const hasFinancialReq  = [
    'transferencia','deposito','pago urgente','fondos','wire transfer','gift card',
    'bank transfer','urgent payment','purchase gift','send funds','transfer money',
  ].some(t => bodyFull.includes(t))
  const hasPersonalData  = [
    'numero de tarjeta','cvv','datos bancarios','cuenta bancaria','numero de cuenta',
    'credit card','card number','bank account','routing number','social security',
  ].some(t => bodyFull.includes(t))
  const hasGenericOpener = [
    'estimado cliente','apreciado usuario','dear customer','dear user',
    'dear account holder','dear valued customer','dear member','to whom it may concern',
  ].some(p => greetingText.includes(p))

  // Detect if display name looks like a real person (2 words, no corporate terms)
  const corpWords = ['soporte','support','equipo','team','noreply','no-reply','admin','info','notificacion',
                     'servicio','service','seguridad','security','atencion','bancomer','bbva']
  const displayOnlyNorm = norm(displayRaw)           // pure display name, no email local part
  const nameParts = displayRaw.split(/\s+/)
  const looksLikePerson = nameParts.length === 2 && !corpWords.some(w => displayOnlyNorm.includes(w))
                          && nameParts.every(p => /^[a-záéíóúñü]/i.test(p))

  // ── Collect all issues ──────────────────────────────────────────────────────
  const issues = []

  // 1. Brand mismatch: sender identity ≠ body topic
  if (senderBrand && bodyBrand && senderBrand !== bodyBrand && maxHits >= 1)
    issues.push({
      desc: `El nombre del remitente indica "${senderBrand}" pero el contenido habla de "${bodyBrand}". Son entidades distintas.`,
      priority: 5,
    })

  // 2. Free domain claiming a known brand
  if (freeDomains.includes(domain) && bodyBrand && maxHits >= 2)
    issues.push({
      desc: `El correo llega desde un dominio personal (${domain}), pero el texto simula ser de "${bodyBrand}". Ninguna empresa envía comunicados oficiales desde cuentas gratuitas.`,
      priority: 5,
    })

  // 3. Closing signature brand ≠ sender brand
  if (sigBrand && senderBrand && sigBrand !== senderBrand)
    issues.push({
      desc: `La firma al final del correo dice ser de "${sigBrand}", pero el remitente se identifica como "${senderBrand}". El mensaje se contradice a sí mismo.`,
      priority: 4,
    })

  // 4. Greeting organization ≠ sender brand
  if (greetingBrand && senderBrand && greetingBrand !== senderBrand)
    issues.push({
      desc: `La apertura del correo menciona a "${greetingBrand}" como destinatario, pero el remitente se presenta como "${senderBrand}". Indicio de correo masivo redirigido.`,
      priority: 4,
    })

  // 5. Departamento incongruente con el contenido del mensaje
  if (isRRHH && (hasCredRequest || hasPersonalData))
    issues.push({
      desc: `El remitente se identifica como RRHH/Recursos Humanos, pero el mensaje solicita credenciales o datos bancarios. RRHH nunca pide esos datos por correo.`,
      priority: 4,
    })
  if (isIT && hasFinancialReq)
    issues.push({
      desc: `El remitente dice ser Soporte Técnico/IT, pero el contenido solicita transferencias o pagos. El área de IT no gestiona transacciones financieras.`,
      priority: 4,
    })
  if (isFinanzas && hasCredRequest && !hasFinancialReq)
    issues.push({
      desc: `El remitente dice ser de Finanzas/Contabilidad, pero el contenido pide credenciales de acceso. El departamento de finanzas no solicita contraseñas por correo.`,
      priority: 3,
    })
  if (isDirec && hasPersonalData)
    issues.push({
      desc: `El remitente se presenta como Dirección General o CEO, pero solicita datos bancarios personales. Los directivos no piden esos datos directamente por correo.`,
      priority: 4,
    })

  // 6. Person name + mass-template body + corporate brand claim
  if (looksLikePerson && hasGenericOpener && senderBrand)
    issues.push({
      desc: `El remitente tiene nombre de persona ("${displayRaw}"), pero el mensaje usa plantillas corporativas masivas ("estimado cliente"…) y suplanta la marca "${senderBrand}". Combinación típica de fraude.`,
      priority: 3,
    })

  // 7. Remitente de planillas/nómina/pagos enviando contenido judicial o gubernamental
  const senderIsPlanillas = ['planillas', 'nomina', 'pagos', 'liquidacion', 'colilla'].some(w => senderFull.includes(w))
  const bodyIsJudicial = ['juzgado', 'tribunal', 'juez', 'proceso penal', 'primera instancia',
                          'citacion', 'demanda', 'mandamiento', 'juicio', 'fiscalia'].some(w => bodyFull.includes(w))
  if (senderIsPlanillas && bodyIsJudicial)
    issues.push({
      desc: `El remitente corresponde a un sistema de nómina/planillas, pero el contenido es una supuesta citación judicial. Los sistemas de nómina no emiten órdenes judiciales.`,
      priority: 5,
    })

  // 8. Cualquier dominio comercial enviando citación/orden judicial
  //    (las entidades judiciales colombianas usan dominios .gov.co o correo certificado)
  const domainIsCommercial = !domain.endsWith('.gov.co') && !domain.endsWith('.gov')
                          && !domain.includes('judicial') && !domain.includes('fiscalia')
  if (domainIsCommercial && bodyIsJudicial)
    issues.push({
      desc: `El correo proviene de "${domain}", un dominio comercial, pero el contenido simula ser una notificación judicial. Las entidades judiciales colombianas usan exclusivamente dominios ".gov.co" o correo certificado.`,
      priority: 5,
    })

  if (issues.length === 0) return null

  // Score scales with number of inconsistencies found:
  // 1 issue → 20 pts | 2 issues → 28 pts | 3+ issues → 35 pts
  const pesoEscalado = issues.length >= 3 ? 35 : issues.length === 2 ? 28 : 20

  // Return highest-priority issue as main description
  issues.sort((a, b) => b.priority - a.priority)
  const best  = issues[0]
  const extra = issues.length > 1
    ? ` (+${issues.length - 1} incongruencia${issues.length > 2 ? 's' : ''} adicional${issues.length > 2 ? 'es' : ''})`
    : ''

  return {
    id: 'correlacion_sospechosa',
    nombre: 'Inconsistencia remitente ↔ contenido',
    icono: 'compare_arrows',
    descripcion: best.desc + extra,
    peso: pesoEscalado,
    severidad: 'alta',
  }
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

function calcularNivel(puntuacion) {
  if (puntuacion <= 25) return { nivel: 'SEGURO',      color: '#22c55e' }
  if (puntuacion <= 50) return { nivel: 'PRECAUCIÓN',  color: '#f59e0b' }
  if (puntuacion <= 75) return { nivel: 'ALTO RIESGO', color: '#f97316' }
  return                       { nivel: 'CRÍTICO',     color: '#ef4444' }
}

function generarRecomendaciones(nivel, senales) {
  const base = {
    SEGURO: [
      'Este correo no presenta señales evidentes de phishing.',
      'Aun así, nunca comparta contraseñas ni datos bancarios por correo.',
      'Si tiene alguna duda, contacte directamente al remitente por teléfono.',
    ],
    'PRECAUCIÓN': [
      'No haga clic en ningún enlace sin verificar antes el destino real.',
      'Contacte al remitente por un canal oficial (teléfono, portal web) para confirmar.',
      'No proporcione datos personales ni contraseñas.',
      'Si persiste la duda, reenvíe el correo a ciberseguridad@haceb.com para análisis.',
    ],
    'ALTO RIESGO': [
      'No interactúe con este correo: no haga clic en enlaces ni descargue adjuntos.',
      'Reporte este correo a ciberseguridad@haceb.com con una captura de este análisis.',
      'No responda ni reenvíe el mensaje a otros compañeros.',
      'Si ya proporcionó algún dato, notifique a TI y cambie sus contraseñas de inmediato.',
    ],
    CRÍTICO: [
      'ALERTA: Este correo presenta múltiples indicadores de phishing. No interactúe con él.',
      'Reporte de inmediato a ciberseguridad@haceb.com y avise a su supervisor.',
      'Si ya hizo clic o ingresó datos, contacte a TI como emergencia urgente ahora mismo.',
      'No reenvíe este mensaje a ningún compañero bajo ningún motivo.',
      'Conserve el correo sin eliminarlo para que el equipo de seguridad pueda investigar.',
    ],
  }

  const especificas = []
  if (senales.find(s => s.id === 'credenciales'))
    especificas.push('Recuerde: ninguna empresa legítima le pedirá contraseñas o PINs por correo.')
  if (senales.find(s => s.id === 'adjunto_inesperado'))
    especificas.push('No abra archivos adjuntos inesperados; pueden contener virus o ransomware.')
  if (senales.find(s => s.id === 'enlaces_sospechosos'))
    especificas.push('Antes de hacer clic en un enlace, pase el cursor por encima para ver la URL real.')

  return [...(base[nivel] || base.SEGURO), ...especificas]
}

// ─── Coherencia remitente ↔ contenido ────────────────────────────────────────
// Regla binaria:
//   • Coincidencia (palabra del remitente aparece en el cuerpo) → riesgo mínimo (0)
//   • Sin coincidencia (dominio sin relación con el contenido)  → CRÍTICO (≥76)
//
// Excepciones:
//   • Dominios gratuitos (gmail, hotmail…): se saltan — ya los detecta remitente_sospechoso
//   • TLDs sospechosos (.xyz, .tk…): nunca reducen a mínimo; pueden escalar a CRÍTICO
//   • Palabras genéricas (info, soporte, admin…) no cuentan como identificadores

const STOPWORDS_REMITENTE = new Set([
  'info', 'mail', 'noreply', 'reply', 'soporte', 'support', 'contact', 'contacto',
  'help', 'ayuda', 'admin', 'correo', 'email', 'notif', 'notificaciones', 'alerta',
  'alert', 'news', 'team', 'equipo', 'general', 'ventas', 'sales', 'marketing',
  'office', 'corp', 'group', 'grupo', 'hola', 'hello', 'cuenta', 'account',
  'cliente', 'clientes', 'customer', 'usuario', 'user', 'seguridad', 'security',
  'servicio', 'service', 'factura', 'invoice', 'banco', 'bank',
])

function evaluarCoherenciaRemitente(remitente, asunto, cuerpo) {
  if (!remitente.trim()) return null

  const emailMatch = remitente.match(/<([^>]+)>/) || remitente.match(/([^\s]+@[^\s]+)/)
  if (!emailMatch) return null
  const email = emailMatch[1].toLowerCase()
  const domainMatch = email.match(/@(.+)$/)
  if (!domainMatch) return null
  const domain = domainMatch[1]

  const freeDomains = [
    'gmail.com', 'hotmail.com', 'yahoo.com', 'yahoo.es', 'outlook.com',
    'live.com', 'icloud.com', 'aol.com', 'protonmail.com', 'zoho.com',
    'mail.com', 'yandex.com', 'msn.com', 'me.com',
  ]
  if (freeDomains.includes(domain)) return null   // dominio libre: sin evaluación

  const suspTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.biz', '.pw', '.cc']
  const esTldSospechoso = suspTlds.some(tld => domain.endsWith(tld))

  // Extraer palabras identificadoras SOLO del dominio y la parte local del email.
  // El nombre de pantalla (display name) es libremente falsificable por cualquier
  // atacante, por lo que NO se usa para determinar coherencia.

  //   1. Núcleo del dominio (sin TLD)
  const domainCore = domain
    .replace(/\.(com|net|org|co|gov|edu|gob|es|mx|ar|cl|pe|br)(\.co)?$/i, '')
    .split(/[.\-_]/)
    .filter(p => p.length >= 4 && !STOPWORDS_REMITENTE.has(p))

  //   2. Parte local del email (antes del @)
  const localPart = email.split('@')[0]
  const localWords = localPart.split(/[.\-_0-9]+/).filter(w => w.length >= 4 && !STOPWORDS_REMITENTE.has(w))

  const senderWords = [...new Set([...domainCore, ...localWords])]
  if (senderWords.length === 0) return null   // sin palabras identificadoras → sin evaluación

  const textNorm = norm(`${asunto} ${cuerpo}`)
  const hayCoincidencia = senderWords.some(w => textNorm.includes(w))

  return { hayCoincidencia, esTldSospechoso, senderWords }
}

function analizarEmail({ remitente, asunto, cuerpo, tieneAdjunto }) {
  const senalesDetectadas = []
  let rawScore = 0

  const detectors = [
    detectarRemitenteSospechoso(remitente),
    detectarUrgencia(asunto, cuerpo),
    detectarCredenciales(cuerpo),
    detectarEnlacesSospechosos(cuerpo),
    detectarAdjuntoInesperado(cuerpo, tieneAdjunto),
    detectarSaludoGenerico(cuerpo),
    detectarErroresRedaccion(cuerpo),
    detectarSuplantacion(remitente, asunto, cuerpo),
    detectarCorrelacionRemitenteContenido(remitente, asunto, cuerpo),
  ]

  for (const signal of detectors) {
    if (signal !== null) {
      senalesDetectadas.push(signal)
      rawScore += signal.peso
    }
  }

  // ── Coherencia remitente ↔ contenido ────────────────────────────────────
  // Reglas:
  //  • Sin coincidencia → escalar a CRÍTICO (siempre aplica)
  //  • Con coincidencia + sin TLD sospechoso + SIN señales → score mínimo (0)
  //  • Con coincidencia + señales detectadas → las señales mandan, no se cancela
  const coherencia = evaluarCoherenciaRemitente(remitente, asunto, cuerpo)
  if (coherencia) {
    if (!coherencia.hayCoincidencia) {
      // Remitente sin relación con el contenido → forzar CRÍTICO
      rawScore = Math.max(rawScore, 76)
    } else if (coherencia.hayCoincidencia && !coherencia.esTldSospechoso && senalesDetectadas.length === 0) {
      // Dominio coherente Y ninguna señal de riesgo detectada → correo limpio
      rawScore = 0
    }
    // Si hay señales: los detectores ya calcularon el riesgo real — no se toca
  }

  // ── Garantía CRÍTICO ──────────────────────────────────────────────────────
  // "DESCARGAR PROCESO" y "CLAVE ACCESO:" son indicadores definitivos de fraude.
  const tieneDescargaProceso = /descargar?\s+(?:el\s+)?proceso|descargue\s+(?:el\s+)?proceso|download\s+(?:the\s+)?(?:process|legal\s+document|case\s+file|court\s+document)/i.test(cuerpo)
  const tieneClaveAcceso     = /clave\s*(?:de\s*)?acceso\s*[:=]|access\s*(?:key|code)\s*[:=]/i.test(cuerpo)
  if (tieneDescargaProceso || tieneClaveAcceso) {
    rawScore = Math.max(rawScore, 76)
  }

  // ── Sin señales → score mínimo ────────────────────────────────────────────
  // Si ningún detector encontró indicadores Y no hay frases críticas absolutas,
  // el correo no tiene evidencia de riesgo.
  if (senalesDetectadas.length === 0 && !tieneDescargaProceso && !tieneClaveAcceso) {
    rawScore = 0
  }

  const puntuacion = Math.min(rawScore, 99)
  const { nivel, color: nivelColor } = calcularNivel(puntuacion)
  const recomendaciones = generarRecomendaciones(nivel, senalesDetectadas)

  return { puntuacion, nivel, nivelColor, senalesDetectadas, recomendaciones }
}

// ─── Example ─────────────────────────────────────────────────────────────────

const EJEMPLO = {
  remitente: 'Soporte Microsoft <soporte@microsoft-verificacion.xyz>',
  asunto: 'URGENTE: Su cuenta de Office 365 expirará en 24 horas - Acción requerida',
  cuerpo: `Estimado cliente,

Le informamos que su cuenta de Office 365 ha sido comprometida y expirara en las proximas 24 horas si no toma accion inmediatamente.

Para evitar la suspension de su cuenta, debe verificar sus datos de acceso ahora mismo haciendo clic en el siguiente enlace:

http://bit.ly/verificar-microsoft-cuenta-2024

Es urgente que confirme su contrasena y nombre de usuario en el formulario de verificacion.

Tambien adjuntamos un archivo con instrucciones adicionales de seguridad. Por favor descargue y abra el adjunto: GuardiaSeguridad.exe

Este es un aviso de seguridad critico. Si no confirma sus datos en las proximas 24 horas, su cuenta sera eliminada permanentemente.

Atentamente,
Equipo de Soporte Microsoft`,
  tieneAdjunto: true,
}

// ─── Mailto Builder ──────────────────────────────────────────────────────────

function generarMailto(resultado, remitente, asunto) {
  const senalesTexto = resultado.senalesDetectadas
    .map(s => `  • ${s.nombre} (+${s.peso} pts)`)
    .join('\n')

  const body = [
    '═══════════════════════════════════════',
    'REPORTE GUARDIAN — Análisis de Phishing',
    '═══════════════════════════════════════',
    '',
    `Fecha del análisis : ${new Date().toLocaleString('es-CO')}`,
    `Puntuación de riesgo: ${resultado.puntuacion} / 100`,
    `Nivel de riesgo    : ${resultado.nivel}`,
    '',
    '─── Datos del correo analizado ────────',
    `Remitente : ${remitente || '(no ingresado)'}`,
    `Asunto    : ${asunto || '(no ingresado)'}`,
    '',
    `─── Señales detectadas (${resultado.senalesDetectadas.length}/9) ─────`,
    senalesTexto || '  (ninguna)',
    '',
    '─── Acción recomendada ────────────────',
    resultado.recomendaciones[0],
    '',
    'Por favor adjunte una captura de pantalla del análisis completo.',
    '═══════════════════════════════════════',
  ].join('\n')

  const params = new URLSearchParams({
    subject: `[Guardian] Correo sospechoso — Riesgo ${resultado.nivel} (${resultado.puntuacion}/100)`,
    body,
  })
  return `mailto:ciberseguridad@haceb.com?${params.toString()}`
}

// ─── Doberman Mascot ─────────────────────────────────────────────────────────

function DobermanMascot({ className = '', searching = false, nivel = null }) {
  const nivelClass = nivel ? ({
    'SEGURO':      'dober-nivel-seguro',
    'PRECAUCIÓN':  'dober-nivel-precaucion',
    'ALTO RIESGO': 'dober-nivel-alto-riesgo',
    'CRÍTICO':     'dober-nivel-critico',
  }[nivel] || '') : ''

  return (
    <svg
      viewBox="0 0 160 200"
      className={`dober-mascot ${className}${searching ? ' dober-searching' : ''}${nivelClass ? ` ${nivelClass}` : ''}`}
      aria-label="Mascota Guardian Doberman"
      xmlns="http://www.w3.org/2000/svg"
      overflow="visible"
    >
      {/* ── Cráneo / cabeza ── */}
      <ellipse cx="80" cy="82" rx="57" ry="52" fill="#1a0b04" />

      {/* ── Oreja izquierda ── */}
      <g className="dober-ear-l">
        <polygon points="23,60 9,4 63,50" fill="#1a0b04" />
        <polygon points="26,57 17,10 58,48" fill="#c47820" opacity="0.72" />
      </g>

      {/* ── Oreja derecha ── */}
      <g className="dober-ear-r">
        <polygon points="137,60 151,4 97,50" fill="#1a0b04" />
        <polygon points="134,57 143,10 102,48" fill="#c47820" opacity="0.72" />
      </g>

      {/* ── Hocico ── */}
      <ellipse cx="80" cy="116" rx="30" ry="27" fill="#2e1508" />
      {/* Manchas tan en los carrillos */}
      <ellipse cx="63" cy="120" rx="13" ry="11" fill="#c47820" opacity="0.84" />
      <ellipse cx="97" cy="120" rx="13" ry="11" fill="#c47820" opacity="0.84" />

      {/* ── Ojos — iris ámbar ── */}
      <ellipse cx="56" cy="80" rx="14" ry="13" fill="#f59e0b" />
      <ellipse cx="104" cy="80" rx="14" ry="13" fill="#f59e0b" />

      {/* ── Pupilas ── */}
      <ellipse className="dober-pupil-l" cx="56" cy="82" rx="8" ry="10" fill="#100500" />
      <ellipse className="dober-pupil-r" cx="104" cy="82" rx="8" ry="10" fill="#100500" />

      {/* ── Brillos de los ojos ── */}
      <ellipse cx="60" cy="76" rx="3.5" ry="2.5" fill="white" opacity="0.45" />
      <ellipse cx="108" cy="76" rx="3.5" ry="2.5" fill="white" opacity="0.45" />

      {/* ── Párpados (parpadeo) ── */}
      <ellipse className="dober-lid-l" cx="56" cy="80" rx="14" ry="13" fill="#1a0b04" />
      <ellipse className="dober-lid-r" cx="104" cy="80" rx="14" ry="13" fill="#1a0b04" />

      {/* ── Manchas de ceja (tan) ── */}
      <ellipse cx="56" cy="67" rx="9" ry="4.5" fill="#c47820" />
      <ellipse cx="104" cy="67" rx="9" ry="4.5" fill="#c47820" />

      {/* ── Nariz ── */}
      <ellipse cx="80" cy="113" rx="13" ry="8.5" fill="#090909" />
      <ellipse cx="74" cy="115" rx="4" ry="3" fill="#1a1a1a" />
      <ellipse cx="86" cy="115" rx="4" ry="3" fill="#1a1a1a" />
      <ellipse cx="76" cy="109" rx="5" ry="2.5" fill="#252525" />

      {/* ── Cuello / garganta ── */}
      <ellipse cx="80" cy="152" rx="40" ry="24" fill="#1a0b04" />
      <ellipse cx="80" cy="157" rx="28" ry="16" fill="#c47820" opacity="0.72" />

      {/* ── Collar teal ── */}
      <path d="M 40,164 Q 80,180 120,164 L 118,155 Q 80,170 42,155 Z" fill="#14b8a6" />
      <path d="M 73,170 Q 80,182 87,170 Q 80,158 73,170 Z" fill="#0d9488" />
      <text x="80" y="176" fill="#e0fffe" fontSize="7" textAnchor="middle" fontWeight="bold">G</text>

      {/* ── Lupa (solo durante búsqueda) ── */}
      {searching && (
        <g className="dober-loupe">
          {/* lente */}
          <circle cx="116" cy="158" r="15" fill="#14b8a6" opacity="0.12" />
          <circle cx="116" cy="158" r="15" fill="none" stroke="#14b8a6" strokeWidth="3.5" />
          {/* mango */}
          <line x1="126" y1="169" x2="138" y2="182" stroke="#14b8a6" strokeWidth="3.5" strokeLinecap="round" />
          {/* línea de escaneo dentro del lente */}
          <line className="dober-scan-line" x1="107" y1="158" x2="125" y2="158" stroke="#f59e0b" strokeWidth="2" strokeLinecap="round" opacity="0.9" />
          {/* brillo del lente */}
          <circle cx="110" cy="152" r="3.5" fill="white" opacity="0.2" />
        </g>
      )}
    </svg>
  )
}

// ─── SVG Gauge ───────────────────────────────────────────────────────────────

const ARC_R = 80
const ARC_CX = 100
const ARC_CY = 100
const CIRCUMFERENCE = Math.PI * ARC_R

function GaugeSVG({ puntuacion, color, animate }) {
  const filled = animate ? (puntuacion / 100) * CIRCUMFERENCE : 0
  const offset = CIRCUMFERENCE - filled

  return (
    <svg viewBox="0 0 200 110" className="gauge-svg" aria-label={`Puntuación de riesgo: ${puntuacion}`}>
      <path
        d={`M ${ARC_CX - ARC_R},${ARC_CY} A ${ARC_R},${ARC_R} 0 0,1 ${ARC_CX + ARC_R},${ARC_CY}`}
        fill="none"
        stroke="#1e3354"
        strokeWidth="14"
        strokeLinecap="round"
      />
      <path
        d={`M ${ARC_CX - ARC_R},${ARC_CY} A ${ARC_R},${ARC_R} 0 0,1 ${ARC_CX + ARC_R},${ARC_CY}`}
        fill="none"
        stroke={color}
        strokeWidth="14"
        strokeLinecap="round"
        strokeDasharray={CIRCUMFERENCE}
        strokeDashoffset={offset}
        className="gauge-arc-fill"
        style={{ filter: `drop-shadow(0 0 8px ${color}88)` }}
      />
      <text x="18" y="108" fill="#4a6080" fontSize="10" textAnchor="middle">0</text>
      <text x="100" y="16" fill="#4a6080" fontSize="10" textAnchor="middle">50</text>
      <text x="182" y="108" fill="#4a6080" fontSize="10" textAnchor="middle">100</text>
    </svg>
  )
}

// ─── VirusTotal URL Analyzer ─────────────────────────────────────────────────

async function analizarURL(url) {
  try {
    const res = await fetch('/api/vt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    if (!res.ok) throw new Error(`Error del servidor (${res.status})`)
    return await res.json()
  } catch (err) {
    return { error: err.message }
  }
}

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  const [remitente, setRemitente] = useState('')
  const [asunto, setAsunto] = useState('')
  const [cuerpo, setCuerpo] = useState('')
  const [urlSospechosa, setUrlSospechosa] = useState('')
  const [urlResultado, setUrlResultado] = useState(null)
  const [urlAnalizando, setUrlAnalizando] = useState(false)
  const [archivo, setArchivo] = useState(null)
  const [archivoResultado, setArchivoResultado] = useState(null)
  const [archivoAnalizando, setArchivoAnalizando] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [resultado, setResultado] = useState(null)
  const [analizando, setAnalizando] = useState(false)
  const [animarGauge, setAnimarGauge] = useState(false)
  const [formError, setFormError] = useState('')
  const resultsRef = useRef(null)
  const fileInputRef = useRef(null)

  async function analizarArchivo(file) {
    setArchivoAnalizando(true)
    setArchivoResultado(null)
    try {
      const base64 = await new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = () => resolve(reader.result.split(',')[1])
        reader.onerror = reject
        reader.readAsDataURL(file)
      })
      const res = await fetch('/api/vt-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, data: base64 }),
      })
      if (!res.ok) throw new Error(`Error del servidor (${res.status})`)
      setArchivoResultado(await res.json())
    } catch (err) {
      setArchivoResultado({ error: err.message })
    } finally {
      setArchivoAnalizando(false)
    }
  }

  function handleFileDrop(e) {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (!file) return
    setArchivo(file)
    analizarArchivo(file)
  }

  function handleFileSelect(e) {
    const file = e.target.files[0]
    if (!file) return
    setArchivo(file)
    analizarArchivo(file)
  }

  function cargarEjemplo() {
    setRemitente(EJEMPLO.remitente)
    setAsunto(EJEMPLO.asunto)
    setCuerpo(EJEMPLO.cuerpo)
    setFormError('')
    setResultado(null)
    setAnimarGauge(false)
  }

  function limpiarFormulario() {
    setRemitente('')
    setAsunto('')
    setCuerpo('')
    setUrlSospechosa('')
    setUrlResultado(null)
    setUrlAnalizando(false)
    setArchivo(null)
    setArchivoResultado(null)
    setArchivoAnalizando(false)
    if (fileInputRef.current) fileInputRef.current.value = ''
    setFormError('')
    setResultado(null)
    setAnimarGauge(false)
  }

  function handleSubmit(e) {
    e.preventDefault()
    if (!remitente.trim() && !cuerpo.trim()) {
      setFormError('Por favor ingrese al menos el remitente o el cuerpo del correo.')
      return
    }
    setFormError('')
    setAnalizando(true)
    setResultado(null)
    setAnimarGauge(false)
    setUrlResultado(null)

    // Análisis de URL con VirusTotal (corre en paralelo si hay URL)
    if (urlSospechosa.trim()) {
      setUrlAnalizando(true)
      analizarURL(urlSospechosa.trim()).then(res => {
        setUrlResultado(res)
        setUrlAnalizando(false)
      })
    }

    setTimeout(() => {
      const res = analizarEmail({ remitente, asunto, cuerpo, tieneAdjunto: false })
      setResultado(res)
      setAnalizando(false)
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setAnimarGauge(true))
      })
      if (resultsRef.current) {
        resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }
    }, 650)
  }

  const nivelSlug = resultado
    ? resultado.nivel === 'CRÍTICO' ? 'critico'
    : resultado.nivel === 'ALTO RIESGO' ? 'alto-riesgo'
    : resultado.nivel === 'PRECAUCIÓN' ? 'precaucion'
    : 'seguro'
    : ''

  return (
    <>
      <header className="app-header">
        <div className="header-brand">
          <DobermanMascot className="dober-header" />
          <span className="header-title">Guardian</span>
        </div>
        <p className="header-subtitle">Analizador de correos sospechosos · Herramienta interna</p>
      </header>

      <main className="app-layout">

        {/* ── Input Panel ── */}
        <section className="panel panel-input">
          <h2 className="panel-title">
            <span className="material-icons">mail_outline</span>
            Analizar correo
          </h2>
          <p className="panel-desc">Pegue los datos del correo sospechoso en los campos a continuación.</p>

          <form onSubmit={handleSubmit} noValidate>
            <div className="field-group">
              <label htmlFor="remitente">
                Remitente <span className="label-hint">(campo "De:")</span>
              </label>
              <div className="input-icon-wrap">
                <span className="material-icons input-icon">alternate_email</span>
                <input
                  id="remitente"
                  type="text"
                  value={remitente}
                  onChange={e => setRemitente(e.target.value)}
                  placeholder='soporte@empresa.com  o  "Nombre <email@dominio.com>"'
                  autoComplete="off"
                  spellCheck="false"
                />
              </div>
            </div>

            <div className="field-group">
              <label htmlFor="asunto">Asunto</label>
              <div className="input-icon-wrap">
                <span className="material-icons input-icon">subject</span>
                <input
                  id="asunto"
                  type="text"
                  value={asunto}
                  onChange={e => setAsunto(e.target.value)}
                  placeholder="Asunto del correo"
                  autoComplete="off"
                />
              </div>
            </div>

            <div className="field-group">
              <label htmlFor="cuerpo">Cuerpo del correo</label>
              <textarea
                id="cuerpo"
                value={cuerpo}
                onChange={e => setCuerpo(e.target.value)}
                placeholder="Pegue aquí el contenido completo del correo..."
                rows={12}
                spellCheck="false"
              />
            </div>

            {/* ── Campo URL VirusTotal ── */}
            <div className="field-group vt-field-group">
              <label htmlFor="url-sospechosa">
                URL sospechosa
                <span className="label-hint"> (análisis VirusTotal — opcional)</span>
              </label>
              <div className="input-icon-wrap">
                <span className="material-icons input-icon">link</span>
                <input
                  id="url-sospechosa"
                  type="text"
                  placeholder="https://ejemplo.com/pagina-sospechosa"
                  value={urlSospechosa}
                  onChange={e => setUrlSospechosa(e.target.value)}
                  spellCheck={false}
                />
              </div>
            </div>

            {/* ── Análisis de archivo ── */}
            <div className="field-group">
              <label>
                Análisis de archivo
                <span className="label-hint"> (VirusTotal — opcional)</span>
              </label>
              <div
                className={`file-drop-zone${dragging ? ' dragging' : ''}${archivo ? ' has-file' : ''}`}
                onDragOver={e => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  style={{ display: 'none' }}
                  onChange={handleFileSelect}
                />
                {archivo ? (
                  <>
                    <span className="material-icons file-drop-icon">insert_drive_file</span>
                    <span className="file-drop-name">{archivo.name}</span>
                    <span className="file-drop-size">{(archivo.size / 1024).toFixed(1)} KB</span>
                  </>
                ) : (
                  <>
                    <span className="material-icons file-drop-icon">upload_file</span>
                    <span className="file-drop-hint">Arrastra un archivo aquí</span>
                    <span className="file-drop-sub">o haz clic para seleccionar</span>
                  </>
                )}
              </div>

              {/* Resultado instantáneo del archivo */}
              {(archivoAnalizando || archivoResultado) && (
                <div className="vt-section vt-file-result">
                  {archivoAnalizando && (
                    <div className="vt-loading">
                      <span className="analyzing-ring" style={{ width: 20, height: 20, borderWidth: 2 }} />
                      <span>Analizando archivo en VirusTotal…</span>
                    </div>
                  )}
                  {archivoResultado && !archivoAnalizando && (() => {
                    if (archivoResultado.error) return (
                      <div className="vt-error">
                        <span className="material-icons">wifi_off</span>
                        {archivoResultado.error}
                      </div>
                    )
                    const { stats, engines, vtLink, cached } = archivoResultado
                    const total   = Object.values(stats).reduce((a, b) => a + b, 0)
                    const mal     = stats.malicious  || 0
                    const sus     = stats.suspicious || 0
                    const flagged = mal + sus
                    const vtNivel = mal >= 3 ? 'malicioso' : mal >= 1 || sus >= 2 ? 'sospechoso' : 'limpio'
                    const vtColor = vtNivel === 'malicioso'  ? 'var(--color-critico)'
                                  : vtNivel === 'sospechoso' ? 'var(--color-precaucion)'
                                  : 'var(--color-seguro)'
                    return (
                      <div className="vt-result">
                        <div className="vt-summary">
                          <div className="vt-ratio" style={{ color: vtColor }}>
                            <span className="vt-ratio-num">{flagged}</span>
                            <span className="vt-ratio-sep"> / </span>
                            <span className="vt-ratio-total">{total}</span>
                          </div>
                          <div className="vt-summary-text">
                            <span className="vt-badge" style={{ color: vtColor, borderColor: vtColor + '55', background: vtColor + '18' }}>
                              {vtNivel === 'malicioso' ? '🔴 MALICIOSO' : vtNivel === 'sospechoso' ? '🟡 SOSPECHOSO' : '🟢 LIMPIO'}
                            </span>
                            <span className="vt-sub">motores lo detectaron como {vtNivel}</span>
                            {cached && <span className="vt-date">Resultado desde caché de VirusTotal</span>}
                          </div>
                          {vtLink && (
                            <a href={vtLink} target="_blank" rel="noreferrer" className="vt-link-btn">
                              <span className="material-icons">open_in_new</span>
                              Ver en VT
                            </a>
                          )}
                        </div>
                        {engines.length > 0 && (
                          <div className="vt-engines">
                            {engines.map(e => (
                              <span key={e.name} className={`vt-engine-tag vt-engine-${e.category}`}>
                                {e.name}: {e.result}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })()}
                </div>
              )}
            </div>

            {formError && (
              <p className="form-error">
                <span className="material-icons">error_outline</span>
                {formError}
              </p>
            )}

            <div className="action-buttons">
              <button type="button" className="btn btn-secondary" onClick={cargarEjemplo}>
                <span className="material-icons">science</span>
                Ejemplo
              </button>
              <button type="button" className="btn btn-ghost" onClick={limpiarFormulario}>
                <span className="material-icons">restart_alt</span>
                Limpiar
              </button>
              <button type="submit" className="btn btn-primary" disabled={analizando}>
                {analizando ? (
                  <>
                    <span className="spinner" aria-hidden="true" />
                    Analizando...
                  </>
                ) : (
                  <>
                    <span className="material-icons">shield</span>
                    Analizar
                  </>
                )}
              </button>
            </div>
          </form>
        </section>

        {/* ── Results Panel ── */}
        <section className="panel panel-results" ref={resultsRef}>

          {!resultado && !analizando && (
            <div className="empty-state">
              <DobermanMascot className="dober-empty" />
              <h3>Listo para analizar</h3>
              <p>Complete los campos del correo y presione <strong>Analizar</strong> para obtener una evaluación de riesgo detallada.</p>
              <p className="empty-hint">Use <strong>Ejemplo</strong> para ver la herramienta en acción.</p>
            </div>
          )}

          {analizando && (
            <div className="analyzing-state">
              <DobermanMascot className="dober-empty" searching />
              <p className="analyzing-label">Analizando señales de riesgo...</p>
            </div>
          )}

          {resultado && !analizando && (
            <div className="results-content">

              {/* Gauge */}
              <div className="gauge-container">
                <GaugeSVG
                  puntuacion={resultado.puntuacion}
                  color={resultado.nivelColor}
                  animate={animarGauge}
                />
                <div className="score-display">
                  <span className="score-number" style={{ color: resultado.nivelColor }}>
                    {resultado.puntuacion}
                  </span>
                  <span className="score-label">/ 100</span>
                </div>
                <div
                  className={`nivel-badge nivel-${nivelSlug}`}
                  style={{
                    color: resultado.nivelColor,
                    borderColor: resultado.nivelColor + '55',
                    backgroundColor: resultado.nivelColor + '18',
                  }}
                >
                  {resultado.nivel}
                </div>
                <DobermanMascot className="dober-result" nivel={resultado.nivel} />
              </div>

              {/* ── VirusTotal URL Result ── */}
              {(urlAnalizando || urlResultado) && (
                <div className="vt-section">
                  <h3 className="section-title">
                    <span className="material-icons">manage_search</span>
                    Análisis de URL · VirusTotal
                  </h3>

                  {urlAnalizando && (
                    <div className="vt-loading">
                      <span className="analyzing-ring" style={{ width: 22, height: 22, borderWidth: 2 }} />
                      <span>Consultando VirusTotal…</span>
                    </div>
                  )}

                  {urlResultado && !urlAnalizando && (() => {
                    if (urlResultado.error) return (
                      <div className="vt-error">
                        <span className="material-icons">wifi_off</span>
                        {urlResultado.error}
                      </div>
                    )
                    const { stats, engines, vtLink, scanDate } = urlResultado
                    const total   = Object.values(stats).reduce((a, b) => a + b, 0)
                    const mal     = stats.malicious  || 0
                    const sus     = stats.suspicious || 0
                    const flagged = mal + sus
                    const vtNivel = mal >= 3 ? 'maliciosa' : mal >= 1 || sus >= 2 ? 'sospechosa' : 'limpia'
                    const vtColor = vtNivel === 'maliciosa' ? 'var(--color-critico)'
                                  : vtNivel === 'sospechosa' ? 'var(--color-precaucion)'
                                  : 'var(--color-seguro)'
                    return (
                      <div className="vt-result">
                        <div className="vt-summary">
                          <div className="vt-ratio" style={{ color: vtColor }}>
                            <span className="vt-ratio-num">{flagged}</span>
                            <span className="vt-ratio-sep"> / </span>
                            <span className="vt-ratio-total">{total}</span>
                          </div>
                          <div className="vt-summary-text">
                            <span className="vt-badge" style={{ color: vtColor, borderColor: vtColor + '55', background: vtColor + '18' }}>
                              {vtNivel === 'maliciosa' ? '🔴 MALICIOSA' : vtNivel === 'sospechosa' ? '🟡 SOSPECHOSA' : '🟢 LIMPIA'}
                            </span>
                            <span className="vt-sub">motores la detectaron como {vtNivel}</span>
                            {scanDate && <span className="vt-date">Último escaneo: {scanDate}</span>}
                          </div>
                          {vtLink && (
                            <a href={vtLink} target="_blank" rel="noreferrer" className="vt-link-btn">
                              <span className="material-icons">open_in_new</span>
                              Ver en VirusTotal
                            </a>
                          )}
                        </div>

                        {engines.length > 0 && (
                          <div className="vt-engines">
                            {engines.map(e => (
                              <span key={e.name} className={`vt-engine-tag vt-engine-${e.category}`}>
                                {e.name}: {e.result}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })()}
                </div>
              )}

              {/* Signals */}
              <div className="signals-section">
                <h3 className="section-title">
                  <span className="material-icons">radar</span>
                  Señales detectadas
                  <span className="signals-count">{resultado.senalesDetectadas.length} / 9</span>
                </h3>

                {resultado.senalesDetectadas.length === 0 ? (
                  <div className="no-signals">
                    <span className="material-icons">check_circle</span>
                    No se encontraron señales de riesgo.
                  </div>
                ) : (
                  <div className="signals-list">
                    {resultado.senalesDetectadas.map((senal, i) => (
                      <div
                        key={senal.id}
                        className={`signal-card sev-${senal.severidad}`}
                        style={{ animationDelay: `${i * 65}ms` }}
                      >
                        <span className={`material-icons signal-icon sev-icon-${senal.severidad}`}>
                          {senal.icono}
                        </span>
                        <div className="signal-body">
                          <strong className="signal-name">{senal.nombre}</strong>
                          <p className="signal-desc">{senal.descripcion}</p>
                        </div>
                        <span className="signal-pts">+{senal.peso}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Recommendations */}
              <div className="recs-section">
                <h3 className="section-title">
                  <span className="material-icons">tips_and_updates</span>
                  Qué hacer
                </h3>
                <ul className="recs-list">
                  {resultado.recomendaciones.map((rec, i) => (
                    <li key={i} className="rec-item">
                      <span className="material-icons rec-chevron">chevron_right</span>
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Report to Cybersecurity */}
              {resultado.nivel !== 'SEGURO' && (
                <div className="report-section">
                  <div className="report-header">
                    <span className="material-icons">forward_to_inbox</span>
                    <div>
                      <strong>¿Necesita un análisis profundo?</strong>
                      <p>Envíe este reporte al equipo de Ciberseguridad de Haceb para una investigación detallada.</p>
                    </div>
                  </div>
                  <a
                    href={generarMailto(resultado, remitente, asunto)}
                    className="btn btn-report"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span className="material-icons">send</span>
                    Reportar a ciberseguridad@haceb.com
                  </a>
                  <p className="report-hint">
                    <span className="material-icons">info_outline</span>
                    Se abrirá su cliente de correo con un reporte pre-llenado. Adjunte una captura de pantalla de esta pantalla.
                  </p>
                </div>
              )}

            </div>
          )}
        </section>

      </main>

      <footer className="app-footer">
        <span className="material-icons">info_outline</span>
        Guardian es una herramienta de apoyo. Ante cualquier duda, contacte a su equipo de TI o seguridad corporativa.
      </footer>
    </>
  )
}
