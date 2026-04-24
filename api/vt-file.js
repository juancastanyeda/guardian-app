const VT_API_KEY = '439792ab6453964b91dbe99f5cf4dff12ab412183cb2a8d6cc8dc30f484d0d18'

export const config = {
  maxDuration: 60,
  api: { bodyParser: { sizeLimit: '32mb' } },
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })

  const { filename, data } = req.body || {}
  if (!filename || !data) return res.status(400).json({ error: 'Archivo requerido' })

  try {
    const buffer = Buffer.from(data, 'base64')

    // ── Intentar lookup por hash SHA-256 primero (sin subir el archivo) ──
    const { createHash } = await import('node:crypto')
    const sha256 = createHash('sha256').update(buffer).digest('hex')

    const hashRes = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: { 'x-apikey': VT_API_KEY },
    })

    if (hashRes.ok) {
      const data = await hashRes.json()
      const attrs = data.data?.attributes
      if (attrs?.last_analysis_stats) {
        const engines = Object.entries(attrs.last_analysis_results || {})
          .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
          .map(([name, v]) => ({ name, category: v.category, result: v.result }))
          .slice(0, 10)
        return res.status(200).json({
          stats: attrs.last_analysis_stats,
          engines,
          filename: attrs.meaningful_name || filename,
          sha256,
          vtLink: `https://www.virustotal.com/gui/file/${sha256}`,
          cached: true,
        })
      }
    }

    // ── Subir archivo nuevo ──
    const blob = new Blob([buffer])
    const form = new FormData()
    form.append('file', blob, filename)

    const uploadRes = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': VT_API_KEY },
      body: form,
    })

    if (!uploadRes.ok) {
      const errText = await uploadRes.text()
      return res.status(200).json({ error: `Error al subir archivo (${uploadRes.status}): ${errText}` })
    }

    const uploadData = await uploadRes.json()
    const analysisId = uploadData.data.id

    // ── Polling (máx 15 intentos × 3s = 45s) ──
    for (let i = 0; i < 15; i++) {
      await new Promise(r => setTimeout(r, 3000))
      const pollRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VT_API_KEY },
      })
      const pollData = await pollRes.json()
      if (pollData.data?.attributes?.status === 'completed') {
        const stats = pollData.data.attributes.stats
        const engines = Object.entries(pollData.data.attributes.results || {})
          .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
          .map(([name, v]) => ({ name, category: v.category, result: v.result }))
          .slice(0, 10)
        return res.status(200).json({
          stats,
          engines,
          filename,
          sha256,
          vtLink: `https://www.virustotal.com/gui/file/${sha256}`,
        })
      }
    }

    return res.status(200).json({ error: 'El análisis tardó demasiado. Intente de nuevo.' })
  } catch (err) {
    return res.status(200).json({ error: err.message })
  }
}
