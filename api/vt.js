const VT_API_KEY = '439792ab6453964b91dbe99f5cf4dff12ab412183cb2a8d6cc8dc30f484d0d18'

export const config = { maxDuration: 25 }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') return res.status(200).end()
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })

  const { url } = req.body || {}
  if (!url) return res.status(400).json({ error: 'URL requerida' })

  try {
    const urlId = Buffer.from(url).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

    // 1 — Intentar reporte existente (rápido)
    const reportRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': VT_API_KEY },
    })

    if (reportRes.ok) {
      const data = await reportRes.json()
      const attrs = data.data?.attributes
      if (attrs?.last_analysis_stats) {
        const engines = Object.entries(attrs.last_analysis_results || {})
          .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
          .map(([name, v]) => ({ name, category: v.category, result: v.result }))
          .slice(0, 8)
        return res.status(200).json({
          stats: attrs.last_analysis_stats,
          engines,
          url: attrs.url || url,
          scanDate: attrs.last_analysis_date
            ? new Date(attrs.last_analysis_date * 1000).toLocaleDateString('es-CO')
            : null,
          vtLink: `https://www.virustotal.com/gui/url/${urlId}`,
        })
      }
    }

    // 2 — Enviar URL para análisis nuevo
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    })

    if (!submitRes.ok) {
      const errText = await submitRes.text()
      return res.status(200).json({ error: `Error al enviar URL (${submitRes.status}): ${errText}` })
    }

    const submitData = await submitRes.json()
    const analysisId = submitData.data.id

    // 3 — Polling (máx 10 intentos × 2s = 20s)
    for (let i = 0; i < 10; i++) {
      await new Promise(r => setTimeout(r, 2000))
      const pollRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VT_API_KEY },
      })
      const pollData = await pollRes.json()
      if (pollData.data?.attributes?.status === 'completed') {
        const stats = pollData.data.attributes.stats
        const engines = Object.entries(pollData.data.attributes.results || {})
          .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
          .map(([name, v]) => ({ name, category: v.category, result: v.result }))
          .slice(0, 8)
        return res.status(200).json({
          stats,
          engines,
          url,
          vtLink: `https://www.virustotal.com/gui/url/${urlId}`,
        })
      }
    }

    return res.status(200).json({ error: 'El análisis tardó demasiado. Intente de nuevo en un momento.' })
  } catch (err) {
    return res.status(200).json({ error: err.message })
  }
}
