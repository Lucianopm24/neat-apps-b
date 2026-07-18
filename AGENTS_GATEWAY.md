# Parche para neat-apps-b (Vercel) — Gateway de agentes v0

## Qué hace
Agrega 7 endpoints NUEVOS (100% aditivo, no modifica nada existente):

**Provisioning (humano autenticado):**
- `POST /agents/keys` — crear key para el humano logueado (respuesta incluye la key UNA vez)
- `GET /agents/keys` — listar keys propias (solo metadata)
- `DELETE /agents/keys/:id` — revocar

**Datos (solo el Worker, con secreto interno):**
- `POST/GET /agents/internal/notes`, `GET/PATCH/DELETE /agents/internal/notes/:id`
- Notas de agente: `visibility=private` por defecto, `via:'agent'` (auditoría)
- Soporta `?updated_since=`, `?q=`, `?tag=`, paginación, límite 64KB/nota

## Cómo aplicar
1. Copiar el contenido de `agents_gateway_snippet.js`
2. Pegarlo en `index.js` de neat-apps-b **al final, antes de `app.listen`**
3. Commit + push (Vercel auto-deploya)

## Env vars requeridas en Vercel (Settings → Environment Variables)
| Var | Valor |
|---|---|
| `NEAT_INTERNAL_SECRET` | (el generado por Claw — mismo que el Worker) |
| `AGENTS_WORKER_URL` | `https://agents.neat.qzz.io` (o la URL .workers.dev temporal) |

## Seguridad
- `internalAuth` es **fail-closed**: sin `NEAT_INTERNAL_SECRET` configurado, los endpoints internos devuelven 503 y no operan. Nunca modo abierto.
- El frontend de id.neat.qzz.io solo necesita llamar `POST /agents/keys` y mostrar `data.key` UNA vez avisando que no es recuperable.
- Recordatorio Claw 🦞: al tocar index.js, oportunidad ideal para los fixes #10 (visibility private) y #11 (defaults "changeme") del checklist.
