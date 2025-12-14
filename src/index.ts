import { Hono } from "hono";
import { jwtVerify, createRemoteJWKSet } from 'jose'

/**
 * Hono アプリで Cloudflare Access の JWT を検証する。
 * Cf‑Access‑Jwt‑Assertion ヘッダーから取得した JWT を公開鍵で検証し、issuer と audience を照合する。
 * https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
 */
type EnvBindings = {
  CF_ACCESS_TEAM_DOMAIN: string  // https://<team>.cloudflareaccess.com
  CF_ACCESS_AUD: string          // アプリケーションの AUD タグ
}

type CfAccessVars = {
  cfAccessJwt?: {
    payload: Record<string, unknown>
  }
}

const app = new Hono<{ Bindings: EnvBindings; Variables: CfAccessVars }>();

// アプリ全体に適用するミドルウェア
app.use(async (c, next) => {
  const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN
  const aud = c.env.CF_ACCESS_AUD

  // 必須の環境変数が設定されているかチェック
  if (!teamDomain || !aud) {
    return c.text('Missing required environment variables', 500)
  }

  // Cloudflare Access が付与する JWT を取得
  const token = c.req.header('cf-access-jwt-assertion')
  if (!token) {
    return c.text('Missing CF Access JWT', 403)
  }

  // 公開鍵のリモートセットを取得
  const jwks = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`))

  try {
    // JWT の検証
    const { payload } = await jwtVerify(token, jwks, {
      issuer: teamDomain,
      audience: aud,
    })

    // 検証成功時は payload をコンテキストに保存し次の処理へ
    c.set('cfAccessJwt', { payload: payload as Record<string, unknown> })
    await next()
  } catch (err) {
    // 検証失敗時は 403 を返す
    return c.text('Invalid CF Access JWT', 403)
  }
})


app.get("/message", (c) => {
  // ミドルウェアで保存した payload からメールアドレスなどを取り出す
  const jwt = c.get('cfAccessJwt')
  const payload = jwt?.payload || {}
  const email = (payload as any).email as string | undefined

  return c.text(`Hello ${email}`);
});

export default app;
