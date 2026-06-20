// Cloudflare Pages Functions: /api/state
// 暗号文（E2Eで暗号化済みのvault JSON）をユーザー単位でKVに読み書きする。
// 認証は Cloudflare Access が前段で実施済み。ここでは本人のメールでキーを分けるだけ。
//
// 必要な設定:
//   - Pages プロジェクトに KV 名前空間をバインド（変数名: VAULT）
//   - Pages 全体に Cloudflare Access を適用（Google等のIdPで自分のみ許可）
//
// 平文はここを通らない（ブラウザ側で暗号化済み）。サーバーは中身を読めない。

export async function onRequest(context) {
  const { request, env } = context;

  // Access が検証済みのメール。未設定時(ローカル等)は default。
  const email = request.headers.get('Cf-Access-Authenticated-User-Email') || 'default';
  const key = 'vault:' + email;

  if (request.method === 'GET') {
    const data = await env.VAULT.get(key);
    return new Response(data || '', {
      headers: { 'content-type': 'application/json; charset=utf-8' }
    });
  }

  if (request.method === 'PUT') {
    const body = await request.text();
    // 軽い上限（個人用途には十分）
    if (body.length > 2_000_000) {
      return new Response('Payload too large', { status: 413 });
    }
    await env.VAULT.put(key, body);
    return new Response('ok');
  }

  return new Response('Method Not Allowed', { status: 405 });
}
