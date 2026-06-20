// Cloudflare Pages Functions: /api/state
// 暗号文（E2Eで暗号化済みのvault JSON）をKVに読み書きする。
// 認証は「共有トークン」方式（Cloudflare Access の代替・カード不要）。
//
// 必要な設定:
//   - Pages プロジェクトに KV 名前空間をバインド（変数名: VAULT）
//   - Pages の環境変数(シークレット)に API_TOKEN を登録（任意の長いランダム文字列）
//
// クライアントは Authorization: Bearer <API_TOKEN> を送る。
// 平文はここを通らない（ブラウザ側で暗号化済み）。サーバーは中身を読めない。

export async function onRequest(context) {
  const { request, env } = context;

  // 共有トークン認証
  const expected = env.API_TOKEN;
  if (!expected) {
    return new Response('Server not configured: API_TOKEN is unset', { status: 503 });
  }
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (token !== expected) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 単一ユーザー想定の固定キー（旧版と同じキーで既存データを引き継ぐ）
  const key = 'vault:default';

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
