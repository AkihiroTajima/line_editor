// Cloudflare Pages Functions: /api/state
// 暗号文（E2Eで暗号化済みのvault JSON）をKVに読み書きする。
// 認証は「共有トークン」方式（Cloudflare Access の代替・カード不要）。
//
// 必要な設定:
//   - Pages プロジェクトに KV 名前空間をバインド（変数名: VAULT）
//   - Pages の環境変数(シークレット)に API_TOKEN を登録（任意の長いランダム文字列）
//
// クライアントは Authorization: Bearer <API_TOKEN> を送る。
// トークンが一致しない場合は 401 を返す（クライアントはローカル専用モードへ）。
// 平文はここを通らない（ブラウザ側で暗号化済み）。サーバーは中身を読めない。
//
// 同期モードでデータを分離:
//   - オート(auto)   : 単一スロットを上書き保存          → キー vault:default
//   - マニュアル(manual): 保存操作ごとにスナップショット追加 → キー vault:manual:<id>
//
// ルーティング（?mode= と ?id= で分岐）:
//   GET    /api/state?mode=auto              → オートスロットの暗号文（無ければ空）
//   PUT    /api/state?mode=auto              → オートスロットを上書き保存
//   GET    /api/state?mode=manual            → スナップショット一覧 {snapshots:[{id,ts,label}]}
//   GET    /api/state?mode=manual&id=<id>    → 指定スナップショットの暗号文
//   PUT    /api/state?mode=manual            → 新規スナップショットを追加 {id,ts}
//   DELETE /api/state?mode=manual&id=<id>    → 指定スナップショットを削除
//   （mode 省略時は auto 扱い・旧クライアント互換）

const AUTO_KEY = 'vault:default';        // 旧版と同じキーで既存データを引き継ぐ
const MANUAL_PREFIX = 'vault:manual:';
const MAX_BYTES = 2_000_000;
const MAX_SNAPSHOTS = 50;                // 古いものから自動削除する保持件数

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
    // トークン不一致 → クライアントはローカル専用モードで動作する
    return new Response('Unauthorized', { status: 401 });
  }

  const url = new URL(request.url);
  const mode = url.searchParams.get('mode') || 'auto';
  const id = url.searchParams.get('id');
  const jsonHeaders = { 'content-type': 'application/json; charset=utf-8' };

  // ---- オート: 単一スロットを上書き ----
  if (mode === 'auto') {
    if (request.method === 'GET') {
      const data = await env.VAULT.get(AUTO_KEY);
      return new Response(data || '', { headers: jsonHeaders });
    }
    if (request.method === 'PUT') {
      const body = await request.text();
      if (body.length > MAX_BYTES) return new Response('Payload too large', { status: 413 });
      await env.VAULT.put(AUTO_KEY, body);
      return new Response('ok');
    }
    return new Response('Method Not Allowed', { status: 405 });
  }

  // ---- マニュアル: スナップショット ----
  if (mode === 'manual') {
    if (request.method === 'GET') {
      if (id) {
        const data = await env.VAULT.get(MANUAL_PREFIX + id);
        if (data == null) return new Response('Not Found', { status: 404 });
        return new Response(data, { headers: jsonHeaders });
      }
      // 一覧（メタデータの ts で新しい順）
      const list = await env.VAULT.list({ prefix: MANUAL_PREFIX });
      const snapshots = list.keys.map(k => ({
        id: k.name.slice(MANUAL_PREFIX.length),
        ts: (k.metadata && k.metadata.ts) || 0,
        label: (k.metadata && k.metadata.label) || ''
      })).sort((a, b) => b.ts - a.ts);
      return new Response(JSON.stringify({ snapshots }), { headers: jsonHeaders });
    }
    if (request.method === 'PUT') {
      const body = await request.text();
      if (body.length > MAX_BYTES) return new Response('Payload too large', { status: 413 });
      const now = Date.now();
      const rand = Math.random().toString(36).slice(2, 8);
      const sid = now + '-' + rand;
      const label = (url.searchParams.get('label') || '').slice(0, 120);
      await env.VAULT.put(MANUAL_PREFIX + sid, body, { metadata: { ts: now, label } });

      // 保持件数を超えたら古いものから削除
      const list = await env.VAULT.list({ prefix: MANUAL_PREFIX });
      if (list.keys.length > MAX_SNAPSHOTS) {
        const old = list.keys
          .map(k => ({ name: k.name, ts: (k.metadata && k.metadata.ts) || 0 }))
          .sort((a, b) => a.ts - b.ts)
          .slice(0, list.keys.length - MAX_SNAPSHOTS);
        for (const o of old) await env.VAULT.delete(o.name);
      }
      return new Response(JSON.stringify({ id: sid, ts: now }), { headers: jsonHeaders });
    }
    if (request.method === 'DELETE') {
      if (!id) return new Response('Missing id', { status: 400 });
      await env.VAULT.delete(MANUAL_PREFIX + id);
      return new Response('ok');
    }
    return new Response('Method Not Allowed', { status: 405 });
  }

  return new Response('Bad mode', { status: 400 });
}
