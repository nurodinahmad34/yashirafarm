// src/index.js

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================
function generateId() { return crypto.randomUUID(); }
function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    return `pbkdf2$100000$${Array.from(salt).join(',')}$${Array.from(new Uint8Array(bits)).join(',')}`;
}

async function verifyPassword(password, storedHash) {
    const parts = storedHash.split('$');
    if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
    const iterations = parseInt(parts[1]);
    const salt = new Uint8Array(parts[2].split(',').map(Number));
    const originalHash = parts[3].split(',').map(Number);
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
    const newHash = Array.from(new Uint8Array(bits));
    if (newHash.length !== originalHash.length) return false;
    for (let i = 0; i < newHash.length; i++) { if (newHash[i] !== originalHash[i]) return false; }
    return true;
}

function parseCookies(request) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
        const [name, ...rest] = cookie.trim().split('=');
        if (name) cookies[name] = rest.join('=');
    });
    return cookies;
}

// ========================================================================
// AUTH HELPERS
// ========================================================================
async function getUserFromSession(request, env) {
    const cookies = parseCookies(request);
    const sessionId = cookies.session_id;
    if (!sessionId) return null;
    const session = await env.DB.prepare('SELECT user_id, expires_at FROM sessions WHERE id = ?').bind(sessionId).first();
    if (!session) return null;
    if (new Date(session.expires_at) < new Date()) {
        await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
        return null;
    }
    return await env.DB.prepare('SELECT id, email, nama, role, status FROM users WHERE id = ?').bind(session.user_id).first();
}

async function requireAuth(request, env) {
    const user = await getUserFromSession(request, env);
    if (!user) return { error: jsonResponse({ error: 'Silakan login terlebih dahulu' }, 401) };
    return { user };
}

async function requireAdmin(request, env) {
    const auth = await requireAuth(request, env);
    if (auth.error) return auth;
    if (auth.user.role !== 'admin') return { error: jsonResponse({ error: 'Akses ditolak. Hanya admin.' }, 403) };
    return auth;
}

async function checkUserStatus(user, env) {
    if (user.status === 'blocked') {
        const setting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('suspend_message').first();
        return { allowed: false, message: setting ? setting.value : 'Akun Anda telah diblokir.' };
    }
    return { allowed: true };
}

// ========================================================================
// MAIN HANDLER
// ========================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        if (path.startsWith('/api/')) {
            return handleAPI(request, env, path, method);
        }

        const asset = await env.ASSETS.fetch(request);
        if (asset.status !== 404) return asset;
        return await env.ASSETS.fetch(new URL('/index.html', request.url));
    }
};

// ========================================================================
// API HANDLER
// ========================================================================
async function handleAPI(request, env, path, method) {
    // AUTH: REGISTER
    if (path === '/api/auth/register' && method === 'POST') {
        try {
            const { email, password, nama } = await request.json();
            if (!email || !password) return jsonResponse({ error: 'Email dan password wajib diisi' }, 400);
            if (password.length < 6) return jsonResponse({ error: 'Password minimal 6 karakter' }, 400);
            const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
            if (existing) return jsonResponse({ error: 'Email sudah terdaftar' }, 400);
            const userCount = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
            const role = userCount.c === 0 ? 'admin' : 'member';
            const id = generateId();
            const passwordHash = await hashPassword(password);
            await env.DB.prepare('INSERT INTO users (id, email, password_hash, nama, role, status) VALUES (?, ?, ?, ?, ?, ?)')
                .bind(id, email, passwordHash, nama || 'Pengguna', role, 'active').run();
            return jsonResponse({ message: 'Registrasi berhasil! Silakan login.', role }, 201);
        } catch (e) { return jsonResponse({ error: 'Terjadi kesalahan: ' + e.message }, 500); }
    }

    // AUTH: LOGIN
    if (path === '/api/auth/login' && method === 'POST') {
        try {
            const { email, password } = await request.json();
            if (!email || !password) return jsonResponse({ error: 'Email dan password wajib diisi' }, 400);
            const user = await env.DB.prepare('SELECT id, email, password_hash, nama, role, status FROM users WHERE email = ?').bind(email).first();
            if (!user) return jsonResponse({ error: 'Email atau password salah' }, 401);
            const valid = await verifyPassword(password, user.password_hash);
            if (!valid) return jsonResponse({ error: 'Email atau password salah' }, 401);
            const statusCheck = await checkUserStatus(user, env);
            if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
            const sessionId = generateId();
            const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            await env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(sessionId, user.id, expiresAt).run();
            return new Response(JSON.stringify({ message: 'Login berhasil!', user: { id: user.id, email: user.email, nama: user.nama, role: user.role } }), {
                status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': `session_id=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${30*24*60*60}` }
            });
        } catch (e) { return jsonResponse({ error: 'Terjadi kesalahan: ' + e.message }, 500); }
    }

    // AUTH: LOGOUT
    if (path === '/api/auth/logout' && method === 'POST') {
        const cookies = parseCookies(request);
        if (cookies.session_id) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(cookies.session_id).run();
        return new Response(JSON.stringify({ message: 'Logout berhasil' }), { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'session_id=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' } });
    }

    // AUTH: ME
    if (path === '/api/auth/me' && method === 'GET') {
        const user = await getUserFromSession(request, env);
        if (!user) return jsonResponse({ user: null }, 200);
        const statusCheck = await checkUserStatus(user, env);
        if (!statusCheck.allowed) return jsonResponse({ user: null, blocked: true, message: statusCheck.message }, 200);
        return jsonResponse({ user });
    }

    // KOLONI: GET
    if (path === '/api/koloni' && method === 'GET') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        const koloni = await env.DB.prepare('SELECT * FROM koloni WHERE user_id = ? ORDER BY created_at DESC').bind(auth.user.id).all();
        return jsonResponse({ koloni: koloni.results || [] });
    }

    // KOLONI: POST
    if (path === '/api/koloni' && method === 'POST') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        const { nama, tanggalLahir, populasi, pakanPerHari } = await request.json();
        if (!nama || !tanggalLahir) return jsonResponse({ error: 'Nama dan tanggal lahir wajib diisi' }, 400);
        const id = generateId();
        await env.DB.prepare('INSERT INTO koloni (id, user_id, nama, tanggal_lahir, populasi, pakan_per_hari) VALUES (?, ?, ?, ?, ?, ?)').bind(id, auth.user.id, nama, tanggalLahir, parseInt(populasi) || 0, parseFloat(pakanPerHari) || 0).run();
        return jsonResponse({ message: 'Koloni ditambahkan', id }, 201);
    }

    // KOLONI: DELETE
    if (path.startsWith('/api/koloni/') && method === 'DELETE') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        const koloniId = path.split('/').pop();
        await env.DB.prepare('DELETE FROM koloni WHERE id = ? AND user_id = ?').bind(koloniId, auth.user.id).run();
        return jsonResponse({ message: 'Koloni dihapus' });
    }

    // KEUANGAN: GET
    if (path === '/api/keuangan' && method === 'GET') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        const keuangan = await env.DB.prepare('SELECT * FROM keuangan WHERE user_id = ? ORDER BY tanggal DESC').bind(auth.user.id).all();
        return jsonResponse({ keuangan: keuangan.results || [] });
    }

    // KEUANGAN: POST
    if (path === '/api/keuangan' && method === 'POST') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        const { tipe, kategori, nominal, tanggal, deskripsi } = await request.json();
        if (!tipe || !kategori || !nominal || !tanggal) return jsonResponse({ error: 'Semua field wajib diisi' }, 400);
        const id = generateId();
        await env.DB.prepare('INSERT INTO keuangan (id, user_id, tipe, kategori, nominal, tanggal, deskripsi) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, auth.user.id, tipe, kategori, parseInt(nominal), tanggal, deskripsi || '').run();
        return jsonResponse({ message: 'Transaksi ditambahkan', id }, 201);
    }

    // KEUANGAN: DELETE
    if (path.startsWith('/api/keuangan/') && method === 'DELETE') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        const trxId = path.split('/').pop();
        await env.DB.prepare('DELETE FROM keuangan WHERE id = ? AND user_id = ?').bind(trxId, auth.user.id).run();
        return jsonResponse({ message: 'Transaksi dihapus' });
    }

    // USER: RESET DATA SENDIRI
    if (path === '/api/user/reset' && method === 'DELETE') {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.error;
        const statusCheck = await checkUserStatus(auth.user, env);
        if (!statusCheck.allowed) return jsonResponse({ error: 'access_denied', message: statusCheck.message }, 403);
        await env.DB.batch([
            env.DB.prepare('DELETE FROM koloni WHERE user_id = ?').bind(auth.user.id),
            env.DB.prepare('DELETE FROM keuangan WHERE user_id = ?').bind(auth.user.id)
        ]);
        return jsonResponse({ message: 'Semua data berhasil dihapus' });
    }

    // ----------------------------------------------------------------
    // ADMIN: GET SEMUA USER (DENGAN STATISTIK)
    // ----------------------------------------------------------------
    if (path === '/api/admin/users' && method === 'GET') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        const users = await env.DB.prepare(`
            SELECT u.id, u.email, u.nama, u.role, u.status, u.created_at,
                COUNT(k.id) as total_transaksi, MAX(k.created_at) as aktivitas_terakhir
            FROM users u LEFT JOIN keuangan k ON u.id = k.user_id
            GROUP BY u.id ORDER BY u.created_at DESC
        `).all();
        return jsonResponse({ users: users.results || [] });
    }

    // ----------------------------------------------------------------
    // ADMIN: HAPUS DATA MEMBER (RESET OLEH ADMIN)
    // ----------------------------------------------------------------
    if (path === '/api/admin/users/reset' && method === 'DELETE') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        const { userId } = await request.json();
        if (!userId) return jsonResponse({ error: 'User ID wajib diisi' }, 400);
        
        await env.DB.batch([
            env.DB.prepare('DELETE FROM koloni WHERE user_id = ?').bind(userId),
            env.DB.prepare('DELETE FROM keuangan WHERE user_id = ?').bind(userId)
        ]);
        return jsonResponse({ message: 'Data member berhasil dihapus permanen' });
    }

    // ADMIN: UPDATE STATUS USER
    if (path === '/api/admin/users/status' && method === 'PUT') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        const { userId, status } = await request.json();
        if (!['active', 'blocked'].includes(status)) return jsonResponse({ error: 'Status tidak valid' }, 400);
        await env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind(status, userId).run();
        return jsonResponse({ message: `Status diubah menjadi ${status}` });
    }

    // ADMIN: GET TEKS SUSPEND
    if (path === '/api/admin/suspend-message' && method === 'GET') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        const setting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('suspend_message').first();
        return jsonResponse({ message: setting ? setting.value : '' });
    }

    // ADMIN: UPDATE TEKS SUSPEND
    if (path === '/api/admin/suspend-message' && method === 'PUT') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        const { message } = await request.json();
        if (!message) return jsonResponse({ error: 'Pesan tidak boleh kosong' }, 400);
        await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)').bind('suspend_message', message).run();
        return jsonResponse({ message: 'Teks suspend diperbarui' });
    }

    // ADMIN: UPLOAD GAMBAR POPUP
    if (path === '/api/admin/popup/upload' && method === 'POST') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        try {
            const formData = await request.formData();
            const file = formData.get('image');
            if (!file) return jsonResponse({ error: 'File tidak ditemukan' }, 400);
            const fileName = `popup-${Date.now()}.${file.name.split('.').pop()}`;
            await env.BUCKET.put(fileName, file.stream(), { httpMetadata: { contentType: file.type } });
            return jsonResponse({ message: 'Upload berhasil', imageUrl: `/api/public/image/${fileName}` });
        } catch (e) { return jsonResponse({ error: 'Gagal upload: ' + e.message }, 500); }
    }

    // PUBLIC: LIHAT GAMBAR
    if (path.startsWith('/api/public/image/') && method === 'GET') {
        const fileName = path.split('/').pop();
        const object = await env.BUCKET.get(fileName);
        if (!object) return new Response('Gambar tidak ditemukan', { status: 404 });
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        headers.set('Cache-Control', 'public, max-age=86400');
        return new Response(object.body, { headers });
    }

    // ADMIN: SIMPAN SETTING POPUP
    if (path === '/api/admin/popup' && method === 'PUT') {
        const auth = await requireAdmin(request, env);
        if (auth.error) return auth.error;
        const { is_active, image_url, link_url } = await request.json();
        await env.DB.batch([
            env.DB.prepare('UPDATE popup_settings SET value = ? WHERE key = ?').bind(String(is_active), 'is_active'),
            env.DB.prepare('UPDATE popup_settings SET value = ? WHERE key = ?').bind(image_url || '', 'image_url'),
            env.DB.prepare('UPDATE popup_settings SET value = ? WHERE key = ?').bind(link_url || '', 'link_url')
        ]);
        return jsonResponse({ message: 'Pengaturan popup disimpan' });
    }

    // PUBLIC: GET SETTING POPUP
    if (path === '/api/public/popup' && method === 'GET') {
        const settings = await env.DB.prepare('SELECT key, value FROM popup_settings').all();
        const result = { is_active: false, image_url: '', link_url: '' };
        settings.results.forEach(row => {
            if (row.key === 'is_active') result.is_active = row.value === 'true';
            else if (row.key === 'image_url') result.image_url = row.value;
            else if (row.key === 'link_url') result.link_url = row.value;
        });
        return jsonResponse(result);
    }

    return jsonResponse({ error: 'Endpoint tidak ditemukan' }, 404);
}
