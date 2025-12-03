# Authentication Configuration Guide

## Overview
Username dan password untuk SMon (Monitoring System) dapat diubah melalui file `settings.json`.

## Mengubah Username dan Password

### Lokasi Konfigurasi
File: `/home/dionipe/graphts/settings.json`

### Default Credentials
```json
"authentication": {
  "enabled": true,
  "username": "admin",
  "password": "admin123",
  "sessionTimeout": 86400000
}
```

### Langkah-Langkah Mengubah Credentials

#### 1. Edit settings.json
```bash
nano settings.json
```

#### 2. Cari bagian authentication
```json
"authentication": {
  "enabled": true,
  "username": "admin",          // Ubah ini ke username baru
  "password": "admin123",       // Ubah ini ke password baru
  "sessionTimeout": 86400000
}
```

#### 3. Ganti dengan credentials baru
```json
"authentication": {
  "enabled": true,
  "username": "newadmin",       // Username baru
  "password": "newpassword123", // Password baru
  "sessionTimeout": 86400000
}
```

#### 4. Simpan file (Ctrl+O, Enter, Ctrl+X)

#### 5. Restart service
```bash
pm2 restart smon
```

## Konfigurasi Authentication

### Parameters Tersedia

| Parameter | Type | Default | Keterangan |
|-----------|------|---------|-----------|
| `enabled` | Boolean | `true` | Enable/disable authentication |
| `username` | String | `"admin"` | Username untuk login |
| `password` | String | `"admin123"` | Password untuk login |
| `sessionTimeout` | Number | `86400000` | Session timeout dalam milliseconds (86400000 = 24 jam) |

### Session Timeout Examples
- **1 hour**: `3600000`
- **8 hours**: `28800000`
- **12 hours**: `43200000`
- **24 hours**: `86400000` (default)
- **7 days**: `604800000`

## Contoh Konfigurasi Lengkap

### Strong Password
```json
"authentication": {
  "enabled": true,
  "username": "monitoring_admin",
  "password": "SecureP@ssw0rd123!",
  "sessionTimeout": 43200000
}
```

### Short Session (8 hours)
```json
"authentication": {
  "enabled": true,
  "username": "admin",
  "password": "admin@2025",
  "sessionTimeout": 28800000
}
```

### Multiple Users (Future Enhancement)
Saat ini sistem mendukung 1 username/password. Untuk multiple users, bisa dikembangkan di versi future dengan database atau LDAP integration.

## Verification

### Memastikan Perubahan Berhasil

1. **Check logs setelah restart:**
```bash
pm2 logs smon --lines 50
```

Anda akan melihat:
```
[AUTH] User 'newadmin' logged in successfully
```

2. **Test login dengan credentials baru:**
```bash
# Buka browser ke http://localhost:3000/login
# Masukkan username dan password baru
```

3. **Verifikasi file settings.json:**
```bash
cat settings.json | grep -A 5 "authentication"
```

## Security Best Practices

1. **Gunakan password yang kuat:**
   - Minimal 12 karakter
   - Kombinasi huruf besar, kecil, angka, dan simbol
   - Contoh: `SMon@2025Monitoring!`

2. **Ubah password secara berkala:**
   - Minimal setiap 3 bulan
   - Setiap ada perubahan staff

3. **Jangan share credentials:**
   - Gunakan password manager (1Password, LastPass, Bitwarden)
   - Share URL dashboard, bukan credentials

4. **Monitor failed login attempts:**
   - Check logs untuk suspicious activity:
   ```bash
   pm2 logs smon | grep "AUTH"
   ```

5. **Backup settings.json:**
   ```bash
   cp settings.json settings.json.backup
   ```

## Troubleshooting

### 1. Login Gagal Setelah Perubahan
**Masalah:** Credentials baru tidak bekerja

**Solusi:**
- Pastikan format JSON valid (gunakan JSON validator)
- Restart service: `pm2 restart smon`
- Check logs: `pm2 logs smon`
- Verifikasi credentials di settings.json sudah tersimpan

### 2. Syntax Error di settings.json
**Masalah:** Service crash setelah edit

**Solusi:**
```bash
# Validate JSON
node -e "console.log(JSON.parse(require('fs').readFileSync('settings.json')))"

# Jika error, gunakan backup
cp settings.json.backup settings.json
pm2 restart smon
```

### 3. Session Timeout Terlalu Pendek/Panjang
**Masalah:** Terlalu sering logout atau session terlalu lama

**Solusi:**
- Ubah `sessionTimeout` value
- Restart service untuk apply perubahan

## Implementation Details

### Autentikasi Flow
1. User membuka http://localhost:3000/login
2. Masukkan username dan password
3. System membandingkan dengan credentials di `settings.json`
4. Jika cocok → set cookie `authenticated=true`
5. Cookie valid selama `sessionTimeout` milliseconds
6. User dapat mengakses dashboard

### Failed Login Logging
Setiap failed login attempt dicatat di logs:
```
[AUTH] Failed login attempt with username: wronguser
```

### Successful Login Logging
```
[AUTH] User 'admin' logged in successfully
```

## Migration dari Versi Lama

Jika upgrade dari versi tanpa authentication config:

1. Update settings.json dengan menambahkan section authentication
2. Restart service
3. Default credentials akan digunakan: `admin` / `admin123`
4. Ubah sesuai kebutuhan

## API Authentication

**Note:** API endpoints (`/api/*`) tidak memerlukan authentication cookie. Untuk production, perlu ditambahkan API key authentication.

## Future Enhancements

Fitur authentication yang mungkin ditambahkan di versi future:
- [ ] Multiple users dengan roles (admin, viewer, editor)
- [ ] LDAP/Active Directory integration
- [ ] OAuth2/OIDC support
- [ ] API key authentication
- [ ] Two-factor authentication (2FA)
- [ ] Login audit trail dengan timestamp dan IP address
- [ ] Automatic session logout warning

---

**Last Updated:** December 3, 2025
**Version:** 1.0
