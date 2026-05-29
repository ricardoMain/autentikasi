# Autentikasi

Backend REST API autentikasi multi-provider (email, Google, GitHub) menggunakan **Go + Gin + Prisma + PostgreSQL**.

## Fitur

- Register & login dengan email/password
- Login dengan Google OAuth
- Login dengan GitHub OAuth
- JWT access token + refresh token (rotasi & revoke)
- Role-based access (user / admin)
- Middleware autentikasi & RBAC
- Rate limiting pada endpoint login/register
- Graceful shutdown
- Repository & Service interfaces (testable)
- Input validation dengan Gin validator

## Tech Stack

- [Go](https://go.dev/)
- [Gin](https://github.com/gin-gonic/gin) — HTTP framework
- [Prisma Go](https://github.com/satishbabariya/prisma-go) — ORM
- [PostgreSQL](https://www.postgresql.org/) — database
- [Docker Compose](https://docs.docker.com/compose/) — container PostgreSQL

## Cara Pakai

### 1. Clone & setup

```bash
git clone <repo-url>
cd autentikasi
cp .env.example .env
# edit .env sesuai kebutuhan (JWT_SECRET, dll)
```

### 2. Jalankan database

```bash
docker compose up -d
docker compose exec -T postgres psql -U postgres -d autentikasi < internal/database/init.sql
```

### 3. Jalankan server

```bash
go run cmd/server/main.go
```

Server akan berjalan di `http://localhost:8080`.

### 4. Testing

```bash
./test.sh
```

Atau buka `api-test.http` di VS Code (extension REST Client).

## API Endpoints

| Method | Endpoint | Auth | Deskripsi |
|--------|----------|------|-----------|
| POST | `/api/auth/register` | - | Registrasi user baru |
| POST | `/api/auth/login` | - | Login email/password |
| POST | `/api/auth/refresh` | - | Refresh access token |
| POST | `/api/auth/logout` | - | Logout (hapus refresh token) |
| GET | `/api/auth/me` | Bearer | Profile user |
| GET | `/api/auth/google/login` | - | Redirect ke Google OAuth |
| GET | `/api/auth/google/callback` | - | Callback Google OAuth |
| GET | `/api/auth/github/login` | - | Redirect ke GitHub OAuth |
| GET | `/api/auth/github/callback` | - | Callback GitHub OAuth |
| GET | `/api/admin/dashboard` | Bearer + Admin | Dashboard admin |

## Environment Variables

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `SERVER_PORT` | `8080` | Port server |
| `DATABASE_URL` | **wajib** | Koneksi PostgreSQL |
| `JWT_SECRET` | **wajib** | Secret key JWT (server akan panic jika kosong) |
| `APP_ENV` | `development` | Set ke `production` untuk secure cookie |
| `GOOGLE_CLIENT_ID` | - | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | - | Google OAuth Client Secret |
| `GITHUB_CLIENT_ID` | - | GitHub OAuth Client ID |
| `GITHUB_CLIENT_SECRET` | - | GitHub OAuth Client Secret |
| `FRONTEND_URL` | `http://localhost:3000` | URL frontend |

## Lisensi

MIT
