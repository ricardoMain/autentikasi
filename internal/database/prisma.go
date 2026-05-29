package database

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	generated "autentikasi/prisma/generated"
)

type DB struct {
	Client *generated.Client
	SQL    *sql.DB
}

func Connect(databaseURL string) *DB {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		slog.Error("unable to connect to database", "error", err)
		panic(err)
	}

	if err := db.Ping(); err != nil {
		slog.Error("unable to ping database", "error", err)
		panic(err)
	}

	client := generated.NewClient(db, "postgresql")
	slog.Info("connected to database")
	return &DB{Client: client, SQL: db}
}

func CleanupExpiredTokens(ctx context.Context, sqlDB *sql.DB) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Hour):
			result, err := sqlDB.ExecContext(ctx, `DELETE FROM "RefreshToken" WHERE "expiresAt" < NOW()`)
			if err != nil {
				slog.Error("failed to cleanup expired tokens", "error", err)
				continue
			}
			if n, _ := result.RowsAffected(); n > 0 {
				slog.Info("cleaned up expired tokens", "count", n)
			}
		}
	}
}
