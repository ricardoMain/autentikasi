package database

import (
	"database/sql"
	"log"

	_ "github.com/jackc/pgx/v5/stdlib"
	generated "autentikasi/prisma/generated"
)

func Connect(databaseURL string) *generated.Client {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		log.Fatalf("unable to connect to database: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("unable to ping database: %v", err)
	}

	client := generated.NewClient(db, "postgresql")
	log.Println("connected to database")
	return client
}
