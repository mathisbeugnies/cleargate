package main

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "postgres://user:password@localhost:5432/cleargate?sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	log.Println("Clearing request_logs table...")
	_, err = db.Exec("TRUNCATE TABLE request_logs")
	if err != nil {
		log.Fatal("Failed to truncate:", err)
	}
	log.Println("Logs cleared successfully. Hash chain reset.")
}
