package api

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// Connect initialise la connexion à la base de données SQLite
func Connect() *sql.DB {
	var err error
	db, err = sql.Open("sqlite3", "./base.db")
	if err != nil {
		log.Println("nil sql")
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Default().Println("erreur ping db")
		log.Fatal(err)
	}

	// Créer la table des utilisateurs
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Créer la table des publications
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			content TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Créer la table des sessions
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			session_token TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

