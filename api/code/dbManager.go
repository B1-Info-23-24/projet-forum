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

	// Exécuter les migrations au démarrage
	RunMigrations(db)

	return db
}

// RunMigrations exécute les migrations pour créer les tables nécessaires
func RunMigrations(db *sql.DB) {
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`

	createPostsTable := `
	CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		likes INTEGER DEFAULT 0
	);
	`
	createLikesTable := `
	CREATE TABLE IF NOT EXISTS likes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		post_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		FOREIGN KEY (post_id) REFERENCES posts(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	`

	createCommentsTable := `
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		post_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (post_id) REFERENCES posts(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	`

	// Exécute les requêtes de création de tables
	_, err := db.Exec(createUsersTable)
	if err != nil {
		log.Fatalf("Erreur lors de la création de la table users: %v", err)
	}

	_, err = db.Exec(createPostsTable)
	if err != nil {
		log.Fatalf("Erreur lors de la création de la table posts: %v", err)
	}

	_, err = db.Exec(createLikesTable)
	if err != nil {
		log.Fatalf("Erreur lors de la création de la table likes: %v", err)
	}

	_, err = db.Exec(createCommentsTable)
	if err != nil {
		log.Fatalf("Erreur lors de la création de la table comments: %v", err)
	}

	log.Println("Migrations exécutées avec succès")
}
