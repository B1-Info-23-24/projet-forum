package api

import (
	"database/sql"
	"log"
)

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
		FOREIGN KEY (user_id) REFERENCES users(id)
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
