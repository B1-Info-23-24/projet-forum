package main

import (
    "api/code"
    "database/sql"
    "log"
    "net/http"

    _ "github.com/mattn/go-sqlite3"
    "github.com/rs/cors"
)

var db *sql.DB

func main() {
    db = api.Connect()
    defer db.Close()

    // Configurer CORS
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"http://localhost:8080"}, // Autoriser l'origine spécifique
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
        AllowedHeaders: []string{"Content-Type"},
        Debug:          true,
    })

    // Configurer les routes de l'API
    api.SetupRoutes()

    // Définir le gestionnaire HTTP avec CORS activé
    handler := c.Handler(http.DefaultServeMux)

    log.Println("API démarrée sur le port 8181")
    http.ListenAndServe(":8181", handler)
}
