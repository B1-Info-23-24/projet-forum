package main

import (
	"log"
	"net/http"
)

func main() {
	fsStatic := http.FileServer(http.Dir("static/"))
	http.Handle("/static/", http.StripPrefix("/static", fsStatic))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/home.html")
	})

	http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/profile.html")
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, "web/login.html")
			return
		} else if r.Method == http.MethodPost {
			// Redirection vers l'API pour gérer la connexion
			redirectToAPI(w, r, "/api/login")
			return
		}
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, "web/register.html")
			return
		} else if r.Method == http.MethodPost {
			// Redirection vers l'API pour gérer l'inscription
			redirectToAPI(w, r, "/api/register")
			return
		}
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
	})

	// Démarrage du serveur frontend
	log.Println("Serveur front-end démarré sur le port :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func redirectToAPI(w http.ResponseWriter, r *http.Request, apiEndpoint string) {
	targetURL := "http://localhost:8181" + apiEndpoint
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}
