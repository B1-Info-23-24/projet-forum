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
		} else if r.Method != http.MethodPost {
			http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
			return
		}
	})

	http.HandleFunc("/home_connected", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/home_connected.html")

	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/register.html")
	})

	log.Println("Starting frontend server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
