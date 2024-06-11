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

	http.HandleFunc("/profil", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/profile.html")
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/login.html")
	})

	log.Println("Starting frontend server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
