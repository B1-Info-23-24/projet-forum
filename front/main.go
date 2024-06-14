package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	// Servir les fichiers statiques (CSS, JS, images)
	router.Static("/static", "./static")

	// Routes pour les fichiers HTML
	router.LoadHTMLGlob("web/*")

	router.GET("/", func(c *gin.Context) {
		// Simuler des données utilisateur pour démonstration
		data := gin.H{
			"Name": "John Doe",
			"ID":   1,
		}
		c.HTML(http.StatusOK, "home-connected.html", data)
	})

	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})

	router.GET("/profile", func(c *gin.Context) {
		c.HTML(http.StatusOK, "profile.html", nil)
	})

	// Lancer le serveur
	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
