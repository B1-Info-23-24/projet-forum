package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Serve static files from the "static" directory
	r.Static("/static", "./static")

	// Load multiple HTML files
	r.LoadHTMLGlob("./web/*")

	// Route to serve the home page
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "home.html", gin.H{})
	})

	// Route to serve the login page
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	// Route to serve the registration page
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{})
	})

	r.Run(":8181")
}
