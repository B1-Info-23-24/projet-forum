package main

import (
	"api/code"
	"github.com/gin-gonic/gin"
)

func main() {
	api.InitDB()
	defer api.DB.Close()

	r := gin.Default()

	r.POST("/register", api.CreateUser)
	r.POST("/login", api.Login)

	authenticated := r.Group("/")
	authenticated.Use(api.Authenticate)
	{
		authenticated.POST("/posts", api.CreatePost)
	}

	r.Run(":8080")
}
