package main

import (
	"api/code"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	api.InitDB()
	defer api.DB.Close()

	r := gin.Default()

	r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"http://http://localhost:8080/"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
    AllowCredentials: true,
    MaxAge:           12 * time.Hour,
}))


	// Configurer CORS pour autoriser toutes les origines (à ajuster en fonction de vos besoins)
	// r.Use(cors.Default())

	// User routes
	r.POST("/register", api.Register)
	r.POST("/login", api.Login)

	// Protected routes
	authenticated := r.Group("/")
	authenticated.Use(api.AuthMiddleware()) // Middleware d'authentification

	{
		// Post routes
		authenticated.POST("/posts", api.CreatePost)
		authenticated.GET("/posts/:postID", api.GetPost)
		authenticated.PUT("/posts/:postID", api.UpdatePost)
		authenticated.DELETE("/posts/:postID", api.DeletePost)

		// Comment routes
		authenticated.POST("/comments", api.CreateComment)
		authenticated.GET("/posts/:postID/comments", api.GetComments)
		authenticated.PUT("/comments/:commentID", api.UpdateComment)
		authenticated.DELETE("/comments/:commentID", api.DeleteComment)

		// Like routes
		authenticated.POST("/posts/:postID/like", api.LikePost)
		authenticated.POST("/posts/:postID/unlike", api.UnlikePost)
		authenticated.GET("/posts/:postID/likes", api.GetLikes)

		// User profile routes
		authenticated.GET("/users/:userID", api.GetUserProfile)
		authenticated.PUT("/users/:userID", api.UpdateUserProfile)
		authenticated.DELETE("/users/:userID", api.DeleteUserProfile)
	}

	// Public search route
	r.GET("/search", api.SearchPosts)

	r.Run(":8181")
}
