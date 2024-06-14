package main

import (
	api "api/code"

	"github.com/gin-gonic/gin"
)

func main() {
	api.InitDB()
	defer api.DB.Close()

	r := gin.Default()

	// User routes
	r.POST("/register", api.Register)
	r.POST("/login", api.Login)

	// Protected routes
	authenticated := r.Group("/")
	authenticated.Use(api.Authenticate)
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
