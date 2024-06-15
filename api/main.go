package main

import (
	"api/handlers"
	"api/utils"
	"log"
	"net/http"
)

func main() {
	utils.InitLog()
	utils.InitDB()
	defer utils.DB.Close()

	http.HandleFunc("/register", handlers.Register)
	http.HandleFunc("/login", handlers.Login)

	// Protected routes
	http.HandleFunc("/posts", utils.AuthMiddleware(handlers.CreatePost))               // POST /posts
	http.HandleFunc("/posts/", utils.AuthMiddleware(handlers.HandlePost))              // GET, PUT, DELETE /posts/:postID
	http.HandleFunc("/comments", utils.AuthMiddleware(handlers.CreateComment))         // POST /comments
	http.HandleFunc("/posts/comments/", utils.AuthMiddleware(handlers.HandleComments)) // GET, PUT, DELETE /posts/:postID/comments/:commentID
	http.HandleFunc("/posts/likes/", utils.AuthMiddleware(handlers.HandleLikes))       // POST /posts/:postID/like, DELETE /posts/:postID/unlike, GET /posts/:postID/likes
	http.HandleFunc("/users/", utils.AuthMiddleware(handlers.HandleUserProfile))       // GET, PUT, DELETE /users/:userID

	http.HandleFunc("/search", handlers.SearchPosts) // GET /search

	utils.InfoLogger.Println("Starting server on :8181")
	log.Println("server sur 8181")
	http.ListenAndServe(":8181", nil)
}
