package api

import "net/http"

func SetupRoutes() {
	http.HandleFunc("/register", serveRegisterForm)
	http.HandleFunc("/users/create", createUser)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/profile", profile)
	http.HandleFunc("/profile/update", updateProfile)
	http.HandleFunc("/profile/delete", deleteUser)
	http.HandleFunc("/home_connected", homeConnected)
	http.HandleFunc("/post/create", createPost)
	http.HandleFunc("/post/update", updatePost)
	http.HandleFunc("/post/delete", deletePost)
	http.HandleFunc("/post/like", likePost)
	http.HandleFunc("/post/comment", commentPost)
	http.HandleFunc("/posts", getPosts)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}
