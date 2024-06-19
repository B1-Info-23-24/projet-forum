package api

import "net/http"

func SetupRoutes() {
	http.HandleFunc("/register", serveRegisterForm)
	http.HandleFunc("/users/create", createUser)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/profile", profile)
	http.HandleFunc("/getuserbyid", GetUserbyid)
	http.HandleFunc("/profile/update", updateProfile)
	http.HandleFunc("/profile/delete", deleteUser)
	http.HandleFunc("/home", homeConnected)
	http.HandleFunc("/post/create", createPost)
	http.HandleFunc("/post/update", updatePost)
	http.HandleFunc("/post/delete", deletePost)
	http.HandleFunc("/post/like", likePost)
	http.HandleFunc("/post/comment", commentPost)
	http.HandleFunc("/posts", getPosts)
	http.HandleFunc("/user/posts", getUserPosts)
	http.HandleFunc("/getpostbyid", getPostById)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}
