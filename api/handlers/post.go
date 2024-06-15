package handlers

import (
    "net/http"
    "strconv"
    "api/models"
    "api/utils"
    "encoding/json"
)

func CreatePost(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    var post models.Post
    err := json.NewDecoder(r.Body).Decode(&post)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    userID, _ := strconv.Atoi(r.Header.Get("UserID"))
    post.UserID = userID

    _, err = utils.DB.Exec("INSERT INTO posts (content, user_id) VALUES (?, ?)", post.Content, post.UserID)
    if err != nil {
        http.Error(w, "Failed to create post", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Post created successfully"))
}

func HandlePost(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        GetPost(w, r)
    case http.MethodPut:
        UpdatePost(w, r)
    case http.MethodDelete:
        DeletePost(w, r)
    default:
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
    }
}

func GetPost(w http.ResponseWriter, r *http.Request) {
    postIDStr := r.URL.Path[len("/posts/"):]
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    var post models.Post
    err = utils.DB.QueryRow("SELECT id, content, user_id FROM posts WHERE id = ?", postID).Scan(&post.ID, &post.Content, &post.UserID)
    if err != nil {
        http.Error(w, "Post not found", http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(post)
}

func UpdatePost(w http.ResponseWriter, r *http.Request) {
    postIDStr := r.URL.Path[len("/posts/"):]
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    var post models.Post
    err = json.NewDecoder(r.Body).Decode(&post)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    _, err = utils.DB.Exec("UPDATE posts SET content = ? WHERE id = ?", post.Content, postID)
    if err != nil {
        http.Error(w, "Failed to update post", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Post updated successfully"))
}

func DeletePost(w http.ResponseWriter, r *http.Request) {
    postIDStr := r.URL.Path[len("/posts/"):]
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    _, err = utils.DB.Exec("DELETE FROM posts WHERE id = ?", postID)
    if err != nil {
        http.Error(w, "Failed to delete post", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Post deleted successfully"))
}

func GetPosts(w http.ResponseWriter, r *http.Request) {
    pageStr := r.URL.Query().Get("page")
    limitStr := r.URL.Query().Get("limit")
    page, err := strconv.Atoi(pageStr)
    if err != nil || page <= 0 {
        page = 1
    }
    limit, err := strconv.Atoi(limitStr)
    if err != nil || limit <= 0 {
        limit = 10
    }
    offset := (page - 1) * limit

    rows, err := utils.DB.Query("SELECT id, content, user_id FROM posts LIMIT ? OFFSET ?", limit, offset)
    if err != nil {
        http.Error(w, "Failed to fetch posts", http.StatusInternalServerError)
        utils.ErrorLogger.Println("Failed to fetch posts:", err)
        return
    }
    defer rows.Close()

    var posts []models.Post
    for rows.Next() {
        var post models.Post
        err := rows.Scan(&post.ID, &post.Content, &post.UserID)
        if err != nil {
            http.Error(w, "Failed to scan post", http.StatusInternalServerError)
            utils.ErrorLogger.Println("Failed to scan post:", err)
            return
        }
        posts = append(posts, post)
    }

    json.NewEncoder(w).Encode(posts)
}
