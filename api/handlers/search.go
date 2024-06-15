package handlers

import (
    "net/http"
    "api/models"
    "api/utils"
    "encoding/json"
)

func SearchPosts(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    if query == "" {
        http.Error(w, "Search query cannot be empty", http.StatusBadRequest)
        return
    }

    rows, err := utils.DB.Query("SELECT id, content, user_id FROM posts WHERE content LIKE ? OR user_id IN (SELECT id FROM users WHERE username LIKE ?)", "%"+query+"%", "%"+query+"%")
    if err != nil {
        http.Error(w, "Failed to search posts", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var posts []models.Post
    for rows.Next() {
        var post models.Post
        err := rows.Scan(&post.ID, &post.Content, &post.UserID)
        if err != nil {
            http.Error(w, "Failed to scan post", http.StatusInternalServerError)
            return
        }
        posts = append(posts, post)
    }

    json.NewEncoder(w).Encode(posts)
}
