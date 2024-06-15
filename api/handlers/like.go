package handlers

import (
	"api/models"
	"api/utils"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func HandleLikes(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/posts/")
    parts := strings.Split(path, "/")

    postIDStr := parts[0]
    action := ""
    if len(parts) > 2 && parts[1] == "likes" {
        action = parts[2]
    }

    switch r.Method {
    case http.MethodPost:
        if action == "like" {
            LikePost(w, r, postIDStr)
        } else if action == "unlike" {
            UnlikePost(w, r, postIDStr)
        } else {
            http.Error(w, "Invalid action", http.StatusBadRequest)
        }
    case http.MethodGet:
        GetLikes(w, r, postIDStr)
    default:
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
    }
}

func LikePost(w http.ResponseWriter, r *http.Request, postIDStr string) {
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    userID, _ := strconv.Atoi(r.Header.Get("UserID"))

    _, err = utils.DB.Exec("INSERT INTO likes (post_id, user_id) VALUES (?, ?)", postID, userID)
    if err != nil {
        http.Error(w, "Failed to like post", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Post liked successfully"))
}

func UnlikePost(w http.ResponseWriter, r *http.Request, postIDStr string) {
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    userID, _ := strconv.Atoi(r.Header.Get("UserID"))

    _, err = utils.DB.Exec("DELETE FROM likes WHERE post_id = ? AND user_id = ?", postID, userID)
    if err != nil {
        http.Error(w, "Failed to unlike post", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Post unliked successfully"))
}

func GetLikes(w http.ResponseWriter, r *http.Request, postIDStr string) {
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    rows, err := utils.DB.Query("SELECT id, post_id, user_id FROM likes WHERE post_id = ?", postID)
    if err != nil {
        http.Error(w, "Failed to fetch likes", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var likes []models.Like
    for rows.Next() {
        var like models.Like
        err := rows.Scan(&like.ID, &like.PostID, &like.UserID)
        if err != nil {
            http.Error(w, "Failed to scan like", http.StatusInternalServerError)
            return
        }
        likes = append(likes, like)
    }

    json.NewEncoder(w).Encode(likes)
}
