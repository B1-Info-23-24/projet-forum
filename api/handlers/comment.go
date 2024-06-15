package handlers

import (
	"api/models"
	"api/utils"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func CreateComment(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    var comment models.Comment
    err := json.NewDecoder(r.Body).Decode(&comment)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    userID, _ := strconv.Atoi(r.Header.Get("UserID"))
    comment.UserID = userID

    _, err = utils.DB.Exec("INSERT INTO comments (content, post_id, user_id) VALUES (?, ?, ?)", comment.Content, comment.PostID, comment.UserID)
    if err != nil {
        http.Error(w, "Failed to create comment", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Comment created successfully"))
}

func HandleComments(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/posts/")
    parts := strings.Split(path, "/")

    postIDStr := parts[0]
    commentIDStr := ""
    if len(parts) > 2 && parts[1] == "comments" {
        commentIDStr = parts[2]
    }

    switch r.Method {
    case http.MethodGet:
        GetComments(w, r, postIDStr)
    case http.MethodPut:
        UpdateComment(w, r, commentIDStr)
    case http.MethodDelete:
        DeleteComment(w, r, commentIDStr)
    default:
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
    }
}

func GetComments(w http.ResponseWriter, r *http.Request, postIDStr string) {
    postID, err := strconv.Atoi(postIDStr)
    if err != nil {
        http.Error(w, "Invalid post ID", http.StatusBadRequest)
        return
    }

    rows, err := utils.DB.Query("SELECT id, content, post_id, user_id FROM comments WHERE post_id = ?", postID)
    if err != nil {
        http.Error(w, "Failed to fetch comments", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var comments []models.Comment
    for rows.Next() {
        var comment models.Comment
        err := rows.Scan(&comment.ID, &comment.Content, &comment.PostID, &comment.UserID)
        if err != nil {
            http.Error(w, "Failed to scan comment", http.StatusInternalServerError)
            return
        }
        comments = append(comments, comment)
    }

    json.NewEncoder(w).Encode(comments)
}

func UpdateComment(w http.ResponseWriter, r *http.Request, commentIDStr string) {
    commentID, err := strconv.Atoi(commentIDStr)
    if err != nil {
        http.Error(w, "Invalid comment ID", http.StatusBadRequest)
        return
    }

    var comment models.Comment
    err = json.NewDecoder(r.Body).Decode(&comment)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    _, err = utils.DB.Exec("UPDATE comments SET content = ? WHERE id = ?", comment.Content, commentID)
    if err != nil {
        http.Error(w, "Failed to update comment", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Comment updated successfully"))
}

func DeleteComment(w http.ResponseWriter, r *http.Request, commentIDStr string) {
    commentID, err := strconv.Atoi(commentIDStr)
    if err != nil {
        http.Error(w, "Invalid comment ID", http.StatusBadRequest)
        return
    }

    _, err = utils.DB.Exec("DELETE FROM comments WHERE id = ?", commentID)
    if err != nil {
        http.Error(w, "Failed to delete comment", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Comment deleted successfully"))
}
