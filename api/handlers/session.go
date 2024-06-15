package handlers

import (
	"api/models"
	"api/utils"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func HandleUserProfile(w http.ResponseWriter, r *http.Request) {
    userIDStr := strings.TrimPrefix(r.URL.Path, "/users/")
    switch r.Method {
    case http.MethodGet:
        GetUserProfile(w, r, userIDStr)
    case http.MethodPut:
        UpdateUserProfile(w, r, userIDStr)
    case http.MethodDelete:
        DeleteUserProfile(w, r, userIDStr)
    default:
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
    }
}

func GetUserProfile(w http.ResponseWriter, r *http.Request, userIDStr string) {
    userID, err := strconv.Atoi(userIDStr)
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }

    var user models.User
    err = utils.DB.QueryRow("SELECT id, username, email FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Email)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(user)
}

func UpdateUserProfile(w http.ResponseWriter, r *http.Request, userIDStr string) {
    userID, err := strconv.Atoi(userIDStr)
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }

    var user models.User
    err = json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    _, err = utils.DB.Exec("UPDATE users SET username = ?, email = ? WHERE id = ?", user.Username, user.Email, userID)
    if err != nil {
        http.Error(w, "Failed to update user profile", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("User profile updated successfully"))
}

func DeleteUserProfile(w http.ResponseWriter, r *http.Request, userIDStr string) {
    userID, err := strconv.Atoi(userIDStr)
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }

    _, err = utils.DB.Exec("DELETE FROM users WHERE id = ?", userID)
    if err != nil {
        http.Error(w, "Failed to delete user profile", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("User profile deleted successfully"))
}
