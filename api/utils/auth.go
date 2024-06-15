package utils

import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
    "net/http"
)

var DB *sql.DB

func InitDB() {
    var err error
    DB, err = sql.Open("mysql", "user:password@tcp(localhost:3306)/forum")
    if err != nil {
        panic(err)
    }
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("session_token")
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        var userID int
        err = DB.QueryRow("SELECT user_id FROM sessions WHERE session_token = ?", cookie.Value).Scan(&userID)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Set user ID in context (if needed)
        r.Header.Set("UserID", string(rune(userID)))

        next(w, r)
    }
}
