package api

import (
    "database/sql"
    "log"
    "time"

    "github.com/dgrijalva/jwt-go"
    _ "github.com/mattn/go-sqlite3"
)

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type Thread struct {
    ID        int       `json:"id"`
    Title     string    `json:"title"`
    CreatedAt time.Time `json:"created_at"`
    UserID    int       `json:"user_id"`
}

type Post struct {
    ID        int       `json:"id"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
    ThreadID  int       `json:"thread_id"`
    UserID    int       `json:"user_id"`
}

var DB *sql.DB
var jwtKey = []byte("your_secret_key")

type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

func InitDB() {
    var err error
    DB, err = sql.Open("sqlite3", "./data.db")
    if err != nil {
        log.Fatal(err)
    }

    createUserTableQuery := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    );`

    _, err = DB.Exec(createUserTableQuery)
    if err != nil {
        log.Fatal(err)
    }
}


func GenerateJWT(username string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtKey)
}

func ValidateJWT(tokenStr string) (*Claims, error) {
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil {
        return nil, err
    }
    if !token.Valid {
        return nil, err
    }
    return claims, nil
}
