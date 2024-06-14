package api

import (
    "database/sql"
    "log"
    "time"

    "github.com/dgrijalva/jwt-go"
    _ "github.com/mattn/go-sqlite3"
)

type User struct {
    ID        int       `json:"id"`
    Username  string    `json:"username"`
    Email     string    `json:"email"`
    Password  string    `json:"password"`
    CreatedAt time.Time `json:"created_at"`
}

type Post struct {
    ID        int       `json:"id"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
    UserID    int       `json:"user_id"`
}

type Comment struct {
    ID        int       `json:"id"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
    PostID    int       `json:"post_id"`
    UserID    int       `json:"user_id"`
}

type Like struct {
    ID        int       `json:"id"`
    PostID    int       `json:"post_id"`
    UserID    int       `json:"user_id"`
    CreatedAt time.Time `json:"created_at"`
}

var DB *sql.DB

var jwtKey = []byte("your_secret_key")

type Claims struct {
    Username string `json:"username"`
    UserID   int    `json:"user_id"`
    jwt.StandardClaims
}

func InitDB() {
    var err error
    DB, err = sql.Open("sqlite3", "./data.db")
    if err != nil {
        log.Fatal(err)
    }

    createTables()
}

func createTables() {
    createUserTableQuery := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`

    createPostTableQuery := `
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );`

    createCommentTableQuery := `
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );`

    createLikeTableQuery := `
    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );`

    executeQuery(createUserTableQuery)
    executeQuery(createPostTableQuery)
    executeQuery(createCommentTableQuery)
    executeQuery(createLikeTableQuery)
}

func executeQuery(query string) {
    _, err := DB.Exec(query)
    if err != nil {
        log.Fatal(err)
    }
}

func GenerateJWT(userID int, username string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: username,
        UserID:   userID,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        return "", err
    }

    return tokenString, nil
}

func ValidateJWT(tokenString string) (*Claims, error) {
    claims := &Claims{}

    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
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
