package handlers

import (
    "crypto/rand"
    "encoding/base64"
    "net/http"
    "time"
    "api/models"
    "api/utils"
    "encoding/json"
    "golang.org/x/crypto/bcrypt"
)

func generateSessionToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func setSessionCookie(w http.ResponseWriter, sessionToken string) {
    http.SetCookie(w, &http.Cookie{
        Name:     "session_token",
        Value:    sessionToken,
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        Secure:   true,
    })
}

func Register(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        utils.ErrorLogger.Println("Invalid request method for /register")
        return
    }

    var user models.User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        utils.ErrorLogger.Println("Invalid input for /register:", err)
        return
    }

    if !utils.IsValidEmail(user.Email) || !utils.IsValidUsername(user.Username) {
        http.Error(w, "Invalid email or username", http.StatusBadRequest)
        utils.ErrorLogger.Println("Invalid email or username for /register")
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Failed to hash password", http.StatusInternalServerError)
        utils.ErrorLogger.Println("Failed to hash password:", err)
        return
    }

    user.Password = string(hashedPassword)
    _, err = utils.DB.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", user.Username, user.Email, user.Password)
    if err != nil {
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        utils.ErrorLogger.Println("Failed to register user:", err)
        return
    }

    utils.InfoLogger.Println("User registered:", user.Username)
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Registration successful"))
}


func Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        utils.ErrorLogger.Println("Invalid request method for /login")
        return
    }

    var loginData struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    err := json.NewDecoder(r.Body).Decode(&loginData)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        utils.ErrorLogger.Println("Invalid input for /login:", err)
        return
    }

    var user models.User
    err = utils.DB.QueryRow("SELECT id, username, email, password FROM users WHERE email = ?", loginData.Email).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        utils.ErrorLogger.Println("Invalid credentials for /login:", err)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        utils.ErrorLogger.Println("Invalid credentials for /login:", err)
        return
    }

    sessionToken := generateSessionToken()
    _, err = utils.DB.Exec("INSERT INTO sessions (user_id, session_token, created_at) VALUES (?, ?, ?)", user.ID, sessionToken, time.Now())
    if err != nil {
        http.Error(w, "Failed to create session", http.StatusInternalServerError)
        utils.ErrorLogger.Println("Failed to create session:", err)
        return
    }

    setSessionCookie(w, sessionToken)
    utils.InfoLogger.Println("User logged in:", user.Username)
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Login successful"))
}