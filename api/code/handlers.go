package api

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Println("Error binding JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if len(user.Username) < 3 || len(user.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username must be at least 3 characters and password at least 6 characters"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error generating hashed password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = string(hashedPassword)

	_, err = DB.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", user.Username, user.Email, user.Password)
	if err != nil {
		log.Println("Error inserting user into database:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func Login(c *gin.Context) {
	var loginData struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		log.Println("Error binding JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if loginData.Identifier == "" || loginData.Password == "" {
		log.Println("Identifier or password is empty")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identifier and password must not be empty"})
		return
	}

	log.Println("Login attempt with identifier:", loginData.Identifier)

	var storedUser User
	err := DB.QueryRow("SELECT id, username, email, password FROM users WHERE username = ? OR email = ?", loginData.Identifier, loginData.Identifier).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Email, &storedUser.Password)
	if err != nil {
		log.Println("Error fetching user:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	log.Println("User found:", storedUser.Username)

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(loginData.Password))
	if err != nil {
		log.Println("Password comparison failed:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	log.Println("Password comparison successful")

	tokenString, err := GenerateJWT(storedUser.Username)
	if err != nil {
		log.Println("Error generating token:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func Authenticate(c *gin.Context) {
    cookie, err := c.Request.Cookie("token")
    if err != nil {
        if err == http.ErrNoCookie {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
            return
        }
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
        return
    }

    tokenStr := cookie.Value
    claims, err := ValidateJWT(tokenStr)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"username": claims.Username})
}

func CreatePost(c *gin.Context) {
    var post Post
    if err := c.ShouldBindJSON(&post); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    userID := c.MustGet("user_id").(int)
    post.UserID = userID
    post.CreatedAt = time.Now()

    _, err := DB.Exec("INSERT INTO posts (content, created_at, thread_id, user_id) VALUES (?, ?, ?, ?)", post.Content, post.CreatedAt, post.ThreadID, post.UserID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create post"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Post created successfully"})
}

func CreateUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	stmt, err := DB.Prepare("INSERT INTO users(username, email, password) VALUES(?, ?, ?)")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare statement"})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Username, user.Email, user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute statement"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}
