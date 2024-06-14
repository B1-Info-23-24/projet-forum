package api

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
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

	tokenString, err := GenerateJWT(storedUser.ID, storedUser.Username)
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

	_, err := DB.Exec("INSERT INTO posts (content, created_at, user_id) VALUES (?, ?, ?)", post.Content, post.CreatedAt, post.UserID)
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

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
				c.Abort()
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		tokenStr := cookie.Value
		claims, err := ValidateJWT(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}
		c.Next()
	}
}

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			log.Println("Error:", c.Errors.String())
		}
	}
}

func ValidationHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			log.Println("Error:", c.Errors.String())
		}
	}
}

func GetPost(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	var post Post
	err = DB.QueryRow("SELECT id, content, created_at, user_id FROM posts WHERE id = ?", postID).Scan(&post.ID, &post.Content, &post.CreatedAt, &post.UserID)
	if err != nil {
			if err == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
			} else {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch post"})
			}
			return
	}

	c.JSON(http.StatusOK, post)
}

func UpdatePost(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	var post Post
	if err := c.ShouldBindJSON(&post); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
	}

	userID := c.MustGet("user_id").(int)
	_, err = DB.Exec("UPDATE posts SET content = ?, created_at = ? WHERE id = ? AND user_id = ?", post.Content, time.Now(), postID, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update post"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Post updated successfully"})
}

func DeletePost(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	userID := c.MustGet("user_id").(int)
	_, err = DB.Exec("DELETE FROM posts WHERE id = ? AND user_id = ?", postID, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete post"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Post deleted successfully"})
}

func GetUserProfile(c *gin.Context) {
	userIDStr := c.Param("userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
	}

	var user User
	err = DB.QueryRow("SELECT id, username, email FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
			if err == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			} else {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user profile"})
			}
			return
	}

	c.JSON(http.StatusOK, user)
}

func UpdateUserProfile(c *gin.Context) {
	userIDStr := c.Param("userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
	}

	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
	}

	loggedInUserID := c.MustGet("user_id").(int)
	if loggedInUserID != userID {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "You can only update your own profile"})
			return
	}

	_, err = DB.Exec("UPDATE users SET username = ?, email = ? WHERE id = ?", user.Username, user.Email, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user profile"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User profile updated successfully"})
}

func DeleteUserProfile(c *gin.Context) {
	userIDStr := c.Param("userID")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
	}

	loggedInUserID := c.MustGet("user_id").(int)
	if loggedInUserID != userID {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "You can only delete your own profile"})
			return
	}

	_, err = DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user profile"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User profile deleted successfully"})
}

func CreateComment(c *gin.Context) {
	var comment Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
	}

	userID := c.MustGet("user_id").(int)
	comment.UserID = userID
	comment.CreatedAt = time.Now()

	_, err := DB.Exec("INSERT INTO comments (content, created_at, post_id, user_id) VALUES (?, ?, ?, ?)", comment.Content, comment.CreatedAt, comment.PostID, comment.UserID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create comment"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Comment created successfully"})
}

func GetComments(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	var comments []Comment
	rows, err := DB.Query("SELECT id, content, created_at, post_id, user_id FROM comments WHERE post_id = ?", postID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch comments"})
			return
	}
	defer rows.Close()

	for rows.Next() {
			var comment Comment
			if err := rows.Scan(&comment.ID, &comment.Content, &comment.CreatedAt, &comment.PostID, &comment.UserID); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan comment"})
					return
			}
			comments = append(comments, comment)
	}

	c.JSON(http.StatusOK, comments)
}

func UpdateComment(c *gin.Context) {
	commentIDStr := c.Param("commentID")
	commentID, err := strconv.Atoi(commentIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid comment ID"})
			return
	}

	var comment Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
	}

	userID := c.MustGet("user_id").(int)
	_, err = DB.Exec("UPDATE comments SET content = ?, created_at = ? WHERE id = ? AND user_id = ?", comment.Content, time.Now(), commentID, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update comment"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Comment updated successfully"})
}

func DeleteComment(c *gin.Context) {
	commentIDStr := c.Param("commentID")
	commentID, err := strconv.Atoi(commentIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid comment ID"})
			return
	}

	userID := c.MustGet("user_id").(int)
	_, err = DB.Exec("DELETE FROM comments WHERE id = ? AND user_id = ?", commentID, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete comment"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Comment deleted successfully"})
}

func LikePost(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	userID := c.MustGet("user_id").(int)

	_, err = DB.Exec("INSERT INTO likes (post_id, user_id) VALUES (?, ?)", postID, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to like post"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Post liked successfully"})
}

func UnlikePost(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	userID := c.MustGet("user_id").(int)

	_, err = DB.Exec("DELETE FROM likes WHERE post_id = ? AND user_id = ?", postID, userID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unlike post"})
			return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Post unliked successfully"})
}

func GetLikes(c *gin.Context) {
	postIDStr := c.Param("postID")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
			return
	}

	var likes []Like
	rows, err := DB.Query("SELECT id, post_id, user_id FROM likes WHERE post_id = ?", postID)
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch likes"})
			return
	}
	defer rows.Close()

	for rows.Next() {
			var like Like
			if err := rows.Scan(&like.ID, &like.PostID, &like.UserID); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan like"})
					return
			}
			likes = append(likes, like)
	}

	c.JSON(http.StatusOK, likes)
}

func SearchPosts(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Search query cannot be empty"})
			return
	}

	var posts []Post
	rows, err := DB.Query("SELECT id, content, created_at, user_id FROM posts WHERE content LIKE ? OR user_id IN (SELECT id FROM users WHERE username LIKE ?)", "%"+query+"%", "%"+query+"%")
	if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search posts"})
			return
	}
	defer rows.Close()

	for rows.Next() {
			var post Post
			if err := rows.Scan(&post.ID, &post.Content, &post.CreatedAt, &post.UserID); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan post"})
					return
			}
			posts = append(posts, post)
	}

	c.JSON(http.StatusOK, posts)
}
