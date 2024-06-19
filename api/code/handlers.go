package api

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type Comment struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	UserName  string    `json:"user_name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type UpdatePostRequest struct {
	PostID  string `json:"postID"`
	UserID  string `json:"userID"`
	Content string `json:"content"`
}


type Post struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	UserName  string    `json:"user_name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	Likes     int       `json:"likes"`
	Comments  []Comment `json:"comments"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}

type DeletePostRequest struct {
	PostID string `json:"id"`
	UserID string `json:"user_id"`
}

func getPostById(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID := r.URL.Query().Get("id")
	if postID == "" {
		http.Error(w, "L'ID du post est requis", http.StatusBadRequest)
		return
	}

	var post Post
	err := db.QueryRow("SELECT id, user_id, content, (SELECT name FROM users WHERE id = posts.user_id) AS user_name, (SELECT COUNT(*) FROM likes WHERE post_id = posts.id) AS likes FROM posts WHERE id = ?", postID).Scan(&post.ID, &post.UserID, &post.Content, &post.UserName, &post.Likes)
	if err != nil {
		http.Error(w, "Post non trouvé", http.StatusNotFound)
		return
	}

	// Fetch comments
	rows, err := db.Query("SELECT user_id, content FROM comments WHERE post_id = ?", postID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var comment Comment
		err := rows.Scan(&comment.UserID, &comment.Content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		post.Comments = append(post.Comments, comment)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(post)
}

func serveRegisterForm(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "web/register.html")
		return
	}
	http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, email FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	jsonResponse, err := json.Marshal(users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func updatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
			http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
			return
	}

	var req UpdatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
	}

	log.Printf("Received PostID: %s, UserID: %s, Content: %s", req.PostID, req.UserID, req.Content)

	if req.PostID == "" || req.UserID == "" || req.Content == "" {
			http.Error(w, "L'ID du post, l'ID utilisateur et le contenu sont requis", http.StatusBadRequest)
			return
	}

	stmt, err := db.Prepare("UPDATE posts SET content = ? WHERE id = ? AND user_id = ?")
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}
	defer stmt.Close()

	result, err := stmt.Exec(req.Content, req.PostID, req.UserID)
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}

	if rowsAffected == 0 {
			http.Error(w, "Aucune mise à jour effectuée", http.StatusNotFound)
			return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Modification du post effectuée avec succès"})
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var req DeletePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.PostID == "" || req.UserID == "" {
		http.Error(w, "L'ID du post et l'ID utilisateur sont requis", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("DELETE FROM posts WHERE id = ? AND user_id = ?")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(req.PostID, req.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Suppression du post effectuée avec succès"})
}

// storeSessionToken enregistre le token de session dans la base de données
// func storeSessionToken(userID int, sessionToken string) error {
// 	// Préparer la requête SQL pour insérer le token de session
// 	query := "INSERT INTO sessions (user_id, session_token, created_at) VALUES (?, ?, ?)"

// 	// Obtenir l'heure actuelle pour le champ created_at
// 	currentTime := time.Now()

// 	// Exécuter la requête SQL avec les paramètres user_id, session_token et created_at
// 	_, err := db.Exec(query, userID, sessionToken, currentTime)
// 	if err != nil {
// 		// En cas d'erreur lors de l'exécution de la requête SQL, la journaliser et la retourner
// 		log.Println("Erreur lors de l'insertion du token de session:", err)
// 		return err
// 	}

// 	// Aucune erreur, retourner nil
// 	return nil
// }

// generateSessionToken génère un token de session aléatoire
// func generateSessionToken() string {
// 	// Définir la longueur du token (en bytes)
// 	tokenLength := 32 // Vous pouvez ajuster la longueur du token selon vos besoins

// 	// Créer un buffer pour stocker le token généré
// 	tokenBytes := make([]byte, tokenLength)

// 	// Lire des bytes aléatoires dans le buffer
// 	_, err := rand.Read(tokenBytes)
// 	if err != nil {
// 		// En cas d'erreur, gérer l'erreur (ce cas ne doit pas se produire en général)
// 		panic(err)
// 	}

// 	// Encoder les bytes en une chaîne base64 pour l'utiliser comme token
// 	token := base64.URLEncoding.EncodeToString(tokenBytes)

// 	return token
// }

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		http.Error(w, "L'email et le mot de passe sont requis", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, name, email, password FROM users WHERE email = ?", email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Envoyer une réponse JSON avec l'URL de redirection
	redirectUrl := "/home?id=" + strconv.Itoa(user.ID)
	response := map[string]string{"redirectUrl": redirectUrl}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
// func Login(w http.ResponseWriter, r *http.Request) {
// 	if r.Method == http.MethodOptions {
// 			return
// 	}

// 	emailOrUsername := r.FormValue("emailOrUsername")
// 	password := r.FormValue("password")

// 	if emailOrUsername == "" || password == "" {
// 			http.Error(w, "L'email/nom d'utilisateur et le mot de passe sont requis", http.StatusBadRequest)
// 			return
// 	}

// 	var user User
// 	var err error

// 	// Vérifier si emailOrUsername est un email
// 	if strings.Contains(emailOrUsername, "@") {
// 			err = db.QueryRow("SELECT id, name, email, password FROM users WHERE email = ?", emailOrUsername).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
// 	} else {
// 			// Sinon, considérer emailOrUsername comme un nom d'utilisateur
// 			err = db.QueryRow("SELECT id, name, email, password FROM users WHERE name = ?", emailOrUsername).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
// 	}

// 	if err != nil {
// 			if err == sql.ErrNoRows {
// 					http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
// 			} else {
// 					http.Error(w, err.Error(), http.StatusInternalServerError)
// 			}
// 			return
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
// 	if err != nil {
// 			http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
// 			return
// 	}

// 	// Envoyer une réponse JSON avec l'URL de redirection
// 	redirectUrl := "/home?id=" + strconv.Itoa(user.ID)
// 	response := map[string]string{"redirectUrl": redirectUrl}
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	log.Println("Received values: Name:", name, ", Email:", email)

	if name == "" || email == "" || password == "" {
		log.Println("Missing values: Name:", name, " Email:", email, " Password:", password)
		http.Error(w, "Le nom, l'email et le mot de passe sont requis", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stmt, err := db.Prepare("INSERT INTO users(name, email, password) VALUES(?, ?, ?)")
	if err != nil {
		log.Println("Error preparing statement:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	log.Println("Prepared statement successfully")

	result, err := stmt.Exec(name, email, string(hashedPassword))
	if err != nil {
		log.Println("Error executing statement:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userID, err := result.LastInsertId()
	if err != nil {
		log.Println("Error getting last insert ID:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("User created successfully with ID:", userID)

	response := map[string]interface{}{
		"id": userID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Println("Error encoding JSON response:", err)
	}
}

type Userid struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func GetUserbyid(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Encode user struct into JSON
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func profile(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	tmpl, err := template.ParseFiles("web/profile.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ID string `json:"id"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
		return
	}

	if payload.ID == "" {
		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("DELETE FROM users WHERE id = ?")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(payload.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Réponse de succès (optionnelle)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Utilisateur avec ID %s supprimé"}`, payload.ID)
}

func homeConnected(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	tmpl, err := template.ParseFiles("web/home_connected.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func createPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Décode le corps JSON de la requête
	var postData struct {
		UserID  int    `json:"user_id"`
		Content string `json:"content"`
	}
	fmt.Println("nbvcvb;n:bn;bvc,xnxc,v;b!!hljghghfxgc:!jkj:hjghxcvjhk!hlhjgkhxfhchvjlhkjkhjcxhffxhhk!jkh;c,xcvhjkhj")
	fmt.Println(r.Body)

	UserID := r.FormValue("userid")
	Content := r.FormValue("content")

	fmt.Println(UserID)
	fmt.Println(Content)
	err := json.NewDecoder(r.Body).Decode(&postData)
	if err != nil {
		http.Error(w, "Erreur de décodage JSON", http.StatusBadRequest)
		return
	}
	fmt.Println("nbvcvb;n:bn;bvc,xnxc,v;b!!hljghghfxgc:!jkj:hjghxcvjhk!hlhjgkhxfhchvjlhkjkhjcxhffxhhk!jkh;c,xcvhjkhj")
	fmt.Println(postData.Content)
	fmt.Println(postData.UserID)
	fmt.Println("nbvcvb;n:bn;bvc,xnxc,v;b!!hljghghfxgc:!jkj:hjghxcvjhk!hlhjgkhxfhchvjlhkjkhjcxhffxhhk!jkh;c,xcvhjkhj")

	// Vérifier que les champs requis sont présents et valides
	if postData.UserID == 0 || postData.Content == "" {
		http.Error(w, "L'ID utilisateur et le contenu sont requis", http.StatusBadRequest)
		return
	}

	// Insérez le post dans la base de données
	stmt, err := db.Prepare("INSERT INTO posts(user_id, content) VALUES(?, ?)")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(postData.UserID, postData.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Répondre avec succès
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Post créé avec succès"))
}

func updateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Requête invalide", http.StatusBadRequest)
		return
	}

	if payload.ID == "" || payload.Name == "" || payload.Email == "" {
		http.Error(w, "L'ID, le nom et l'email sont requis", http.StatusBadRequest)
		return
	}

	var stmt *sql.Stmt
	var err error
	if payload.Password != "" {
		hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
		if hashErr != nil {
			http.Error(w, hashErr.Error(), http.StatusInternalServerError)
			return
		}
		stmt, err = db.Prepare("UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = stmt.Exec(payload.Name, payload.Email, string(hashedPassword), payload.ID)
	} else {
		stmt, err = db.Prepare("UPDATE users SET name = ?, email = ? WHERE id = ?")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = stmt.Exec(payload.Name, payload.Email, payload.ID)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Profil mis à jour avec succès"})

}

func getPosts(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Début de la fonction getPosts")

	query := `
		SELECT 
			posts.id, 
			posts.user_id, 
			users.name AS user_name, 
			posts.content, 
			posts.created_at,
			COALESCE(likes.like_count, 0) AS likes,
			(
				SELECT 
					'[' || group_concat(JSON_OBJECT('id', comments.id, 'user_name', users_comments.name, 'content', comments.content)) || ']'
				FROM comments
				LEFT JOIN users AS users_comments ON comments.user_id = users_comments.id
				WHERE comments.post_id = posts.id
			) AS comments
		FROM posts
		JOIN users ON posts.user_id = users.id
		LEFT JOIN (
			SELECT post_id, COUNT(*) AS like_count
			FROM likes
			GROUP BY post_id
		) AS likes ON likes.post_id = posts.id
		ORDER BY posts.created_at DESC
	`

	fmt.Println("Exécution de la requête SQL...")
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors de la requête SQL : %v", err), http.StatusInternalServerError)
		fmt.Printf("Erreur lors de la requête SQL : %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("Récupération des données de la base de données...")
	posts := []Post{}
	for rows.Next() {
		var post Post
		var commentsJSON sql.NullString
		if err := rows.Scan(&post.ID, &post.UserID, &post.UserName, &post.Content, &post.CreatedAt, &post.Likes, &commentsJSON); err != nil {
			http.Error(w, fmt.Sprintf("Erreur lors du scan des lignes : %v", err), http.StatusInternalServerError)
			fmt.Printf("Erreur lors du scan des lignes : %v\n", err)
			return
		}
		// Vérifier si commentsJSON est valide avant de le décoder
		if commentsJSON.Valid {
			if err := json.Unmarshal([]byte(commentsJSON.String), &post.Comments); err != nil {
				http.Error(w, fmt.Sprintf("Erreur lors du décodage JSON : %v", err), http.StatusInternalServerError)
				fmt.Printf("Erreur lors du décodage JSON : %v\n", err)
				return
			}
		} else {
			post.Comments = []Comment{} // Ou nil, selon votre modèle de données
		}
		posts = append(posts, post)
	}

	fmt.Println("Conversion des résultats en JSON...")
	jsonResponse, err := json.Marshal(posts)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur lors du codage JSON : %v", err), http.StatusInternalServerError)
		fmt.Printf("Erreur lors du codage JSON : %v\n", err)
		return
	}

	fmt.Println("Envoi de la réponse JSON...")
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func likePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID := r.FormValue("post_id")
	userID := r.FormValue("user_id")

	stmt, err := db.Prepare("INSERT INTO likes (post_id, user_id) VALUES (?, ?)")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(postID, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func commentPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID := r.FormValue("post_id")
	userID := r.FormValue("user_id")
	content := r.FormValue("content")

	stmt, err := db.Prepare("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(postID, userID, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func getUserPosts(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("userId")
	if userId == "" {
		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
		return
	}

	log.Println("Fetching posts for user...")

	// Charger les posts de l'utilisateur
	rows, err := db.Query("SELECT id, user_id, content, created_at FROM posts WHERE user_id = ?", userId)
	if err != nil {
		fmt.Println("Error querying posts:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.UserID, &post.Content, &post.CreatedAt); err != nil {
			fmt.Println("Error scanning post row:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Charger le nom d'utilisateur à partir de la table users
		user, err := getUserByID(post.UserID)
		if err != nil {
			fmt.Println("Error fetching user details:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		post.UserName = user.Name // Supposons que `user` contient les détails de l'utilisateur chargés depuis la base de données.

		// Charger les commentaires associés au post (comme vous l'avez déjà fait)
		comments, err := getCommentsByPostID(post.ID)
		if err != nil {
			fmt.Println("Error fetching comments:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		post.Comments = comments

		posts = append(posts, post)
	}

	// Renvoyer les posts en JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(posts); err != nil {
		fmt.Println("Error encoding JSON response:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Fonction pour charger les détails d'un utilisateur par son ID
func getUserByID(userID int) (User, error) {
	var user User
	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// Fonction pour charger les commentaires associés à un post par son ID
func getCommentsByPostID(postID int) ([]Comment, error) {
	rows, err := db.Query("SELECT id, user_id, content, created_at FROM comments WHERE post_id = ?", postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.ID, &comment.UserID, &comment.Content, &comment.CreatedAt); err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}
	return comments, nil

}
