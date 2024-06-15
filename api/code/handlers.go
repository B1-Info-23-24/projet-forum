package api

import (
	"database/sql"
	"fmt"
	"strconv"

	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

//var db *sql.DB // Assurez-vous que la variable db est initialisée ailleurs dans votre application

type Post struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	UserName  string `json:"user_name"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
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

// func Login(w http.ResponseWriter, r *http.Request) {
// 	if r.Method == http.MethodGet {
// 		http.ServeFile(w, r, "web/login.html")
// 		return
// 	} else if r.Method != http.MethodPost {
// 		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	email := r.FormValue("email")
// 	password := r.FormValue("password")

// 	if email == "" || password == "" {
// 		http.Error(w, "L'email et le mot de passe sont requis", http.StatusBadRequest)
// 		return
// 	}

// 	var user User
// 	err := db.QueryRow("SELECT id, name, email, password FROM users WHERE email = ?", email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			http.Error(w, "Utilisateur non trouvé", http.StatusUnauthorized)
// 		} else {
// 			http.Error(w, err.Error(), http.StatusInternalServerError)
// 		}
// 		return
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
// 	if err != nil {
// 		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
// 		return
// 	}

// 	// Générer un token de session aléatoire
// 	sessionToken := generateSessionToken()

// 	// Stocker le token de session dans la base de données (ou un autre magasin sécurisé)
// 	err = storeSessionToken(user.ID, sessionToken)
// 	if err != nil {
// 		log.Println("erreur de stockage")
// 		http.Error(w, "Erreur lors du stockage de la session", http.StatusInternalServerError)
// 		return
// 	}

// 	// Créer un cookie de session
// 	cookie := http.Cookie{
// 		Name:     "session_token",
// 		Value:    sessionToken,
// 		Expires:  time.Now().Add(24 * time.Hour), // Expire dans 24 heures
// 		HttpOnly: true,
// 		SameSite: http.SameSiteStrictMode,
// 		Path:     "/",
// 	}

// 	// Définir le cookie dans la réponse
// 	http.SetCookie(w, &cookie)

// 	// Répondre avec les informations de l'utilisateur en JSON (ou rediriger si nécessaire)
// 	userInfo := map[string]interface{}{
// 		"id":    user.ID,
// 		"name":  user.Name,
// 		"email": user.Email,
// 	}

// 	userJSON, err := json.Marshal(userInfo)
// 	if err != nil {
// 		http.Error(w, "Erreur lors de la sérialisation des données utilisateur", http.StatusInternalServerError)
// 		return
// 	}

// 	// Si vous souhaitez rediriger après la connexion, utilisez http.Redirect ici
// 	// Par exemple:
// 	http.Redirect(w, r, "/profile", http.StatusSeeOther)

// 	// Sinon, si vous souhaitez répondre avec les informations JSON, utilisez ceci :
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	w.Write(userJSON)
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
	redirectUrl := "/home_connected?id=" + strconv.Itoa(user.ID)
	response := map[string]string{"redirectUrl": redirectUrl}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

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

// func GetUserbyid(w http.ResponseWriter, r *http.Request) {
// 	id := r.URL.Query().Get("id")
// 	if id == "" {
// 		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
// 		return
// 	}

// 	var user User
// 	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
// 		} else {
// 			http.Error(w, err.Error(), http.StatusInternalServerError)
// 		}
// 		return
// 	}

// 	// Envoyer une réponse JSON avec l'URL de redirection
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode()

// 	tmpl, err := template.ParseFiles("web/profile.html")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	err = tmpl.Execute(w, user)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

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

func updateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	id := r.FormValue("id")
	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if id == "" || name == "" || email == "" {
		http.Error(w, "L'ID, le nom et l'email sont requis", http.StatusBadRequest)
		return
	}

	var stmt *sql.Stmt
	var err error
	if password != "" {
		hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if hashErr != nil {
			http.Error(w, hashErr.Error(), http.StatusInternalServerError)
			return
		}
		stmt, err = db.Prepare("UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = stmt.Exec(name, email, string(hashedPassword), id)
	} else {
		stmt, err = db.Prepare("UPDATE users SET name = ?, email = ? WHERE id = ?")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = stmt.Exec(name, email, id)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/home_connected?id="+id, http.StatusSeeOther)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "ID utilisateur requis", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("DELETE FROM users WHERE id = ?")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

// func createPost(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	userID := r.FormValue("userid")
// 	content := r.FormValue("content")

// 	if userID == "" || content == "" {
// 		http.Error(w, "L'ID utilisateur et le contenu sont requis", http.StatusBadRequest)
// 		return
// 	}

// 	stmt, err := db.Prepare("INSERT INTO posts(user_id, content) VALUES(?, ?)")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer stmt.Close()

// 	_, err = stmt.Exec(userID, content)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	http.Redirect(w, r, "/home_connected?id="+userID, http.StatusSeeOther)
// }

// Handler pour la création de post
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

func updatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID := r.FormValue("post_id")
	userID := r.FormValue("user_id")
	content := r.FormValue("content")

	if postID == "" || userID == "" || content == "" {
		http.Error(w, "L'ID du post, l'ID utilisateur et le contenu sont requis", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("UPDATE posts SET content = ? WHERE id = ? AND user_id = ?")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(content, postID, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/home_connected?id="+userID, http.StatusSeeOther)
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID := r.FormValue("post_id")
	userID := r.FormValue("user_id")

	if postID == "" || userID == "" {
		http.Error(w, "L'ID du post et l'ID utilisateur sont requis", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("DELETE FROM posts WHERE id = ? AND user_id = ?")
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

	http.Redirect(w, r, "/home_connected?id="+userID, http.StatusSeeOther)
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
			SELECT posts.id, posts.user_id, users.name, posts.content, posts.created_at
			FROM posts
			JOIN users ON posts.user_id = users.id
			ORDER BY posts.created_at DESC
		`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts := []Post{}
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.UserID, &post.UserName, &post.Content, &post.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	jsonResponse, err := json.Marshal(posts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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
