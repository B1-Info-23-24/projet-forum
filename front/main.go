package main

import (
    "log"
    "net/http"
    "io/ioutil"
    "path/filepath"
)

// Serve the home page
func homeHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("Serving home.html")
    http.ServeFile(w, r, "web/home.html")
}

// Serve the login page
func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        log.Println("Serving login.html")
        http.ServeFile(w, r, "web/login.html")
    } else if r.Method != http.MethodPost {
        log.Println("Method not allowed for login")
        http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
    } else {
        log.Println("Handling POST request for login")
        // Handle login logic here for POST request
        // For example, you can forward the request to the API
        apiURL := "http://localhost:8181/login"
        req, err := http.NewRequest(r.Method, apiURL, r.Body)
        if err != nil {
            log.Printf("Error creating request: %v", err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        req.Header = r.Header

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Error making request to API: %v", err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Printf("Error reading response body: %v", err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        for k, v := range resp.Header {
            for _, vv := range v {
                w.Header().Add(k, vv)
            }
        }
        w.WriteHeader(resp.StatusCode)
        w.Write(body)
    }
}

// Serve the register page
func registerHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("Serving register.html")
    http.ServeFile(w, r, "web/register.html")
}

// Serve static files (CSS, JS, images)
func staticFileHandler(w http.ResponseWriter, r *http.Request) {
    var staticPath = "static"
    path := r.URL.Path[len("/static/"):]
    file := filepath.Join(staticPath, path)
    log.Printf("Serving static file: %s", file)
    http.ServeFile(w, r, file)
}

// Proxy requests to the API
func apiProxyHandler(w http.ResponseWriter, r *http.Request) {
    apiURL := "http://localhost:8181" + r.URL.Path
    req, err := http.NewRequest(r.Method, apiURL, r.Body)
    if err != nil {
        log.Printf("Error creating request: %v", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    req.Header = r.Header

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error making request to API: %v", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response body: %v", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    for k, v := range resp.Header {
        for _, vv := range v {
            w.Header().Add(k, vv)
        }
    }
    w.WriteHeader(resp.StatusCode)
    w.Write(body)
}

func main() {
    // Serve the HTML pages
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/register", registerHandler)

    // Serve static files
    fsStatic := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static", fsStatic))

    // Proxy API requests
    http.HandleFunc("/api/", apiProxyHandler)

    // Start the server
    log.Println("Starting frontend server on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}
