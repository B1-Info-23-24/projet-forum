package models

type Session struct {
    ID           int    `json:"id"`
    UserID       int    `json:"user_id"`
    SessionToken string `json:"session_token"`
    CreatedAt    string `json:"created_at"`
}
