package models

type Post struct {
    ID      int    `json:"id"`
    Content string `json:"content"`
    UserID  int    `json:"user_id"`
}
