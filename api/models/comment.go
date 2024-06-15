package models

type Comment struct {
    ID      int    `json:"id"`
    Content string `json:"content"`
    PostID  int    `json:"post_id"`
    UserID  int    `json:"user_id"`
}
