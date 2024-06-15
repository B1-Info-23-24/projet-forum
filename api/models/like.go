package models

type Like struct {
    ID     int `json:"id"`
    PostID int `json:"post_id"`
    UserID int `json:"user_id"`
}
