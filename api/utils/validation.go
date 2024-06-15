package utils

import "regexp"

func IsValidEmail(email string) bool {
    re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    return re.MatchString(email)
}

func IsValidUsername(username string) bool {
    re := regexp.MustCompile(`^[a-zA-Z0-9_]{3,}$`)
    return re.MatchString(username)
}
