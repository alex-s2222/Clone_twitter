package auth

import "time"


type UserRepo interface{
	
}

type User struct{
	ID string
	Username string
	Email string
	Password string
	CreateAt time.Time
	UpdateAt time.Time
}