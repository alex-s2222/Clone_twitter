package auth

import (
	"context"
	"time"
	"errors"
)

var (
	ErrUsernameTaken = errors.New("username taken")
	ErrEmailTaken = errors.New("email taken")
)

type UserRepo interface {
	Create(ctx context.Context, user User) (User, error)
	GetByUsername(ctx context.Context, Username string) (User, error)
	GetByEmail(ctx context.Context, Email string) (User, error)
}

type User struct {
	ID       string
	Username string
	Email    string
	Password string
	CreateAt time.Time
	UpdateAt time.Time
}
