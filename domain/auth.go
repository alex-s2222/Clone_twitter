package domain

import (
	"context"
	"errors"
	"fmt"
	"go_twitter/auth"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct{
	UserRepo auth.UserRepo
}

func NewAuthService(ur auth.UserRepo) *AuthService {
	return  &AuthService{
		UserRepo: ur,
	}
}

func (as *AuthService) Register(ctx context.Context, input auth.RegisterInput) (auth.AuthResponse, error){
	input.Sanitize()

	if err := input.Validate(); err != nil {
		return auth.AuthResponse{}, err 
	}
	
	// check if Username  is already 
	if _, err := as.UserRepo.GetByUsername(ctx, input.Username); !errors.Is(err, auth.ErrNotFound){
		return auth.AuthResponse{}, auth.ErrUsernameTaken
	}

	// check if email already 
	if _, err := as.UserRepo.GetByEmail(ctx, input.Email); !errors.Is(err, auth.ErrNotFound){
		return auth.AuthResponse{}, auth.ErrEmailTaken
	}

	user := auth.User{
		Email: input.Email,
		Username: input.Username,
	}

	// hash password
	hashPassword, err  := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil{
		return auth.AuthResponse{}, fmt.Errorf("error hashing password: %v", err)
	}

	user.Password = string(hashPassword)
	
	// create user 
	user, err = as.UserRepo.Create(ctx, user)
	if err != nil{
		return auth.AuthResponse{}, fmt.Errorf("error creating user: %v", err)
	}

	// return access token and user
	return auth.AuthResponse{
		AccessToken: "a token",
		User: user,
	}, nil
}

func (as *AuthService) Login(ctx context.Context, input auth.LoginInput) (auth.AuthResponse, error){
	input.Sanitize()

	if err := input.Validate(); err != nil{
		return auth.AuthResponse{}, err
	}
	user, err := as.UserRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		switch{
		case errors.Is(err, auth.ErrNotFound):
			return auth.AuthResponse{}, auth.ErrBadCredentials
		default:
			return auth.AuthResponse{}, err
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil{
		return auth.AuthResponse{}, auth.ErrBadCredentials
	}
	
	return auth.AuthResponse{
		AccessToken: "a token",
		User: user,
	}, nil
}