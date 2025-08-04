package auth

import "errors"

var (
	ErrBadCredentials = errors.New("email/password wrong combination")
	ErrValidation = errors.New("validation errror")
	ErrNotFound = errors.New("not found")
)