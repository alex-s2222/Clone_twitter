package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterInput_Sanitize(t *testing.T) {
	input := RegisterInput{
		Username:        "   bob ",
		Email:           "BOB@gmail.com",
		Password:        "password",
		ConfirmPassword: "password",
	}

	want := RegisterInput{
		Username:        "bob",
		Email:           "bob@gmail.com",
		Password:        "password",
		ConfirmPassword: "password",
	}

	input.Sanitize()

	require.Equal(t, want, input)
}

func TestRegisterInput_Validate(t *testing.T) {
	testCases := []struct {
		name  string
		input RegisterInput
		err   error
	}{
		{
			name: "valid",
			input: RegisterInput{
				Username:        "bob",
				Email:           "bob@gmail.com",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: nil,
		},
		{
			name: "to short Username ",
			input: RegisterInput{
				Username:        "O",
				Email:           "O@gmail.com",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "email not valid",
			input: RegisterInput{
				Username:        "bob",
				Email:           "bobgmail.com",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "to short password",
			input: RegisterInput{
				Username:        "bob",
				Email:           "bob@gmail.com",
				Password:        "pass",
				ConfirmPassword: "pass",
			},
			err: ErrValidation,
		},
		{
			name: "confirm password does't match a password",
			input: RegisterInput{
				Username:        "bob",
				Email:           "bob@gmail.com",
				Password:        "password",
				ConfirmPassword: "password1",
			},
			err: ErrValidation,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Validate()

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err, tc.err)
			}

		})
	}
}


func TestLoginInput_Sanitize(t *testing.T) {
	input := LoginInput{
		Email:           "   BOB@gmail.com   ",
		Password:        "password",
	}

	want := LoginInput{
		Email:           "bob@gmail.com",
		Password:        "password",
	}

	input.Sanitize()

	require.Equal(t, want, input)
}


func TestLoginInput_Validate(t *testing.T) {
	testCases := []struct {
		name  string
		input LoginInput
		err   error
	}{
		{
			name: "valid",
			input: LoginInput{
				Email:           "bob@gmail.com",
				Password:        "password",
			},
			err: nil,
		},
		{
			name: "not valid emai",
			input: LoginInput{
				Email:           "bobgmail.com",
				Password:        "password",
			},
			err: ErrValidation,
		},
		{
			name: "password required",
			input: LoginInput{
				Email:           "bob@gmail.com",
				Password:        "",
			},
			err: ErrValidation,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Validate()

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err, tc.err)
			}

		})
	}
}