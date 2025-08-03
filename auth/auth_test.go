package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)


func TestRegisterInput_Sanitize(t *testing.T){
	input := RegisterInput{
		UserName: "   bob ",
		Email: "BOB@gmail.com", 
		Password: "password", 
		ConfirmPassword: "password",
	}

	want := RegisterInput{
		UserName: "bob",
		Email: "bob@gmail.com", 
		Password: "password", 
		ConfirmPassword: "password",
	}

	input.Sanitize()

	require.Equal(t, want, input)
}

func TestRegisterInput_Validate(t *testing.T){
	testCases := []struct{
		name string
		input RegisterInput
		err error
	}{
		{
			name: "valid",
			input: RegisterInput{
				UserName: "bob",
				Email: "bob@gmail.com",
				Password: "password",
				ConfirmPassword: "password",
			},
			err: nil,
		},
		{
			name: "to short username",
			input: RegisterInput{
				UserName: "O",
				Email: "O@gmail.com",
				Password: "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "to short password",
			input: RegisterInput{
				UserName: "bob",
				Email: "bob@gmail.com",
				Password: "pass",
				ConfirmPassword: "pass",
			},
			err: ErrValidation, 
		},
		{
			name: "confirm password does't match a password",
			input: RegisterInput{
				UserName: "bob",
				Email: "bob@gmail.com",
				Password: "password",
				ConfirmPassword: "password1",
			},
			err: ErrValidation,
		},
	}


	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T){
			err := tc.input.Validate()
			
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err, tc.err)
			}

		})
	}
}