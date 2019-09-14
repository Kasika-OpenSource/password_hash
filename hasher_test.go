package hasher_test

import (
	hasher "github.com/Kasika-OpenSource/password_hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCheck(t *testing.T) {
	t.Run("Check password", func(t *testing.T) {
		result, err := hasher.Check("dnlXnb9np0EytkAzKXLGGRc9QwcZ1urY3rdWSvLCLSo=", "sha512!10000!RkkoQ6ZO2G9l8ezSCLJMPdnX+wYKDowNSwwQ9ckYL6E=", "password")
		if assert.NoError(t, err) {
			assert.Equal(t, true, result)
		}
	})
}

func TestCreate(t *testing.T) {
	t.Run("Create password hash", func(t *testing.T) {
		password := "password"
		_, _, err := hasher.Create(password)
		assert.NoError(t, err)
	})
}

func TestHash(t *testing.T) {
	t.Run("Generate hash", func(t *testing.T) {
		hashed := hasher.Hash("password", "pbe0D/NA5WmsbWPbSQO9GDEwW4cI7fK5TSkWQw2FkK0=", 10000, 32)
		want := "QAyou6NwRRe3cYscIUrzo2XkpX6XSDHY1y2FQlw48DM="
		assert.Equal(t, want, hashed)
	})
}
