package hasher

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"regexp"
	"strconv"
	"strings"
)

var pbkdf2Iterations int = 10000
var hashSize int = 32
var digestAlgorithm string = "sha512"

func Create(password string) (string, string, error) {
	var hashed string
	var saltWithMetadata string
	var err error

	salt, err := generateRandomString(32)
	if err != nil {
		return hashed, saltWithMetadata, err
	}

	hashed = Hash(password, salt, pbkdf2Iterations, hashSize)
	metadata := []string{digestAlgorithm, strconv.Itoa(pbkdf2Iterations), salt}
	saltWithMetadata = strings.Join(metadata, "!")

	return hashed, saltWithMetadata, nil
}

func Check(hashed, saltWithMetadata, candidate string) (bool, error) {
	var result bool = false
	var err error

	r := regexp.MustCompile(`!`)
	if !r.MatchString(saltWithMetadata) {
		err = errors.New(`No "!" included.`)
		return result, err
	}

	ais := strings.Split(saltWithMetadata, "!")
	i := ais[1]
	iterations, err := strconv.Atoi(i)
	if err != nil {
		return result, err
	}
	salt := ais[2]

	decoded, err := base64.StdEncoding.Strict().DecodeString(hashed)
	if err != nil {
		return result, err
	}

	c := Hash(candidate, salt, iterations, len(decoded))

	result = hashed == c

	return result, nil
}

func Hash(password, salt string, iterations, size int) string {
	b := pbkdf2.Key([]byte(password), []byte(salt), iterations, size, sha512.New)
	return base64.StdEncoding.Strict().EncodeToString(b)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateRandomString(n int) (string, error) {
	b, err := generateRandomBytes(n)
	return base64.StdEncoding.Strict().EncodeToString(b), err
}
