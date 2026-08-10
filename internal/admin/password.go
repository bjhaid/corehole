package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordHasher interface {
	Hash(password []byte) (string, error)
	Compare(encoded string, password []byte) (bool, error)
}

type Argon2idParams struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type Argon2idHasher struct {
	params Argon2idParams
}

func NewArgon2idHasher(params Argon2idParams) Argon2idHasher {
	if params.Memory == 0 {
		params.Memory = 64 * 1024
	}
	if params.Time == 0 {
		params.Time = 3
	}
	if params.Parallelism == 0 {
		params.Parallelism = 1
	}
	if params.SaltLength == 0 {
		params.SaltLength = 16
	}
	if params.KeyLength == 0 {
		params.KeyLength = 32
	}
	return Argon2idHasher{params: params}
}

func (h Argon2idHasher) Hash(password []byte) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(password, salt, h.params.Time, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.params.Memory,
		h.params.Time,
		h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (h Argon2idHasher) Compare(encoded string, password []byte) (bool, error) {
	params, salt, expected, err := parseArgon2idHash(encoded)
	if err != nil {
		return false, err
	}

	actual := argon2.IDKey(password, salt, params.Time, params.Memory, params.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parseArgon2idHash(encoded string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id version")
	}
	if version != argon2.Version {
		return Argon2idParams{}, nil, nil, errors.New("unsupported argon2id version")
	}

	var params Argon2idParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Parallelism); err != nil {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id salt")
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id hash bytes")
	}
	if len(salt) == 0 || len(hash) == 0 {
		return Argon2idParams{}, nil, nil, errors.New("invalid argon2id hash")
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))
	return params, salt, hash, nil
}
