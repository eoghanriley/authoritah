package authoritah

import "errors"

var (
	ErrSessionNotFound   = errors.New("authoritah: session not found")
	ErrSessionExpired    = errors.New("authoritah: session expired")
	ErrUserNotFound      = errors.New("authoritah: user not found")
	ErrUserAlreadyExists = errors.New("authoritah: user already exists")
	ErrUnauthorized      = errors.New("authoritah: unauthorized")
	ErrPluginNotFound    = errors.New("authoritah: plugin not found")
)
