package netlink

import (
	"os"
	"strings"
)

func IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "operation not supported")
}

func IsExist(err error) bool {
	if err == nil {
		return false
	}
	return os.IsExist(err) || strings.Contains(err.Error(), "already exists")
}

func IsNotExist(err error) bool {
	if err == nil {
		return false
	}
	return os.IsNotExist(err) || strings.Contains(err.Error(), "not found")
}
