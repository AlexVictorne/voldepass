package service

import "github.com/google/uuid"

// newID генерирует новый UUID v4 для идентификаторов сущностей.
func newID() string {
	return uuid.NewString()
}
