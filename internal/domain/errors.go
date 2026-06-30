package domain

import "errors"

// Sentinel-ошибки доменного слоя. Все слои выше (сервисы, транспорт) сравнивают
// ошибки через errors.Is, поэтому обёртки через fmt.Errorf("%w", ...) сохраняют
// совместимость.

// ErrNotFound возвращается, когда запрашиваемая сущность не найдена.
var ErrNotFound = errors.New("not found")

// ErrConflict возвращается при конфликте версий (optimistic locking):
// base_version записи устарела относительно версии на сервере.
var ErrConflict = errors.New("version conflict")

// ErrUnauthorized возвращается при попытке доступа к чужим ресурсам или
// при недействительном токене/challenge.
var ErrUnauthorized = errors.New("unauthorized")

// ErrAlreadyExists возвращается при попытке создать сущность с уже занятым
// уникальным идентификатором (например, логином пользователя).
var ErrAlreadyExists = errors.New("already exists")

// ErrRateLimited возвращается, когда превышен лимит попыток (например, логина).
var ErrRateLimited = errors.New("rate limited")

// ErrInvalidArgument возвращается при некорректных входных данных.
var ErrInvalidArgument = errors.New("invalid argument")
