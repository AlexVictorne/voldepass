// Пакет transport реализует HTTP-клиент Voldepass поверх go-retryablehttp:
// двухфазный login, автоматический рефреш access-токена, X-API-Version,
// опциональный certificate pinning.
package transport
