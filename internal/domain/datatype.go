package domain

// DataType — тип хранимой записи.
// go:generate stringer -type=DataType -linecomment
type DataType uint8

const (
	// DataTypeUnknown используется как нулевое значение (не должен встречаться в реальных записях).
	DataTypeUnknown DataType = iota // unknown
	// DataTypeCredentials — пара логин/пароль.
	DataTypeCredentials // credentials
	// DataTypeText — произвольный текст.
	DataTypeText // text
	// DataTypeBinary — произвольные бинарные данные.
	DataTypeBinary // binary
	// DataTypeCard — данные банковской карты.
	DataTypeCard // card
	// DataTypeOTP — секрет одноразового пароля (TOTP/HOTP).
	DataTypeOTP // otp
)

// Valid возвращает true, если тип является одним из допустимых.
func (t DataType) Valid() bool {
	return t >= DataTypeCredentials && t <= DataTypeOTP
}
