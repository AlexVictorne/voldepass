package domain

// Payload-структуры живут только на стороне клиента: они сериализуются в JSON,
// шифруются dataKey и кладутся в Record.Ciphertext. Сервер никогда не видит
// расшифрованный payload.

// CredentialsPayload — пара логин/пароль для произвольного сервиса.
type CredentialsPayload struct {
	// Login — имя пользователя или адрес электронной почты.
	Login string `json:"login"`
	// Password — пароль в открытом виде (до шифрования).
	Password string `json:"password"`
}

// TextPayload — произвольный текстовый фрагмент (заметки, секретные ключи и т.п.).
type TextPayload struct {
	// Content — текстовое содержимое.
	Content string `json:"content"`
}

// BinaryPayload — произвольные бинарные данные (файл, изображение и т.п.).
type BinaryPayload struct {
	// Data — бинарные данные в формате base64 при JSON-сериализации.
	Data []byte `json:"data"`
	// Filename — исходное имя файла (опционально).
	Filename string `json:"filename,omitempty"`
}

// CardPayload — данные банковской карты.
type CardPayload struct {
	// Number — номер карты (16–19 цифр).
	Number string `json:"number"`
	// Holder — имя держателя карты.
	Holder string `json:"holder"`
	// Expiry — срок действия в формате MM/YY.
	Expiry string `json:"expiry"`
	// CVV — код проверки карты (3–4 цифры).
	CVV string `json:"cvv"`
}

// OTPPayload — секрет и параметры одноразового пароля (TOTP/HOTP, RFC 6238/4226).
type OTPPayload struct {
	// Secret — base32-кодированный общий секрет.
	Secret string `json:"secret"`
	// Issuer — имя издателя (сервиса), например "GitHub".
	Issuer string `json:"issuer,omitempty"`
	// Account — имя аккаунта, например "user@example.com".
	Account string `json:"account,omitempty"`
	// Algorithm — алгоритм хеширования: SHA1, SHA256, SHA512 (по умолчанию SHA1).
	Algorithm string `json:"algorithm,omitempty"`
	// Digits — количество цифр в коде: 6 или 8 (по умолчанию 6).
	Digits int `json:"digits,omitempty"`
	// Period — период смены кода в секундах (по умолчанию 30).
	Period int `json:"period,omitempty"`
}
