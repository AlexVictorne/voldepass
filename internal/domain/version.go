package domain

// APIVersion — текущая версия API Voldepass.
// Клиент передаёт её в заголовке X-API-Version; сервер проверяет совместимость
// по major-компоненту и возвращает 426 Upgrade Required при несовпадении.
const APIVersion = "1.0.0"
