# File Encryption Tool (AES-256-GCM)

CLI-утилита для шифрования/дешифрования файлов паролем. Использует
проверенные примитивы из библиотеки `cryptography`

## Как это устроено
- **Key derivation:** PBKDF2-HMAC-SHA256, 600 000 итераций (текущая
  рекомендация OWASP) - защита от брутфорса пароля по словарю
- **Шифрование:** AES-256-GCM - authenticated encryption
- **Формат файла:** `[16 байт salt][12 байт nonce][ciphertext+tag]`
  Соль и nonce каждый раз генерируются случайно и хранятся в самом файле.
## Установка
```bash
pip install -r requirements.txt
```

## Использование
```bash
python3 crypto_tool.py encrypt secret.txt secret.txt.enc
python3 crypto_tool.py decrypt secret.txt.enc secret_restored.txt
```
Пароль вводится скрыто (через `getpass`, не сохраняется в истории shell).

