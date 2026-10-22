# Auth service

Auth — внутренний gRPC-сервис учётных записей [Auth project (KLoad)](https://github.com/Weit145/auth-project). Он создаёт пользователей, подтверждает email, проверяет пароль, выпускает JWT, управляет refresh-сессиями и восстановлением пароля. Публичный HTTP API предоставляет [Gateway](https://github.com/Weit145/gateway-project-service#readme); в Docker Compose gRPC-порт Auth не опубликован наружу.

## Архитектура — C4 Level 3

![Компонентная диаграмма Auth](docs/diagrams/c4-component.png)

[Открыть SVG](docs/diagrams/c4-component.svg) · [Исходник PlantUML](docs/diagrams/c4-component.puml)

| Компонент | Роль |
| --- | --- |
| gRPC transport | Принимает вызовы Gateway по mTLS и передаёт их в use cases. |
| Use cases | Выполняют сценарии регистрации, входа, обновления сессии и работы с паролем. |
| Token provider | Создаёт подписанные JWT, случайные одноразовые токены и их хеши для хранения. |
| PostgreSQL repository | Выполняет SQL-запросы и транзакции. |
| Outbox worker и Kafka producer | Забирают ожидающие события из БД, публикуют их в topic `notifications` и повторяют отправку при сбое. |

При `RegisterRequest` сервис сохраняет ожидающего пользователя, хеш токена подтверждения и событие outbox в одной транзакции. `ConfirmEmail` погашает токен и создаёт короткую регистрационную сессию. `RegisterComplete` использует эту сессию, задаёт пароль, отмечает email подтверждённым и создаёт refresh-сессию. Повторная регистрация существующего email не переписывает пароль: вставка пользователя использует `ON CONFLICT (email) DO NOTHING`.

## Схема БД — PostgreSQL

![Схема PostgreSQL Auth](docs/diagrams/database.png)

[Открыть SVG](docs/diagrams/database.svg) · [Исходник PlantUML](docs/diagrams/database.puml) · [SQL-миграции](migrations)

| Таблица | Назначение и ключевые поля |
| --- | --- |
| `users` | `id` — PK, `email` — UNIQUE. `password_hash` и `email_verified_at` остаются пустыми до завершения регистрации; `role` ограничен значениями `user` и `admin`. |
| `email_verification_tokens` | Хеш одноразового токена, срок действия и `used_at`; `user_id` ссылается на `users.id`. |
| `registration_sessions` | Короткие сессии для задания пароля: `id`, `token_hash`, `expires_at`, `used_at` и `user_id`. Частичный уникальный индекс допускает одну неиспользованную сессию на пользователя. |
| `refresh_sessions` | Хеш refresh token, срок действия и `revoked_at` для входа, обновления и выхода. |
| `password_reset_tokens` | Одноразовые токены восстановления пароля с истечением срока и `used_at`. |
| `event_outbox` | `event_id`, тип, email, ссылка, статус, время следующей попытки и счётчик попыток. `user_id` здесь не имеет внешнего ключа в SQL-схеме. |

Все четыре таблицы токенов и сессий имеют внешний ключ `user_id → users.id` с `ON DELETE CASCADE`. Поле `name` было удалено миграцией `00003` и в текущей схеме отсутствует. Актуальная структура получается после миграций `00001`–`00005`.

## Путь пользователя

![Путь пользователя в Auth](docs/diagrams/cjm.png)

[Открыть SVG](docs/diagrams/cjm.svg) · [Исходник PlantUML](docs/diagrams/cjm.puml)

## Взаимодействие и запуск

Go-модуль сервиса: `github.com/Weit145/auth-startup`. Общий gRPC-контракт —
[`github.com/weit145/proto-startup`](https://github.com/Weit145/proto-startup), версия `v1.0.0`.
Зависимости Go и их версии перечислены в [go.mod](go.mod).

Gateway вызывает Auth по gRPC с клиентским сертификатом; Auth проверяет его по CA. PostgreSQL хранит данные аккаунтов, а Kafka получает события писем из outbox. Письма отправляет отдельный [notification service](https://github.com/Weit145/notification-startup).

Для запуска полного стека выполните `make build` в [корне проекта](https://github.com/Weit145/auth-project#readme). Настройки Auth задаются через переменные окружения: `DATABASE_URL`, `GRPC_AUTH_ADDR`, `KAFKA_BROKERS`, `JWT_PRIVATE_KEY_PATH`, `JWT_REFRESH_SECRET` и пути сертификатов `GRPC_TLS_*`. Пользовательский путь показан на [CJM](docs/diagrams/cjm.png).
