# Keycloak IdP Login Limiter

Custom **Authenticator** for Keycloak that limits the number of authentications a user can perform through a specified Identity Provider (IdP) within a given time interval.

Кастомный **Authenticator** для Keycloak, который ограничивает количество аутентификаций пользователя через указанный Identity Provider (IdP) в пределах заданного интервала.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://img.shields.io/badge/build-passing-brightgreen)
[![Keycloak](https://img.shields.io/badge/keycloak-22%2B-orange)](https://img.shields.io/badge/keycloak-22%2B-orange)
[![Java](https://img.shields.io/badge/java-21%2B-blue)](https://img.shields.io/badge/java-21%2B-blue)

## 🔎 Description / Описание

**English:** This authenticator checks the number of login attempts a user makes through a specific IdP and blocks authentication if the limit is exceeded. It runs as part of the authentication flow, ensuring that user attribute changes are properly saved to the database, including production environments with PostgreSQL.

**Русский:** Этот аутентификатор проверяет количество попыток входа пользователя через конкретный провайдер IdP и блокирует аутентификацию, если лимит превышен. Он выполняется как часть потока аутентификации, гарантируя, что изменения атрибутов пользователя правильно сохраняются в базе данных, включая продакшн-среды с PostgreSQL.

## 🚀 Features / Функциональные возможности

- Limit authentication attempts per IdP / Ограничение количества аутентификаций по IdP
- Support for global limit (if IdP is not specified) / Поддержка глобального лимита (если IdP не указан)
- Personal user attributes for storing counters / Персональные пользовательские атрибуты для хранения счётчиков
- Automatic counter reset by time (interval in hours) / Автоматический сброс счётчика по времени (интервал в часах)
- Manual counter reset in user admin console / Можно сбросить счётчики вручную в админ-консоли пользователя
- Works with Keycloak 22+ and Java 21+ / Работает с Keycloak 22+ и Java 21+

## 📦 Requirements / Требования

- **Keycloak**: 22.0.0+
- **Java**: 21+
- **Maven**: 3.8+

## 🛠 Build / Сборка

```bash
mvn clean package
```

**English:** After successful build, the JAR will appear in `target/keycloak-idp-login-limiter-${version}.jar`.

**Русский:** После успешной сборки JAR появится в `target/keycloak-idp-login-limiter-${version}.jar`.

## 📥 Installation / Установка

**English:**
1. Copy the built JAR to the Keycloak `providers` directory or another provider directory depending on server configuration.
2. Restart Keycloak.
3. In the admin console, create or edit an authentication flow.
4. Add the new `Identity Provider Rate Limiting` as an execution authenticator.

**Русский:**
1. Скопируйте собранный JAR в директорию `providers` Keycloak или в другую директорию провайдеров в зависимости от конфигурации сервера.
2. Перезапустите Keycloak.
3. В админ-консоли создайте или отредактируйте поток аутентификации.
4. Добавьте новый `Identity Provider Rate Limiting` как execution authenticator.

## ⚙️ Authenticator Configuration / Конфигурация аутентификатора

**English:** The following parameters are available in the authenticator settings:

**Русский:** В настройках аутентификатора доступны следующие параметры:

| Field / Поле | Configuration Name / Имя конфигурации | Description / Описание | Example / Пример |
|---|---|---|---|
| Login Limit / Лимит входов | `idp-limit` | Maximum number of authentications through the specified IdP per interval / Максимальное число аутентификаций через указанный IdP за интервал | `5` |
| IdP Alias / Алиас IdP | `idp-alias` | Provider alias for which the limit is calculated. If empty - global counter for all IdPs / Алиас провайдера, для которого считается лимит. Если пусто — глобальный счётчик для всех IdP | `google` |
| Reset Interval / Интервал сброса | `reset-interval-hours` | Interval in hours after which the counter is automatically reset / Интервал в часах, после которого автоматически сбрасывается счётчик | `24` |
| Error Message / Сообщение об ошибке | `error-message` | Custom error message when limit is exceeded. Supports placeholders: ${username}, ${idpAlias}, ${limit}, ${resetHours} / Кастомное сообщение об ошибке при превышении лимита. Поддерживает плейсхолдеры: ${username}, ${idpAlias}, ${limit}, ${resetHours} | `Login limit exceeded for ${username} via ${idpAlias}` |

### Configuration Examples / Примеры конфигурации

- `idp-limit = 5`, `idp-alias = google`, `reset-interval-hours = 24` — maximum 5 logins through `google` per day / максимум 5 входов через `google` в сутки.
- `idp-limit = 10`, `idp-alias = `, `reset-interval-hours = 12` — maximum 10 logins through any IdP in 12 hours / максимум 10 входов через любой IdP за 12 часов.
- `idp-limit = 3`, `idp-alias = github`, `reset-interval-hours = 1`, `error-message = Login limit exceeded for ${username} via ${idpAlias}. Try again in ${resetHours} hour(s)` — custom message in English with placeholders / кастомное сообщение на английском с плейсхолдерами.

## 🧩 How It Works / Как это работает

**English:**
1. The user is extracted from the authentication context.
2. The IdP is determined:
   - if `idp-alias` is specified, it is used;
   - otherwise, session notes `BROKER_IDENTITY_PROVIDER` and `IDENTITY_PROVIDER` are checked;
   - if IdP is not found, the condition is not met.
3. The time of the last attribute reset is checked.
4. If more than the specified number of hours have passed, the counter is reset.
5. The counter is incremented and compared with the limit.
6. Attributes are updated with the remaining attempts.

**Русский:**
1. Извлекается пользователь из контекста аутентификации.
2. Определяется IdP:
   - если указан `idp-alias`, используется он;
   - иначе проверяются заметки сессии `BROKER_IDENTITY_PROVIDER` и `IDENTITY_PROVIDER`;
   - если IdP не найден — условие не выполняется.
3. Проверяется время последнего сброса атрибута.
4. Если прошло больше заданного числа часов, счётчик сбрасывается.
5. Счётчик инкрементируется и сравнивается с лимитом.
6. Обновляется атрибут оставшихся попыток.

## 🧾 User Attributes / Пользовательские атрибуты

**English:** The following attributes are used for each user:
- `idp_attempts_{alias}` — current number of logins through IdP
- `idp_last_reset_{alias}` — timestamp of last reset

If alias is not specified, the `global` suffix is used:
- `idp_attempts_global`
- `idp_last_reset_global`

**Русский:** Для каждого пользователя используются атрибуты вида:
- `idp_attempts_{alias}` — текущее число входов через IdP
- `idp_last_reset_{alias}` — метка времени последнего сброса

Если алиас не указан, используется суффикс `global`:
- `idp_attempts_global`
- `idp_last_reset_global`

### Note / Примечание

**English:** Attributes store only the attempt counter and the time of the last reset; remaining attempts are calculated using the formula `limit - attempts`.

**Русский:** Атрибуты хранят только счётчик попыток и время последнего сброса; оставшиеся попытки вычисляются по формуле `limit - attempts`.

## 🔧 Manual Reset in Admin Console / Сброс в админ-консоли

**English:** An administrator can manually reset user counters by deleting or modifying the corresponding attributes in the user profile.

**Русский:** Администратор может вручную сбросить счётчики у пользователя, удалив или изменив соответствующие атрибуты в профиле пользователя.

### Where to Find / Где искать

**English:** In the Keycloak admin console:
- `Users` → select user → `Attributes` tab
- Find `idp_attempts_*`, `idp_last_reset_*`
- Delete or modify values to reset counters

**Русский:** В админ-консоли Keycloak:
- `Users` → выберите пользователя → вкладка `Attributes`
- Найдите `idp_attempts_*`, `idp_last_reset_*`
- Удалите или измените значения, чтобы сбросить счётчики

## 🧪 Testing / Тестирование

```bash
mvn test
```

## 📌 Notes / Замечания

- If there is no correct limit configuration, the plugin will choose safe behavior and will not block the user / При отсутствии корректной конфигурации лимита аутентификации плагин выберет безопасное поведение и не заблокирует пользователя.
- Time reset works at the hour level and is set by the administrator via the `reset-interval-hours` parameter / Сброс по времени работает на уровне часов и задаётся администратором через параметр `reset-interval-hours`.
- Custom error messages support placeholder interpolation for personalization: `${username}`, `${idpAlias}`, `${limit}`, `${resetHours}` / Кастомное сообщение об ошибке поддерживает интерполяцию плейсхолдеров для персонализации: `${username}`, `${idpAlias}`, `${limit}`, `${resetHours}`.
- If the `error-message` field is empty, the default Keycloak authentication error message is used / Если поле `error-message` пустое, используется стандартное сообщение Keycloak об ошибке аутентификации.

## 🔧 Improvements and Implementation Features / Улучшения и особенности реализации

- **Thread Safety / Потокобезопасность**: Using `ReentrantLock` instead of `String.intern()` to prevent memory leaks / Использование `ReentrantLock` вместо `String.intern()` для предотвращения утечек памяти
- **Error Handling / Обработка ошибок**: Improved exception handling with detailed logging / Улучшенная обработка исключений с подробным логированием
- **Code Duplication Elimination / Устранение дублирования кода**: Moving repeated logic into separate methods / Вынесение повторяющейся логики в отдельные методы
- **Compatibility / Совместимость**: Support for various Keycloak versions and ways to obtain IdP alias / Поддержка различных версий Keycloak и способов получения IdP alias
- **Testing / Тестирование**: Extended test coverage using JUnit 5 / Расширенное покрытие тестами с использованием JUnit 5
- **Documentation / Документация**: Detailed code comments and improved documentation / Подробные комментарии к коду и улучшенная документация

## Contacts / Контакты

**English:** If you need to modify behavior or add integration with a specific Keycloak version, open an issue or submit a pull request.

**Русский:** Если необходимо доработать поведение или добавить интеграцию с конкретной версией Keycloak, открывайте issue или предлагайте пулл-реквест.