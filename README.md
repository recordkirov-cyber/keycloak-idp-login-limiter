# Keycloak IdP Login Limiter

Custom **Authenticator** for Keycloak that limits the number of authentications a user can perform through a specified Identity Provider (IdP) within a given time interval.

Кастомный **Authenticator** для Keycloak, который ограничивает количество аутентификаций пользователя через указанный Identity Provider (IdP) в пределах заданного интервала.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://img.shields.io/badge/build-passing-brightgreen)
[![Keycloak](https://img.shields.io/badge/keycloak-22%2B-orange)](https://img.shields.io/badge/keycloak-22%2B-orange)
[![Java](https://img.shields.io/badge/java-21%2B-blue)](https://img.shields.io/badge/java-21%2B-blue)

## 🔎 Description / Описание

**English:** This authenticator limits the number of successful logins a user makes through a specific IdP over a configured time interval by counting Keycloak user `LOGIN` events. It does not rely on writing user attributes, so it works with read-only federated users and distributed Keycloak clusters.

**Русский:** Этот аутентификатор ограничивает количество успешных входов пользователя через конкретный IdP за заданный интервал времени, считая события `LOGIN` пользователя в Keycloak. Он не использует запись пользовательских атрибутов, поэтому корректно работает с read-only федерацией и распределённым кластером Keycloak.

## 🚀 Features / Функциональные возможности

- Limit authentication attempts per IdP / Ограничение количества аутентификаций по IdP
- Support for global limit (if IdP is not specified) / Поддержка глобального лимита (если IdP не указан)
- Event-based rate limiting using `LOGIN` user events / Ограничение на основе событий `LOGIN` пользователя
- No user attribute writes required / Без записи пользовательских атрибутов
- Works with read-only federated users and distributed Keycloak clusters / Работает с read-only федерацией и распределённым кластером Keycloak
- Automatic limit check by recent event history instead of local counters / Автоматическая проверка лимита по истории событий вместо локальных счётчиков
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
   - if IdP is not found, the check is skipped and authentication proceeds.
3. The authenticator queries Keycloak user `LOGIN` events for the user in the current realm.
4. Only events from the last `reset-interval-hours` hours are counted.
5. If `idp-alias` is configured, only events with `identity_provider` matching that alias are counted; otherwise, all successful `LOGIN` events are counted.
6. If the event count reaches the configured limit, authentication is blocked.

**Русский:**
1. Извлекается пользователь из контекста аутентификации.
2. Определяется IdP:
   - если указан `idp-alias`, используется он;
   - иначе проверяются заметки сессии `BROKER_IDENTITY_PROVIDER` и `IDENTITY_PROVIDER`;
   - если IdP не найден — проверка пропускается и аутентификация продолжается.
3. Аутентификатор запрашивает события `LOGIN` пользователя в текущем реалме Keycloak.
4. Считаются только события за последние `reset-interval-hours` часов.
5. Если настроен `idp-alias`, учитываются только события с `identity_provider`, совпадающим с алиасом; иначе считаются все успешные `LOGIN` события.
6. Если число событий достигает лимита, аутентификация блокируется.

## 📂 Event Requirements / Требования к событиям

**English:** This authenticator relies on Keycloak user `LOGIN` events. Make sure that user events are enabled in the realm settings, and that `LOGIN` events are recorded in the current realm.

**Русский:** Аутентификатор зависит от пользовательских событий `LOGIN` в Keycloak. Убедитесь, что пользовательские события включены в настройках реалма и что события `LOGIN` сохраняются в текущем реалме.

### Keycloak realm settings / Настройки реалма

**English:** In Keycloak admin console, go to `Realm Settings` → `Events` and enable:
- `Save Events`
- `Login Events`
- optionally `Event Listeners` such as `jboss-logging` or custom event listeners

**Русский:** В админ-консоли Keycloak перейдите в `Realm Settings` → `Events` и включите:
- `Save Events`
- `Login Events`
- при необходимости `Event Listeners`, например `jboss-logging` или кастомные слушатели событий

### Note / Примечание

**English:** Since all rate limiting is based on event history, event storage must be available and contain recent `LOGIN` events for the user.

**Русский:** Поскольку ограничение работает на основе истории событий, хранилище событий должно быть доступно и содержать свежие события `LOGIN` для пользователя.

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