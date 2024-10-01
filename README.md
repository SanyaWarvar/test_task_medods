## Установка

1. `git clone https://github.com/SanyaWarvar/test_task_medods`
2. Развернуть PostgreSQL `./cmd/db/database_up.bat`
3. Прогнать миграции `./cmd/db/make_migrations.bat`
4. Создать в корне `.env`. Пример данных находится в `.env-example`

## Документация
**Всем ендпоинтам необходим header "X-Forwarded-From"**

1. **GET {{base_url}}/auth/{{uuid}}**

В теле запроса отправить json {"email": string}

Возвращает json формата: {"refresh_token": string, "access_token": string}

Создает пользователя в бд и возвращает пару refresh и access токенов.

3. **POST {{base_url}}/refresh**

В теле запроса отправить json {"access_token": string, "refresh_token": string}

Возвращает json формата: {"refresh_token": string, "access_token": string}

Обновляет refresh и access токены. Если изменился ip адресс, то отправляет сообщение об этом на почту.
