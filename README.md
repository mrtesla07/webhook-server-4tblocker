# TBlocker Webhook Relay

Небольшой FastAPI-сервис, который принимает вебхуки от [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker),
достает из них Telegram ID пользователя и отправляет ему понятное уведомление о временной блокировке за торрент-трафик.
Дополнительно сервис может уведомлять администратора.

## Переменные окружения

- `TELEGRAM_BOT_TOKEN` — токен Telegram-бота, через которого будут уходить сообщения.
- `ADMIN_CHAT_ID` — опционально. Если задан, сюда дублируется служебное уведомление.
  Без этой переменной сервис будет использовать `chat_id`, который пришёл в исходном вебхуке.

Создайте файл `.env` на основе `.env.example` или передайте переменные окружения любым удобным способом.

## Запуск локально

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

По умолчанию эндпоинт доступен по адресу `http://localhost:8000/webhook`.

## Запуск в Docker

```bash
docker build -t tblocker-webhook .
docker run -d --name tblocker-webhook \
  -p 8000:8000 \
  --env-file .env \
  tblocker-webhook
```

## Настройка webhook в tblocker

```yaml
WebhookURL: "https://ваш-домен/webhook"
WebhookHeaders:
  Content-Type: "application/json"
WebhookTemplate: >-
  {"chat_id":"2104519441",
   "text":"?? tblocker\n?? user: %s\n?? ip: %s\n??? server: %s\n? action: %s\n? ttl(s): %d\n?? time: %s"}
```

- `%s %s %s %s %d %s` — стандартные плейсхолдеры tblocker.
- `chat_id` в шаблоне можно оставить на администратора — сервис всё равно возьмёт фактический ID из поля `user`.

## Что делает сервис

1. Принимает POST-запрос от tblocker.
2. Разбирает текст и извлекает `user_XXXXXXXX`.
3. Удаляет префикс `user_` и отправляет уведомление прямо пользователю.
4. Опционально дублирует тех. информацию администратору.

## Проверка

```bash
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "chat_id": "2104519441",
    "text": "?? tblocker\n?? user: user_2104519441\n?? ip: 176.109.188.156\n??? server: example-server\n? action: block\n? ttl(s): 60\n?? time: 2025-10-09T22:29:21Z"
  }'
```
