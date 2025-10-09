# TBlocker Webhook Relay

��������� FastAPI-������, ������� ��������� ������� �� [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker),
������� �� ��� Telegram ID ������������ � ���������� ��� �������� ����������� � ��������� ���������� �� �������-������.
������������� ������ ����� ���������� ��������������.

## ���������� ���������

- `TELEGRAM_BOT_TOKEN` � ����� Telegram-����, ����� �������� ����� ������� ���������.
- `ADMIN_CHAT_ID` � �����������. ���� �����, ���� ����������� ��������� �����������.
  ��� ���� ���������� ������ ����� ������������ `chat_id`, ������� ������ � �������� �������.

�������� ���� `.env` �� ������ `.env.example` ��� ��������� ���������� ��������� ����� ������� ��������.

## ������ ��������

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

�� ��������� �������� �������� �� ������ `http://localhost:8000/webhook`.

## ������ � Docker

```bash
docker build -t tblocker-webhook .
docker run -d --name tblocker-webhook \
  -p 8000:8000 \
  --env-file .env \
  tblocker-webhook
```

## ��������� webhook � tblocker

```yaml
WebhookURL: "https://���-�����/webhook"
WebhookHeaders:
  Content-Type: "application/json"
WebhookTemplate: >-
  {"chat_id":"2104519441",
   "text":"?? tblocker\n?? user: %s\n?? ip: %s\n??? server: %s\n? action: %s\n? ttl(s): %d\n?? time: %s"}
```

- `%s %s %s %s %d %s` � ����������� ������������ tblocker.
- `chat_id` � ������� ����� �������� �� �������������� � ������ �� ����� ������ ����������� ID �� ���� `user`.

## ��� ������ ������

1. ��������� POST-������ �� tblocker.
2. ��������� ����� � ��������� `user_XXXXXXXX`.
3. ������� ������� `user_` � ���������� ����������� ����� ������������.
4. ����������� ��������� ���. ���������� ��������������.

## ��������

```bash
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "chat_id": "2104519441",
    "text": "?? tblocker\n?? user: user_2104519441\n?? ip: 176.109.188.156\n??? server: example-server\n? action: block\n? ttl(s): 60\n?? time: 2025-10-09T22:29:21Z"
  }'
```
