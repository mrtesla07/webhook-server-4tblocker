import logging
import os
import re
from typing import Any, Dict

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError


load_dotenv()

logger = logging.getLogger("tblocker-webhook")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

app = FastAPI(title="TBlocker Telegram Relay")


class TBlockerPayload(BaseModel):
    chat_id: str = Field(..., description="Адресат, которому tblocker пытался отправить сообщение")
    text: str = Field(..., description="Форматированное сообщение, содержащее детали блокировки")


def extract_fields(text: str) -> Dict[str, Any]:
    """
    Преобразуем текст tblocker в словарь значений.

    Пример входа:
    ?? tblocker
    ?? user: user_2104519441
    ?? ip: 176.109.188.156
    ??? server: example-server
    ? action: unblock
    ? ttl(s): 60
    ?? time: 2025-10-09T22:29:21Z
    """
    data: Dict[str, Any] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue

        # Отбрасываем emoji / иконки
        parts = line.split(" ", 1)
        if len(parts) == 2 and ":" in parts[1]:
            line = parts[1]

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "user":
            data["username_raw"] = value
            data["telegram_id"] = value.split("user_", 1)[-1] if "user_" in value else value
        elif key == "ip":
            data["ip"] = value
        elif key == "server":
            data["server"] = value
        elif key == "action":
            data["action"] = value
        elif key.startswith("ttl"):
            try:
                data["duration_seconds"] = int(re.sub(r"[^\d]", "", value) or "0")
            except ValueError:
                data["duration_seconds"] = 0
        elif key == "time":
            data["timestamp"] = value

    return data


def build_user_message(data: Dict[str, Any]) -> str:
    duration_seconds = data.get("duration_seconds") or 60
    duration_minutes = max(1, round(duration_seconds / 60)) if duration_seconds else 1

    server = data.get("server", "неизвестный сервер")
    ip = data.get("ip", "неизвестный IP")
    timestamp = data.get("timestamp", "неизвестное время")
    action = data.get("action", "block")

    return (
        "?? <b>Временная блокировка</b>\n"
        "Мы обнаружили трафик, похожий на использование торрентов или p2p-апдейтеров игр.\n\n"
        f"<b>Статус:</b> {action}\n"
        f"<b>IP:</b> <code>{ip}</code>\n"
        f"<b>Сервер:</b> {server}\n"
        f"<b>Время фиксации:</b> {timestamp}\n\n"
        f"Доступ ограничен примерно на {duration_minutes} мин. Блокировка снимается автоматически. "
        "Чтобы ускорить процесс, остановите приложения, которые используют P2P (торрент-клиенты, обновляторы игр и т.д.).\n\n"
        "Если считаете это ошибкой — ответьте на сообщение или напишите в поддержку."
    )


async def send_telegram_message(token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        status = getattr(exc.response, "status_code", 502)
        body = getattr(exc.response, "text", str(exc))
        logger.error("Ошибка отправки сообщения в Telegram: %s - %s", status, body)
        raise HTTPException(status_code=502, detail="Не удалось отправить сообщение в Telegram") from exc


@app.post("/webhook")
async def webhook_handler(request: Request) -> Dict[str, str]:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise HTTPException(status_code=500, detail="Не задан TELEGRAM_BOT_TOKEN")

    try:
        payload = TBlockerPayload.model_validate(await request.json())
    except ValidationError as exc:
        logger.warning("Некорректный payload: %s", exc)
        raise HTTPException(status_code=400, detail="Некорректный формат payload") from exc

    data = extract_fields(payload.text)
    telegram_id = data.get("telegram_id")

    if not telegram_id:
        raise HTTPException(status_code=400, detail="Не удалось определить Telegram ID пользователя")

    message = build_user_message(data)
    await send_telegram_message(token, telegram_id, message)

    admin_chat_id = os.getenv("ADMIN_CHAT_ID") or payload.chat_id
    if admin_chat_id:
        admin_message = (
            "?? <b>tblocker webhook</b>\n"
            f"Уведомление доставлено пользователю <code>{telegram_id}</code>.\n"
            f"IP: <code>{data.get('ip', '—')}</code>\n"
            f"Сервер: {data.get('server', '—')}\n"
            f"Действие: {data.get('action', '—')}"
        )
        try:
            await send_telegram_message(token, admin_chat_id, admin_message)
        except HTTPException:
            pass

    return {"status": "ok"}
