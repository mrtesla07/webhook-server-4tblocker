import json
import logging
import os
import re
from typing import Any, Dict, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError
from starlette.datastructures import FormData

# ---------------------
# Bootstrap
# ---------------------
load_dotenv()

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("tblocker-webhook")

app = FastAPI(title="TBlocker Telegram Relay", version="1.3.5")

# ---------------------
# Aliases
# ---------------------
def _parse_aliases(env_val: Optional[str]) -> Dict[str, str]:
    """
    Parse SERVER_ALIASES env like:
      SERVER_ALIASES="test01.isgood.host=Russia YouTube, helga.freedomnet.pro=Germany"
    Whitespace around keys/values is trimmed. Keys are lowercased.
    """
    mapping: Dict[str, str] = {}
    if not env_val:
        return mapping
    for part in env_val.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k and v:
            mapping[k] = v
    return mapping

SERVER_ALIASES: Dict[str, str] = _parse_aliases(os.getenv("SERVER_ALIASES"))

def resolve_server_alias(server: Optional[str]) -> str:
    """
    Return aliased/friendly server name if configured; otherwise original or default.
    Matching is case-insensitive; strips optional ':port'.
    """
    if not server:
        return "YouTube Russia"
    raw = str(server).strip()
    key = raw.lower()
    if ":" in key:
        key = key.split(":", 1)[0]
    alias = SERVER_ALIASES.get(key)
    return alias or raw

# ---------------------
# Models
# ---------------------
class TBlockerPayload(BaseModel):
    chat_id: str = Field(..., description="Адресат, которому tblocker пытался отправить сообщение")
    text: str = Field(..., description="Форматированное сообщение, содержащее детали блокировки")

# ---------------------
# Helpers
# ---------------------
def extract_first_json_object(raw: bytes) -> Optional[Dict[str, Any]]:
    """
    Попытаться распарсить JSON из сырого тела; если вокруг мусор — выделить
    первый валидный JSON-объект по скобочному балансу.
    """
    s = raw.lstrip()
    # Прямая попытка
    try:
        return json.loads(s)
    except Exception:
        pass

    # Переход к строке
    try:
        text = s.decode("utf-8", errors="replace")
    except Exception:
        return None

    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        return json.loads(candidate)
                    except Exception:
                        break
    return None

def _to_int_safe(s: Optional[str]) -> int:
    if not s:
        return 0
    m = re.search(r"-?\d+", s)
    return int(m.group()) if m else 0

def _norm_text(t: str) -> str:
    """
    Нормализуем текст tblocker:
      - превращаем литералы '\\n' в реальные переводы строки
      - приводим окончания строк к '\n'
      - тримим пробелы у каждой строки
    """
    if not t:
        return t
    t = t.replace("\\n", "\n")
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.strip() for ln in t.split("\n")]
    return "\n".join(lines)

def extract_fields(text: str) -> Dict[str, Any]:
    """
    Надёжно извлекаем поля user/ip/server/action/ttl/time регулярками.
    Не зависит от эмодзи и произвольных пробелов.
    """
    data: Dict[str, Any] = {}
    if not text:
        return data

    nt = _norm_text(text)

    def grab(patterns: list[str]) -> Optional[str]:
        for p in patterns:
            m = re.search(p, nt, flags=re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        return None

    # user
    user = grab([r"\buser\s*:\s*([^\n]+)"])
    if user:
        data["username_raw"] = user
        data["telegram_id"] = user.split("user_", 1)[-1] if "user_" in user else user

    # ip
    ip = grab([r"\bip\s*:\s*([^\n]+)"])
    if ip:
        data["ip"] = ip

    # server
    server = grab([r"\bserver\s*:\s*([^\n]+)"])
    if server:
        data["server"] = server

    # action
    action = grab([r"\baction\s*:\s*([^\n]+)"])
    if action:
        v = action.lower()
        if v in {"block", "unblock"}:
            data["action"] = v
        else:
            data["action_raw"] = action

    # ttl
    ttl_str = grab([r"\bttl\s*\(s\)\s*:\s*([^\n]+)", r"\bttl\s*:\s*([^\n]+)"])
    if ttl_str is not None:
        data["ttl"] = _to_int_safe(ttl_str)
        data["ttl_raw"] = ttl_str

    # time
    time_val = grab([r"\btime\s*:\s*([^\n]+)"])
    if time_val:
        data["timestamp"] = time_val

    # Нормализуем action по ttl, если action не распознан
    if "action" not in data:
        ttl = int(data.get("ttl") or 0)
        data["action"] = "block" if ttl > 0 else "unblock"

    if "ttl_raw" not in data:
        data["ttl_raw"] = str(data["ttl"]) if "ttl" in data else "—"

    logger.info("Normalized text:\n%s", nt)
    return data

def build_user_message(data: Dict[str, Any]) -> Dict[str, Any]:
    server_raw = data.get("server", "YouTube Russia")
    server = resolve_server_alias(server_raw)
    timestamp = data.get("timestamp", "неизвестное время")
    action = (data.get("action") or "block").lower().strip()
    ttl_raw = data.get("ttl_raw", "неизвестно")

    is_unblock = (action == "unblock")

    logger.info(
        "Message branch: %s | server_raw=%s server_alias=%s ttl_raw=%s time=%s",
        "UNBLOCK" if is_unblock else "BLOCK",
        server_raw, server, ttl_raw, timestamp
    )

    if is_unblock:
        text = (
            "✅ <b>Разблокировка доступа</b>\n"
            "━━━━━━━━━━━━━\n"
            "Временная блокировка доступа к FreedomNET с вашего аккаунта снята.\n\n"
            f"🖥️ <b>Сервер:</b> {server}\n"
            f"📅 <b>Время снятия:</b> {timestamp}\n"
            f"📊 <b>Статус:</b> <code>{action}</code>\n\n"
            "🟢 Доступ к ресурсам восстановлен.\n"
            "Приятного пользования сервисом FreedomNET 🚀"
        )
    else:
        text = (
            "🚫 <b>Временная блокировка</b>\n"
            "━━━━━━━━━━━━━\n"
            "Мы обнаружили трафик, похожий на использование торрентов или P2P-апдейтеров игр.\n\n"
            "❗ <b>На FreedomNET запрещено</b> скачивание через <b>torrent</b> — это мешает другим пользователям.\n\n"
            "📥 Если вам нужно что-то скачать или обновить игру:\n"
            "1️⃣ Выключите VPN.\n"
            "2️⃣ Скачайте или обновите файлы.\n"
            "3️⃣ Затем снова включите VPN.\n\n"
            "⚙️ Чтобы блокировки не происходили:\n"
            "• Закрывайте torrent-приложения после скачивания.\n"
            "• Отключайте апдейтеры игр после входа в игру.\n\n"
            f"🖥️ <b>Сервер:</b> {server}\n"
            f"📅 <b>Время фиксации:</b> {timestamp}\n"
            f"⏱️ <b>Длительность блокировки:</b> {ttl_raw} минут.\n"
            f"📊 <b>Статус:</b> <code>{action}</code>\n\n"
            "🔓 Блокировка снимается автоматически.\n"
            "Если вы считаете это ошибкой — свяжитесь с поддержкой 💬"
        )

    reply_markup = {
        "inline_keyboard": [
            [{"text": "🆘 Техподдержка", "url": "https://t.me/FreedomSuppRobot"}],
            [{"text": "🏠 На главную", "callback_data": "back_to_menu"}],
        ]
    }
    return {"text": text, "reply_markup": reply_markup}

async def send_telegram_message(
    token: str,
    chat_id: str,
    text: str,
    reply_markup: Optional[Dict[str, Any]] = None,
    message_thread_id: Optional[int] = None
) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload: Dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if message_thread_id:
        payload["message_thread_id"] = message_thread_id

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        status = getattr(exc.response, "status_code", 502)
        body = getattr(exc.response, "text", str(exc))
        logger.error("Ошибка отправки сообщения в Telegram: %s - %s", status, body)
        raise HTTPException(status_code=502, detail="Не удалось отправить сообщение в Telegram") from exc

# ---------------------
# Routess
# ---------------------
@app.get("/health", tags=["monitoring"])
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok", "version": app.version}

@app.post("/webhookcfvceyu123")
async def webhook_handler(request: Request) -> Dict[str, str]:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise HTTPException(status_code=500, detail="Не задан TELEGRAM_BOT_TOKEN")

    content_type = (request.headers.get("content-type") or "").lower()
    raw = await request.body()

    # --- full incoming webhook logging (headers + body) for debugging ---
    try:
        client_addr = request.client.host if getattr(request, "client", None) else None
    except Exception:
        client_addr = None

    try:
        headers_dict = dict(request.headers)
    except Exception:
        headers_dict = {k: v for k, v in request.headers.items()}

    try:
        body_text = raw.decode("utf-8", errors="replace")
    except Exception:
        body_text = str(raw)

    LOG_BODY_LIMIT = int(os.environ.get("LOG_BODY_LIMIT", "20000"))
    if len(body_text) > LOG_BODY_LIMIT:
        short_body = body_text[:LOG_BODY_LIMIT] + "\n...[truncated: total %d bytes]" % len(body_text)
    else:
        short_body = body_text

    masked_headers = dict(headers_dict)
    for h in ("authorization", "proxy-authorization", "cookie"):
        if h in masked_headers:
            masked_headers[h] = "<redacted>"

    logger.info(
        "Incoming webhook from=%s content-type=%s headers=%s body=\n%s",
        client_addr,
        content_type,
        masked_headers,
        short_body,
    )
    # --- end logging ---

    try:
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form: FormData = await request.form()
            payload_dict: Dict[str, Any] = dict(form)
        else:
            obj = extract_first_json_object(raw)
            if obj is None:
                try:
                    form: FormData = await request.form()
                    payload_dict = dict(form)
                except Exception:
                    payload_dict = {"text": body_text}
            else:
                payload_dict = obj

        # Normalize common key names to (chat_id, text)
        def _get_first_key(d: Dict[str, Any], keys: list[str]) -> Optional[Any]:
            for k in keys:
                if k in d and d[k] not in (None, ""):
                    return d[k]
            return None

        candidate = _get_first_key(payload_dict, ["payload", "data", "message", "event", "body"])
        if isinstance(candidate, dict):
            payload_dict = candidate

        text_val = _get_first_key(payload_dict, ["text", "message", "msg", "body", "content", "description"])
        chat_val = _get_first_key(payload_dict, [
            "chat_id", "chatId", "telegram_id", "telegramId", "user_id", "userId",
            "user", "to", "recipient", "receiver"
        ])

        if text_val is None:
            try:
                text_val = json.dumps(payload_dict, ensure_ascii=False)
            except Exception:
                text_val = body_text

        if chat_val is None:
            chat_val = request.query_params.get("chat_id") or payload_dict.get("chat_id") or "0"

        normalized = {"chat_id": str(chat_val), "text": str(text_val)}

        payload = TBlockerPayload.model_validate(normalized)

    except ValidationError as exc:
        snippet = body_text[:1000]
        keys = list(payload_dict.keys()) if isinstance(payload_dict, dict) else "?"
        logger.warning("400 Bad payload (%s, %d bytes): %s | keys=%s | snippet=%r",
                       content_type, len(raw or b""), exc, keys, snippet)
        raise HTTPException(status_code=400, detail="Некорректный формат payload")
    except Exception as exc:
        snippet = body_text[:1000]
        logger.warning("400 Unrecognized body (%s, %d bytes): %s | snippet=%r",
                       content_type, len(raw or b""), exc, snippet)
        raise HTTPException(status_code=400, detail="Нераспознанное тело запроса")

    # Разбор содержимого сообщения и выбор получателя
    data = extract_fields(payload.text)

    logger.info("Parsed fields: user=%s ip=%s server=%s action=%s ttl=%s time=%s",
                data.get("telegram_id"), data.get("ip"), data.get("server"),
                data.get("action"), data.get("ttl"), data.get("timestamp"))

    telegram_id = data.get("telegram_id") or payload.chat_id
    if not telegram_id or str(telegram_id) in ("0", ""):
        raise HTTPException(status_code=400, detail="Не удалось определить Telegram ID пользователя")

    # Сообщение пользователю (с кнопками)
    msg = build_user_message(data)
    await send_telegram_message(token, telegram_id, msg["text"], msg["reply_markup"])

    # Уведомление в канал (без кнопок) — показываем сырое имя и алиас
    admin_channel_id = os.getenv("ADMIN_CHANNEL_ID")
    admin_topic_id = os.getenv("ADMIN_TOPIC_ID")
    if admin_channel_id:
        server_raw = data.get("server", "—")
        server_alias = resolve_server_alias(server_raw) if server_raw != "—" else "—"
        server_line = server_alias if server_alias == server_raw else f"{server_raw} → {server_alias}"
        admin_message = (
            "ℹ️ <b>tblocker webhook</b>\n"
            f"Уведомление доставлено пользователю <code>{telegram_id}</code>.\n"
            f"IP: <code>{data.get('ip', '—')}</code>\n"
            f"Сервер: {server_line}\n"
            f"Действие: {data.get('action', '—')}"
        )
        message_thread_id = None
        if admin_topic_id:
            try:
                message_thread_id = int(admin_topic_id)
            except (ValueError, TypeError):
                logger.warning("Некорректный ADMIN_TOPIC_ID: %s", admin_topic_id)
        try:
            await send_telegram_message(token, admin_channel_id, admin_message, message_thread_id=message_thread_id)
        except HTTPException:
            pass

    return {"status": "ok"}
