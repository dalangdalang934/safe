import json
import os
import time
import urllib.parse
import urllib.request


def notification_for(best, last_nonce):
    if best['score'] < 11 or best['saltNonce'] == last_nonce:
        return None
    return (
        f"Safe 找到 {best['score']} 位重复字符地址\n\n"
        f"地址：{best['address']}\n"
        f"saltNonce：{best['saltNonce']}"
    )


def telegram_request(token, method, params=None):
    url = f'https://api.telegram.org/bot{token}/{method}'
    data = urllib.parse.urlencode(params).encode() if params else None
    with urllib.request.urlopen(url, data=data, timeout=20) as response:
        result = json.load(response)
    if not result.get('ok'):
        raise RuntimeError(f'Telegram {method} failed')
    return result['result']


def discover_chat_id(token):
    updates = telegram_request(token, 'getUpdates')
    for update in reversed(updates):
        message = update.get('message') or update.get('edited_message') or {}
        chat = message.get('chat', {})
        if chat.get('type') == 'private':
            return str(chat['id'])
    return None


def read_new_matches(path, offset):
    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b'\n')
    if end < 0:
        return [], offset
    matches = [json.loads(line) for line in data[:end].splitlines() if line.strip()]
    return matches, offset + end + 1


def watch(path, token, chat_id=None, poll_seconds=5):
    offset = os.path.getsize(path) if os.path.exists(path) else 0
    while True:
        try:
            if chat_id is None:
                chat_id = discover_chat_id(token)
            matches, new_offset = read_new_matches(path, offset)
            if chat_id is not None:
                for best in matches:
                    message = notification_for(best, None)
                    if message:
                        telegram_request(token, 'sendMessage', {'chat_id': chat_id, 'text': message})
                offset = new_offset
        except (OSError, ValueError, RuntimeError) as error:
            print(f'{type(error).__name__}: {error}', flush=True)
        time.sleep(poll_seconds)


if __name__ == '__main__':
    watch(
        os.environ.get('BEST_FILE', '/root/best-safe.json'),
        os.environ['TELEGRAM_BOT_TOKEN'],
        os.environ.get('TELEGRAM_CHAT_ID'),
    )
