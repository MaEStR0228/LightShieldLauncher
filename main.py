import os
import subprocess
import sys
import json
import hashlib
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Tuple, Set, Optional
import base64
import shutil

from appdirs import user_data_dir
import minecraft_launcher_lib as mll
from PySide6.QtCore import Qt, QSize, QThread, Signal, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QMessageBox,
    QSpacerItem,
    QSizePolicy,
    QSpinBox, QFileDialog, QSlider, QCheckBox,
)
import socket
import time
import ctypes
import urllib.request
import logging
import traceback
from logging.handlers import RotatingFileHandler
import zipfile
import requests

# Импортируем менеджер вайтлиста
try:
    from whitelist_manager import whitelist_manager
    WHITELIST_AVAILABLE = True
except ImportError:
    WHITELIST_AVAILABLE = False
    logging.warning("Модуль вайтлиста не найден, проверка отключена")

# Импортируем систему обновлений
try:
    from github_updater import github_updater
    UPDATER_AVAILABLE = True
except ImportError:
    UPDATER_AVAILABLE = False
    logging.warning("Модуль обновлений не найден, обновления отключены")


LAUNCHER_NAME = "LightShieldLauncher"
MINECRAFT_VERSION = "1.21.5"
FABRIC_LOADER = None  # latest
SERVER_HOST = "107.161.154.240"
SERVER_PORT = 25594
FILES_ARCHIVE_URL = "https://drive.google.com/file/d/11ANG1nx9g7x7Dsyv34Rx1dtkp4WdFl4d/view?usp=sharing"

# Защита и шифрование отключены в новой версии. Все связанные механизмы не используются.


# Удалены функции шифрования/расшифрования. Они больше не используются.


def get_instance_root() -> Path:
    data_root = Path(user_data_dir(LAUNCHER_NAME, False))
    mc_root = data_root / "mc"
    mc_root.mkdir(parents=True, exist_ok=True)
    return mc_root


def sha1_of_file(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_launcher_settings(instance_root: Path) -> Dict[str, object]:
    settings_path = instance_root / "launcher_settings.json"
    defaults: Dict[str, object] = {"max_memory_gb": 4, "use_shaders": True, "nickname": ""}
    if settings_path.exists():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            for k in list(defaults.keys()):
                if k in data:
                    defaults[k] = data[k]
        except Exception:
            pass
    return defaults


def write_launcher_settings(instance_root: Path, settings: Dict[str, object]) -> None:
    settings_path = instance_root / "launcher_settings.json"
    try:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    settings_path.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8"
    )

def get_total_ram_gb() -> int:
    """Определение объёма физической памяти в ГБ (округление вниз)."""
    try:
        # Windows: GetPhysicallyInstalledSystemMemory returns KB
        kbytes = ctypes.c_ulonglong(0)
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll.kernel32, "GetPhysicallyInstalledSystemMemory"):
            if ctypes.windll.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(kbytes)):
                gb = int(kbytes.value // (1024 * 1024))  # to GB
                return max(gb, 1)
    except Exception:
        pass
    # Fallbacks
    try:
        import psutil  # type: ignore
        return max(int(psutil.virtual_memory().total // (1024**3)), 1)
    except Exception:
        return 8

###############################################
# Установка из локальной папки Installation files
###############################################

def _app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent

def get_installation_files_dir() -> Path:
    d = _app_base_dir() / "Installation files"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_installation_whitelist_dir() -> Path:
    d = get_installation_files_dir() / "whitelist"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_logs_dir() -> Path:
    d = _app_base_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _init_logging() -> None:
    """Инициализирует логирование лаунчера с ротацией файлов."""
    logs_dir = get_logs_dir()
    log_file = logs_dir / "launcher.log"
    logger = logging.getLogger()
    if logger.handlers:
        return  # уже настроено
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logging.info("Логирование инициализировано")

# --- простое шифрование для конфигов (обфускация от обычных пользователей) ---
def _secure_key() -> bytes:
    # Ключ фиксирован в коде, это обфускация, а не защита от злоумышленника
    seed = f"{LAUNCHER_NAME}:{MINECRAFT_VERSION}:CFGv1".encode("utf-8")
    return hashlib.sha1(seed).digest()  # 20 байт

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)

def _encrypt_bytes_to_b64(data: bytes) -> str:
    enc = _xor_bytes(data, _secure_key())
    return base64.b64encode(enc).decode("ascii")

def _decrypt_b64_to_bytes(text: str) -> bytes:
    raw = base64.b64decode(text.encode("ascii"))
    return _xor_bytes(raw, _secure_key())

def _get_secure_cfg_path() -> Path:
    return get_installation_whitelist_dir() / "secure_config.bin"

def _read_secure_config() -> Optional[Dict[str, object]]:
    p = _get_secure_cfg_path()
    if not p.exists():
        return None
    try:
        b64 = p.read_text(encoding="utf-8").strip()
        data = _decrypt_b64_to_bytes(b64)
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        logging.warning(f"Не удалось прочитать secure_config.bin: {e}")
        return None

def _bootstrap_secure_config() -> None:
    """Если существует шаблон secure_config.template.json — зашифровать его в secure_config.bin.
    Плейнтекстовые файлы-конфиги не трогаем, они остаются как fallback."""
    tpl = get_installation_whitelist_dir() / "secure_config.template.json"
    dst = _get_secure_cfg_path()
    if dst.exists() or not tpl.exists():
        return
    try:
        data = tpl.read_text(encoding="utf-8")
        b64 = _encrypt_bytes_to_b64(data.encode("utf-8"))
        dst.write_text(b64, encoding="utf-8")
        try:
            tpl.unlink(missing_ok=True)  # скрываем плейнтекст после успешного шифрования
        except Exception:
            pass
        logging.info("Создан secure_config.bin из шаблона и удалён шаблон")
    except Exception as e:
        logging.warning(f"Не удалось создать secure_config.bin: {e}")

# Удалены e-mail и троттлинг-структуры (не используются)

def report_event(subject: str, body: str) -> None:
    # Только локальный лог. Отправка в Discord отключена по требованию.
    logging.info(f"REPORT: {subject} — {body[:120]}")
    return

def _read_discord_cfg() -> Optional[Dict[str, object]]:
    """Читает настройки для Discord ТОЛЬКО из secure_config.bin."""
    try:
        sec = _read_secure_config()
        if sec and isinstance(sec.get("discord"), dict):
            return dict(sec["discord"])  # type: ignore[index]
    except Exception as e:
        logging.warning(f"Ошибка чтения secure_config для Discord: {e}")
    return None

def _fetch_discord_channel_text(channel_id: str, bot_token: str) -> Optional[str]:
    try:
        url = f"https://discord.com/api/v10/channels/{channel_id}/messages?limit=50"
        headers = {"Authorization": f"Bot {bot_token}"}
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code != 200:
            logging.error(f"Discord API status {r.status_code}: {r.text[:200]}")
            return None
        messages = r.json()
        # собираем тексты с конца, чтобы получить хронологию снизу-вверх
        texts = []
        for m in reversed(messages):
            content = m.get("content", "")
            if content:
                texts.append(content)
        return "\n".join(texts)
    except Exception as e:
        logging.error(f"Ошибка Discord API: {e}")
        return None

# Удалена отправка сообщений в Discord (не используется)

def _fetch_remote_text(url: str, timeout: float = 8.0) -> Optional[str]:
    try:
        logging.info(f"Попытка загрузки: {url}")
        if url.startswith("file:") or (os.path.isabs(url) and Path(url).exists()):
            # локальный файл (в т.ч. кэш из Discord)
            p = Path(url.replace("file://", "")) if url.startswith("file:") else Path(url)
            result = p.read_text(encoding="utf-8", errors="ignore")
            logging.info(f"Загружено из локального файла {p} — {len(result)} символов")
            return result
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
            result = data.decode("utf-8", errors="ignore")
            logging.info(f"Успешно загружено {len(result)} символов")
            return result
    except Exception as e:
        logging.error(f"Ошибка загрузки {url}: {e}")
        return None

def _fetch_remote_json(url: str, timeout: float = 12.0) -> Optional[Dict[str, object]]:
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code >= 300:
            logging.error(f"Ошибка загрузки JSON {url}: {r.status_code}")
            return None
        return r.json()
    except Exception as e:
        logging.error(f"Исключение при загрузке JSON {url}: {e}")
        return None

def _normalize_gdrive_url(url: str) -> str:
    """Приводит ссылки вида /file/d/<id>/view и open?id=<id> к uc?export=download&id=<id>."""
    try:
        if 'drive.google.com' not in url:
            return url
        # /file/d/<id>/view
        if '/file/d/' in url:
            start = url.find('/file/d/') + len('/file/d/')
            end = url.find('/', start)
            file_id = url[start:] if end == -1 else url[start:end]
            file_id = file_id.strip()
            if file_id:
                return f"https://drive.google.com/uc?export=download&id={file_id}"
        # open?id=<id>
        if 'open?id=' in url:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(url).query)
            file_id = (qs.get('id') or [''])[0]
            if file_id:
                return f"https://drive.google.com/uc?export=download&id={file_id}"
        return url
    except Exception:
        return url

def _gdrive_download(url: str, timeout: float = 30.0) -> Optional[bytes]:
    """Загрузка файлов Google Drive по ссылке uc?export=download&id=... c обработкой предупреждения."""
    try:
        url = _normalize_gdrive_url(url)
        with requests.Session() as s:
            resp = s.get(url, stream=True, timeout=timeout)
            if 'content-disposition' in resp.headers:
                return resp.content
            # ищем confirm токен
            token = None
            for k, v in resp.cookies.items():
                if k.startswith('download_warning'):
                    token = v
                    break
            if token:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = list(urlparse(url))
                qs = parse_qs(parsed[4])
                qs['confirm'] = token
                parsed[4] = urlencode({k: v if isinstance(v, str) else v[0] for k, v in qs.items()})
                url2 = urlunparse(parsed)
                resp2 = s.get(url2, stream=True, timeout=timeout)
                if 'content-disposition' in resp2.headers:
                    return resp2.content
            # если не получилось — пробуем как есть
            return resp.content
    except Exception as e:
        logging.error(f"Ошибка загрузки с Google Drive: {e}")
        return None

def _read_files_index_url() -> Optional[str]:
    try:
        sec = _read_secure_config()
        if sec and isinstance(sec.get("files_index_url"), str):
            url = str(sec["files_index_url"]).strip()
            return url or None
    except Exception:
        pass
    return None

def _read_files_archive_url() -> Optional[str]:
    try:
        sec = _read_secure_config()
        if sec and isinstance(sec.get("files_archive_url"), str):
            url = str(sec["files_archive_url"]).strip()
            return url or None
    except Exception:
        pass
    return None

# --- Новая установка: копирование из локальной папки ---
def _iter_installation_items() -> List[Tuple[Path, Path]]:
    """Возвращает пары (src, rel_path) для всех файлов в Installation files, исключая служебные папки."""
    src_root = get_installation_files_dir()
    pairs: List[Tuple[Path, Path]] = []
    exclude_dirs = {"whitelist", "__macosx"}
    for p in src_root.rglob("*"):
        if p.is_dir():
            # пропускаем служебные папки
            rel = p.relative_to(src_root)
            if rel.parts and rel.parts[0].lower() in exclude_dirs:
                continue
            continue
        rel = p.relative_to(src_root)
        if rel.parts and rel.parts[0].lower() in exclude_dirs:
            continue
        pairs.append((p, rel))
    return pairs

def _install_all_from_installation_files(instance_root: Path) -> Tuple[int, int]:
    """Локальный источник: копирует все файлы из Installation files. Возвращает (скопировано, всего)."""
    copied = 0
    items = _iter_installation_items()
    for src, rel in items:
        dst = instance_root / rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            # если файл отсутствует или отличается по размеру/хешу — копируем
            need_copy = True
            if dst.exists() and dst.is_file():
                try:
                    if dst.stat().st_size == src.stat().st_size and sha1_of_file(dst) == sha1_of_file(src):
                        need_copy = False
                except Exception:
                    need_copy = True
            if need_copy:
                dst.write_bytes(src.read_bytes())
                copied += 1
        except Exception as e:
            logging.error(f"Не удалось скопировать {src} → {dst}: {e}")
    return copied, len(items)

def _install_all_from_remote_index(instance_root: Path) -> Tuple[int, int]:
    """Удалённый источник: скачивает файлы по индексу files_index_url (из secure_config.bin)."""
    url = _read_files_index_url()
    if not url:
        return 0, 0
    index = _fetch_remote_json(url)
    if not index or not isinstance(index.get('files'), list):  # type: ignore[index]
        logging.error("Некорректный files_index.json")
        return 0, 0
    files: List[Dict[str, object]] = index['files']  # type: ignore[assignment]
    copied = 0
    for entry in files:
        try:
            rel = str(entry.get('path', '')).strip()
            src_url = str(entry.get('url', '')).strip()
            if not rel or not src_url:
                continue
            dst = instance_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            # проверка необходимости
            need = True
            expected_size = None
            expected_sha1 = None
            try:
                if 'size' in entry:
                    expected_size = int(entry['size'])  # type: ignore[index]
                if 'sha1' in entry and str(entry['sha1']).strip():
                    expected_sha1 = str(entry['sha1']).strip()
            except Exception:
                pass
            if dst.exists() and dst.is_file():
                try:
                    if expected_size is not None and dst.stat().st_size != expected_size:
                        need = True
                    elif expected_sha1 is not None and sha1_of_file(dst) != expected_sha1:
                        need = True
                    else:
                        need = False
                except Exception:
                    need = True
            if not need:
                continue
            # скачивание
            data = None
            if 'drive.google.com' in src_url:
                data = _gdrive_download(src_url)
            else:
                try:
                    r = requests.get(src_url, timeout=60)
                    if r.status_code < 300:
                        data = r.content
                except Exception as e:
                    logging.error(f"Ошибка скачивания {src_url}: {e}")
            if not data:
                logging.error(f"Не удалось скачать {src_url}")
                continue
            dst.write_bytes(data)
            copied += 1
        except Exception as e:
            logging.error(f"Ошибка установки файла из индекса: {e}")
    return copied, len(files)

def _install_all_from_remote_archive(instance_root: Path) -> Tuple[int, int]:
    """Удалённый источник: скачивает единый ZIP‑архив и распаковывает его в папку игры."""
    url = _read_files_archive_url()
    if not url:
        return 0, 0
    data: Optional[bytes] = None
    if 'drive.google.com' in url:
        data = _gdrive_download(url)
    else:
        try:
            r = requests.get(url, timeout=120)
            if r.status_code < 300:
                data = r.content
        except Exception as e:
            logging.error(f"Ошибка скачивания архива: {e}")
    if not data:
        logging.error("Архив не скачан")
        return 0, 0
    # распаковка
    tmp_zip = instance_root / "__remote_pack.zip"
    try:
        instance_root.mkdir(parents=True, exist_ok=True)
        tmp_zip.write_bytes(data)
        copied = 0
        with zipfile.ZipFile(tmp_zip, 'r') as zf:
            for info in zf.infolist():
                if info.is_dir():
                    # создадим директории
                    dst_dir = instance_root / info.filename
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    continue
                # файлы
                dst = instance_root / info.filename
                dst.parent.mkdir(parents=True, exist_ok=True)
                # если уже есть и совпадает по размеру — пропустим
                need = True
                try:
                    if dst.exists() and dst.stat().st_size == info.file_size:
                        need = False
                except Exception:
                    need = True
                if need:
                    with zf.open(info, 'r') as src, open(dst, 'wb') as out:
                        out.write(src.read())
                    copied += 1
        try:
            tmp_zip.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        return copied, len([i for i in zf.infolist() if not i.is_dir()])  # type: ignore[name-defined]
    except Exception as e:
        logging.error(f"Ошибка распаковки архива: {e}")
        try:
            tmp_zip.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        return 0, 0

def install_all_from_source(instance_root: Path) -> Tuple[int, int]:
    """Всегда ставим/обновляем с онлайна (Google Drive).
    1) Если задан files_archive_url — скачиваем ZIP и распаковываем
    2) Иначе если задан files_index_url — скачиваем по индексу
    3) Иначе — ничего не делаем (локальный источник отключён)
    """
    if _read_files_archive_url():
        return _install_all_from_remote_archive(instance_root)
    if _read_files_index_url():
        return _install_all_from_remote_index(instance_root)
    logging.error("Не настроены files_archive_url/files_index_url. Установка из локальной папки отключена.")
    return 0, 0

def download_and_extract_archive(instance_root: Path, url: str) -> Tuple[int, int]:
    """Скачивает единый ZIP‑архив по ссылке (Google Drive поддерживается) и распаковывает в папку игры.
    Возвращает (скопировано_файлов, всего_файлов)."""
    data: Optional[bytes] = None
    if 'drive.google.com' in url:
        data = _gdrive_download(url)
    else:
        try:
            r = requests.get(url, timeout=120)
            if r.status_code < 300:
                data = r.content
        except Exception as e:
            logging.error(f"Ошибка скачивания архива: {e}")
    # Подготовим локальный fallback
    local_zip = _app_base_dir() / "Installation files" / "Installation files.zip"
    def _read_local_zip_bytes() -> Optional[bytes]:
        try:
            if local_zip.exists() and local_zip.is_file():
                return local_zip.read_bytes()
        except Exception as e:
            logging.warning(f"Не удалось прочитать локальный архив: {e}")
        return None

    # Проверка: получили ли мы настоящий zip
    if not data:
        data = _read_local_zip_bytes()
        if not data:
            raise Exception("Не удалось скачать архив с файлами и не найден локальный 'Installation files/Installation files.zip'")
    else:
        # Иногда Google Drive возвращает HTML (требуется вход) — распознаём по сигнатуре zip
        if not (len(data) >= 4 and data[:2] == b'PK'):
            logging.warning("Получены не zip-данные (возможно, требуется доступ к Google Drive). Пробуем локальный архив.")
            alt = _read_local_zip_bytes()
            if alt is not None:
                data = alt
            else:
                raise Exception("Ссылка Google Drive не даёт прямой доступ (возможно, требуется авторизация). Сделайте файл доступным по ссылке или положите локально 'Installation files/Installation files.zip'.")

    # Кэшируем скачанный архив локально для последующих запусков
    try:
        local_zip.parent.mkdir(parents=True, exist_ok=True)
        # Перезапишем, если размера нет или отличается
        if not local_zip.exists() or local_zip.stat().st_size != len(data):
            local_zip.write_bytes(data)
    except Exception as e:
        logging.warning(f"Не удалось записать локальный кэш архива: {e}")
    tmp_zip = instance_root / "__pack.zip"
    copied = 0
    try:
        instance_root.mkdir(parents=True, exist_ok=True)
        tmp_zip.write_bytes(data)
        with zipfile.ZipFile(tmp_zip, 'r') as zf:
            file_infos = [i for i in zf.infolist() if not i.is_dir()]
            for info in zf.infolist():
                if info.is_dir():
                    (instance_root / info.filename).mkdir(parents=True, exist_ok=True)
                    continue
                dst = instance_root / info.filename
                dst.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, 'r') as src, open(dst, 'wb') as out:
                    out.write(src.read())
                copied += 1
        try:
            tmp_zip.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        return copied, len(file_infos)
    except Exception as e:
        try:
            tmp_zip.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        raise

def clean_instance_root(instance_root: Path) -> None:
    """Чистая установка: удаляет пользовательские файлы (моды/ресурспаки/конфиги и т.п.),
    но сохраняет ядро Minecraft (versions/assets/libraries/natives), чтобы не переустанавливать клиент."""
    if not instance_root.exists():
        return
    keep = {"versions", "assets", "libraries", "natives"}
    for child in instance_root.iterdir():
        name_lower = child.name.lower()
        if name_lower in keep:
            continue
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception as e:
            logging.warning(f"Не удалось удалить {child}: {e}")

def is_initial_install_done(instance_root: Path) -> bool:
    return (instance_root / "installed.flag").exists()

def mark_initial_install_done(instance_root: Path) -> None:
    (instance_root / "installed.flag").write_text("ok", encoding="utf-8")


def _ensure_game_directories(instance_root: Path) -> None:
    """Создаёт базовые папки, если их нет."""
    directories = ["mods", "resourcepacks", "shaderpacks"]
    for dir_name in directories:
        dir_path = instance_root / dir_name
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"Создана папка: {dir_path}")


def build_allowlist_from_remote_drive() -> Dict[str, str]:
    """Не используется: возвращает пустой словарь в новой схеме."""
    return {}


def build_allowlist_from_installation() -> Dict[str, str]:
    """Не используется: возвращает пустой словарь в новой схеме."""
    return {}


def write_allowlist_files(instance_root: Path) -> None:
    pass


def get_whitelist_dir(instance_root: Path) -> Path:
    # Больше не используем локальный whitelist в игре
    return instance_root / "whitelist"


def get_whitelist_file(instance_root: Path) -> Path:
    return get_whitelist_dir(instance_root) / "mods_whitelist.txt"


def get_resourcepacks_whitelist_file(instance_root: Path) -> Path:
    return get_whitelist_dir(instance_root) / "resourcepacks_whitelist.txt"


def get_nick_whitelist_file(instance_root: Path) -> Path:
    return get_whitelist_dir(instance_root) / "nicks_whitelist.txt"


def _load_remote_whitelist_url(kind: str) -> Optional[str]:
    # env overrides
    env_map = {
        "mods": os.environ.get("LS_REMOTE_MODS_WHITELIST"),
        "resourcepacks": os.environ.get("LS_REMOTE_RP_WHITELIST"),
        "nicks": os.environ.get("LS_REMOTE_NICKS_WHITELIST"),
    }
    if env_map.get(kind):
        print(f"Найден env URL для {kind}: {env_map[kind]}")
        return env_map[kind]
    # сначала пробуем secure_config.bin
    try:
        sec = _read_secure_config()
        if sec and isinstance(sec.get("whitelist_urls"), dict):
            url = sec["whitelist_urls"].get(kind)  # type: ignore[index]
            if isinstance(url, str) and url.strip():
                return url.strip()
    except Exception:
        pass
    # удалён fallback на remote_whitelist_urls.json
    # Альтернатива: читать из Discord-канала
    dc = _read_discord_cfg()
    if dc and isinstance(dc.get("channels", {}), dict):
        # поддержка плоских полей для удобства
        ch_map = dict(dc.get("channels", {}))
        for key in ["nicks", "mods", "resourcepacks", "shaderpacks"]:
            if key in dc and key not in ch_map:
                ch_map[key] = dc.get(key)
        token = str(dc.get("bot_token", "")).strip()
        channel_id = ch_map.get(kind)
        if token and channel_id:
            txt = _fetch_discord_channel_text(str(channel_id), token)
            if txt is not None:
                # Сохраняем в кэш-файл и возвращаем file:// URL
                cache_dir = get_installation_whitelist_dir()
                cache_file = cache_dir / f"{kind}_from_discord.txt"
                try:
                    cache_file.write_text(txt, encoding="utf-8")
                    return str(cache_file)
                except Exception as e:
                    logging.warning(f"Не удалось записать кэш Discord для {kind}: {e}")
    return None


def read_mods_whitelist(instance_root: Path) -> Set[str]:
    return set()


def read_mods_whitelist_with_size(instance_root: Path) -> Dict[str, Optional[int]]:
    """Считывает вайтлист модов из удалённого URL (или локального файла). Формат строк:
    name.jar[, size_in_bytes]
    Возвращает: имя (lower) -> ожидаемый размер (или None).
    """
    remote_url = _load_remote_whitelist_url("mods")
    if remote_url:
        txt = _fetch_remote_text(remote_url)
        if txt is not None:
            mapping: Dict[str, Optional[int]] = {}
            try:
                for line in txt.splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    parts = [p.strip() for p in s.split(',')]
                    name = parts[0].lower()
                    size_val: Optional[int] = None
                    if len(parts) >= 2:
                        try:
                            size_val = int(parts[1])
                        except Exception:
                            size_val = None
                    mapping[name] = size_val
                return mapping
            except Exception:
                pass
    # локальный fallback (в инстансе)
    wl_file = get_whitelist_file(instance_root)
    if wl_file.exists():
        mapping: Dict[str, Optional[int]] = {}
        try:
            for line in wl_file.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                parts = [p.strip() for p in s.split(',')]
                name = parts[0].lower()
                size_val: Optional[int] = None
                if len(parts) >= 2:
                    try:
                        size_val = int(parts[1])
                    except Exception:
                        size_val = None
                mapping[name] = size_val
        except Exception:
            pass
        return mapping
    return {}


def read_resourcepacks_whitelist(instance_root: Path) -> Set[str]:
    return set()


def read_resourcepacks_whitelist_with_size(instance_root: Path) -> Dict[str, Optional[int]]:
    """Считывает вайтлист ресурспаков, формат: name.zip[, size]"""
    remote_url = _load_remote_whitelist_url("resourcepacks")
    if remote_url:
        txt = _fetch_remote_text(remote_url)
        if txt is not None:
            mapping: Dict[str, Optional[int]] = {}
            try:
                for line in txt.splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    parts = [p.strip() for p in s.split(',')]
                    name = parts[0].lower()
                    size_val: Optional[int] = None
                    if len(parts) >= 2:
                        try:
                            size_val = int(parts[1])
                        except Exception:
                            size_val = None
                    mapping[name] = size_val
                return mapping
            except Exception:
                pass
    wl_file = get_resourcepacks_whitelist_file(instance_root)
    if wl_file.exists():
        mapping: Dict[str, Optional[int]] = {}
        try:
            for line in wl_file.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                parts = [p.strip() for p in s.split(',')]
                name = parts[0].lower()
                size_val: Optional[int] = None
                if len(parts) >= 2:
                    try:
                        size_val = int(parts[1])
                    except Exception:
                        size_val = None
                mapping[name] = size_val
        except Exception:
            pass
        return mapping
    return {}

def read_shaderpacks_whitelist_with_size(instance_root: Path) -> Dict[str, Optional[int]]:
    """Считывает вайтлист шейдерпаков (опционально), формат: name.zip|jar[, size]. Если нет — возвращает пустой словарь."""
    remote_url = _load_remote_whitelist_url("shaderpacks")
    if remote_url:
        txt = _fetch_remote_text(remote_url)
        if txt is not None:
            mapping: Dict[str, Optional[int]] = {}
            try:
                for line in txt.splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    parts = [p.strip() for p in s.split(',')]
                    name = parts[0].lower()
                    size_val: Optional[int] = None
                    if len(parts) >= 2:
                        try:
                            size_val = int(parts[1])
                        except Exception:
                            size_val = None
                    mapping[name] = size_val
                return mapping
            except Exception:
                pass
    return {}

def _installation_catalog_names(category: str) -> Set[str]:
    """Список имён (lower) файлов из Installation files/<category>."""
    root = get_installation_files_dir() / category
    names: Set[str] = set()
    if root.exists():
        for p in root.iterdir():
            if p.is_file():
                names.add(p.name.lower())
    return names


def read_nick_whitelist(instance_root: Path) -> Set[str]:
    """Return set of allowed nicknames (case-insensitive)."""
    # Пытаемся загрузить удалённый вайтлист ников
    remote_url = _load_remote_whitelist_url("nicks")
    if remote_url:
        print(f"Загружаем вайтлист ников с: {remote_url}")
        txt = _fetch_remote_text(remote_url)
        if txt is not None:
            try:
                allowed = {line.strip().lower() for line in txt.splitlines() if line.strip() and not line.strip().startswith('#')}
                print(f"Загружено ников из онлайн-вайтлиста: {len(allowed)}")
                return allowed
            except Exception as e:
                print(f"Ошибка парсинга онлайн-вайтлиста ников: {e}")
        else:
            print("Не удалось загрузить онлайн-вайтлист ников")
    else:
        print("URL для онлайн-вайтлиста ников не найден")
    
    # Fallback к локальному файлу (если существует)
    wl_file = get_nick_whitelist_file(instance_root)
    if wl_file.exists():
        allowed: Set[str] = set()
        try:
            for line in wl_file.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                allowed.add(s.lower())
        except Exception:
            pass
        print(f"Загружено ников из локального файла: {len(allowed)}")
        return allowed
    # Если локального файла нет, возвращаем пустой список
    print("Локальный файл вайтлиста ников не найден")
    return set()


# --- track user-added files ---
def get_user_added_file(instance_root: Path) -> Path:
    return instance_root / "user_added.json"


def read_user_added(instance_root: Path) -> Dict[str, List[str]]:
    p = get_user_added_file(instance_root)
    if not p.exists():
        return {"mods": [], "resourcepacks": [], "shaderpacks": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return {
            "mods": list({x.lower() for x in data.get("mods", [])}),
            "resourcepacks": list({x.lower() for x in data.get("resourcepacks", [])}),
            "shaderpacks": list({x.lower() for x in data.get("shaderpacks", [])}),
        }
    except Exception:
        return {"mods": [], "resourcepacks": [], "shaderpacks": []}


def write_user_added(instance_root: Path, data: Dict[str, List[str]]) -> None:
    p = get_user_added_file(instance_root)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def track_user_added(instance_root: Path, category: str, filenames: List[str]) -> None:
    data = read_user_added(instance_root)
    bucket = data.get(category, [])
    present = set(x.lower() for x in bucket)
    for name in filenames:
        lower = name.lower()
        if lower not in present:
            bucket.append(lower)
            present.add(lower)
    data[category] = bucket
    write_user_added(instance_root, data)


###############################################
# Защита отключена — no-op функции для совместимости
###############################################

def protect_game_assets(instance_root: Path) -> None:
    return

def unprotect_game_assets(instance_root: Path) -> None:
    return


def find_installed_fabric_id(instance_root: Path) -> str | None:
    minecraft_dir = str(instance_root)
    try:
        installed_versions = mll.utils.get_installed_versions(minecraft_dir)
    except Exception:
        return None
    installed_ids = [str(v.get("id", "")) for v in installed_versions]
    if not installed_ids:
        return None
    # 1) классический id fabric-loader-…-<mc_version>
    candidates = [vid for vid in installed_ids if vid.startswith("fabric-loader-") and vid.endswith(f"-{MINECRAFT_VERSION}")]
    if candidates:
        candidates.sort()
        return candidates[-1]
    # 2) нестандартные id с упоминанием fabric и версии
    cand2 = [vid for vid in installed_ids if ("fabric" in vid.lower() and MINECRAFT_VERSION in vid)]
    if cand2:
        cand2.sort()
        return cand2[-1]
    # 3) любая версия, где есть номер версии
    cand3 = [vid for vid in installed_ids if MINECRAFT_VERSION in vid]
    if cand3:
        cand3.sort()
        return cand3[-1]
    # 4) fallback: первый установленный id
    return installed_ids[-1]


def ensure_version_and_fabric(instance_root: Path, callback: Dict[str, callable] | None = None) -> Tuple[str, str]:
    """Устанавливает Minecraft версию через minecraft-launcher-lib. Возвращает (version_id, game_dir)."""
    minecraft_dir = str(instance_root)
    
    # Создаем папки
    (Path(minecraft_dir) / "versions").mkdir(parents=True, exist_ok=True)
    
    logging.info("Устанавливаем Minecraft через minecraft-launcher-lib")
    
    try:
        # Получаем список версий
        version_list = mll.utils.get_version_list()
        logging.info(f"Доступных версий: {len(version_list)}")
        
        # Ищем версию 1.21.5 или любую стабильную
        target_version = None
        for version in version_list:
            if version.get("id") == "1.21.5":
                target_version = version
                break
        
        # Если 1.21.5 не найдена, ищем стабильную версию
        if not target_version:
            for version in version_list:
                if version.get("type") == "release":
                    target_version = version
                    break
        
        # Если стабильной нет, берем первую
        if not target_version and version_list:
            target_version = version_list[0]
        
        if not target_version:
            raise Exception("Не найдена подходящая версия")
        
        version_id = target_version.get("id")
        logging.info(f"Устанавливаем версию: {version_id}")
        
        # Используем официальный метод установки из документации
        mll.install.install_minecraft_version(version_id, minecraft_dir, callback=None)
        
        logging.info(f"Версия {version_id} установлена успешно")
        
        return version_id, minecraft_dir
        
    except Exception as e:
        logging.error(f"Ошибка установки: {e}")
        raise


def _get_java_executable(game_dir: str) -> str:
    # 1) Попробуем API библиотеки (если доступно в текущей версии)
    try:
        if hasattr(mll, "runtime"):
            jre = mll.runtime.get_executable_path("java-runtime-gamma", game_dir) or mll.runtime.get_executable_path("java-runtime-beta", game_dir)  # type: ignore[attr-defined]
            if jre:
                return jre
    except Exception:
        pass
    # 2) JAVA_HOME/bin/java(.exe)
    try:
        java_home = os.environ.get("JAVA_HOME", "").strip()
        if java_home:
            cand = Path(java_home) / "bin" / ("javaw.exe" if os.name == "nt" else "java")
            if cand.exists():
                return str(cand)
            cand = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
            if cand.exists():
                return str(cand)
    except Exception:
        pass
    # 3) Встроенные рантаймы внутри папки игры (архив может содержать свою Java)
    try:
        root = Path(game_dir)
        search_dirs = [root / "runtime", root]
        for base in search_dirs:
            if not base.exists():
                continue
            # Ищем javaw.exe / java.exe на Windows, иначе 'java'
            patterns = ["javaw.exe", "java.exe"] if os.name == "nt" else ["java"]
            for pat in patterns:
                found = next(base.rglob(pat), None)
                if found and found.exists():
                    return str(found)
    except Exception:
        pass
    # 4) Системная java в PATH
    return "java"


def _patch_mll_get_libraries_for_classifiers() -> None:
    """Патчит minecraft_launcher_lib.command.get_libraries и install.install_libraries, чтобы поддерживать координаты с 4 частями
    (group:artifact:version:classifier), из-за которых падает старая версия библиотеки.
    Безопасно вызывается много раз.
    """
    # Патчим command.get_libraries
    try:
        import minecraft_launcher_lib.command as mll_cmd  # type: ignore
    except Exception:
        pass
    else:
        if not getattr(mll_cmd, "__ls_patched__", False):
            orig = getattr(mll_cmd, "get_libraries", None)
            if callable(orig):
                import os as _os
                from pathlib import Path as _Path

                def _patched_get_libraries(data, path):  # type: ignore[override]
                    try:
                        libraries = list(data.get("libraries", []))
                    except Exception:
                        return orig(data, path)
                    sep = ";" if _os.name == "nt" else ":"
                    classpath_items = []
                    for lib in libraries:
                        try:
                            coords = str(lib.get("name", "")).strip().split(":")
                            if len(coords) < 3:
                                continue
                            group, artifact, version = coords[0], coords[1], coords[2]
                            classifier = coords[3] if len(coords) >= 4 else None
                            base = _Path(path) / "libraries" / _Path(group.replace(".", "/")) / artifact / version
                            jar_name = f"{artifact}-{version}{('-' + classifier) if classifier else ''}.jar"
                            jar_path = base / jar_name
                            if jar_path.exists():
                                classpath_items.append(str(jar_path))
                        except Exception:
                            continue
                    return sep.join(classpath_items)

                mll_cmd.get_libraries = _patched_get_libraries  # type: ignore[assignment]
                mll_cmd.__ls_patched__ = True  # type: ignore[attr-defined]

    # Патчим install.install_libraries
    try:
        import minecraft_launcher_lib.install as mll_install  # type: ignore
    except Exception:
        pass
    else:
        if not getattr(mll_install, "__ls_patched__", False):
            orig_install = getattr(mll_install, "install_libraries", None)
            if callable(orig_install):
                def _patched_install_libraries(versiondata, path, callback):
                    try:
                        libraries = list(versiondata.get("libraries", []))
                    except Exception:
                        return orig_install(versiondata, path, callback)
                    
                    # Создаем исправленную версию данных
                    fixed_versiondata = dict(versiondata)
                    fixed_libraries = []
                    
                    for lib in libraries:
                        try:
                            coords = str(lib.get("name", "")).strip().split(":")
                            if len(coords) < 3:
                                fixed_libraries.append(lib)
                                continue
                            # Используем только первые 3 части для совместимости
                            group, artifact, version = coords[0], coords[1], coords[2]
                            # Создаем исправленный объект библиотеки
                            fixed_lib = dict(lib)
                            fixed_lib["name"] = f"{group}:{artifact}:{version}"
                            fixed_libraries.append(fixed_lib)
                        except Exception:
                            fixed_libraries.append(lib)
                    
                    fixed_versiondata["libraries"] = fixed_libraries
                    # Вызываем оригинальную функцию с исправленными данными
                    return orig_install(fixed_versiondata, path, callback)

                mll_install.install_libraries = _patched_install_libraries  # type: ignore[assignment]
                mll_install.__ls_patched__ = True  # type: ignore[attr-defined]

def _install_fabric_manual(
    minecraft_dir: str,
    mc_version: str,
    loader_version: Optional[str],
    callback: Dict[str, callable] | None,
    download_minecraft: bool = False,
) -> Optional[str]:
    try:
        # 1) Узнаём версии installer и loader с meta.fabricmc.net
        installer_ver = None
        try:
            lst = _fetch_remote_json("https://meta.fabricmc.net/v2/versions/installer") or []  # type: ignore[assignment]
            # Берём первый стабильный, иначе первый элемент
            stable = [x for x in lst if x.get("stable")]  # type: ignore[union-attr]
            installer_ver = (stable[0] if stable else (lst[0] if lst else {})).get("version")  # type: ignore[index]
        except Exception:
            pass
        if not installer_ver:
            installer_ver = "1.0.0"  # запасное значение; реальный мейвен вернёт 404 если нет

        if not loader_version:
            try:
                lv = _fetch_remote_json(f"https://meta.fabricmc.net/v2/versions/loader/{mc_version}") or []  # type: ignore[assignment]
                stable = [x for x in lv if x.get("loader", {}).get("stable")]  # type: ignore[union-attr]
                chosen = (stable[0] if stable else (lv[0] if lv else {}))
                loader_version = chosen.get("loader", {}).get("version")  # type: ignore[assignment]
            except Exception:
                loader_version = None

        # 2) Скачиваем installer JAR
        jar_url = f"https://maven.fabricmc.net/net/fabricmc/fabric-installer/{installer_ver}/fabric-installer-{installer_ver}.jar"
        tmp_dir = Path(minecraft_dir)
        tmp_dir.mkdir(parents=True, exist_ok=True)
        jar_path = tmp_dir / f"fabric-installer-{installer_ver}.jar"
        # Если уже скачан — не перезагружаем лишний раз
        if not jar_path.exists() or jar_path.stat().st_size == 0:
            if callback and callable(callback.get("setStatus")):
                try:
                    callback["setStatus"]("Скачивание Fabric installer")
                except Exception:
                    pass
            r = requests.get(jar_url, timeout=60)
            if r.status_code >= 300:
                raise Exception(f"Не удалось скачать Fabric installer: HTTP {r.status_code}")
            jar_path.write_bytes(r.content)

        # 3) Запускаем installer в режиме client (фоновый режим)
        if callback and callable(callback.get("setStatus")):
            try:
                callback["setStatus"]("Установка Fabric")
            except Exception:
                pass
        java = _get_java_executable(minecraft_dir)
        base_cmd = [java, "-jar", str(jar_path), "client", "-dir", minecraft_dir, "-mcversion", mc_version, "-noprofile"]
        if download_minecraft:
            base_cmd += ["-downloadMinecraft"]
        # Попробуем сначала без явного -loader, чтобы installer сам подобрал совместимую версию
        attempts = []
        attempts.append(list(base_cmd))
        if loader_version:
            attempts.append(list(base_cmd) + ["-loader", str(loader_version)])
        # В случае сбоя с выбранной java попробуем системную
        attempts_sys = [["java"] + a[1:] for a in attempts]
        attempts += attempts_sys
        last_err = None
        for cmd in attempts:
            try:
                # Запускаем в фоновом режиме с перенаправлением вывода
                if os.name == "nt":  # Windows
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, 
                                       startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW)
                else:  # Linux/Mac
                    res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                logging.info(f"Fabric installer OK: {' '.join(cmd)}\n{res.stdout[-500:]}" )
                last_err = None
                break
            except subprocess.CalledProcessError as e:
                last_err = f"Installer failed (code {e.returncode}) for: {' '.join(cmd)}\nSTDERR: {e.stderr[-800:]}\nSTDOUT: {e.stdout[-400:]}"
                logging.error(last_err)
                continue
            except Exception as e:
                last_err = f"Installer exception for: {' '.join(cmd)} — {e}"
                logging.error(last_err)
                continue
        if last_err:
            raise Exception(last_err)

        # 4) Удаляем installer и возвращаем установленный id
        try:
            jar_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        # Выбираем установленный профиль
        installed = mll.utils.get_installed_versions(minecraft_dir)
        ids = {v.get("id", "") for v in installed}
        candidates = [vid for vid in ids if vid.startswith("fabric-loader-") and vid.endswith(f"-{mc_version}")]
        if not candidates:
            return None
        candidates.sort()
        return candidates[-1]
    except Exception as e:
        raise Exception(f"Ошибка установки Fabric: {e}")


class InstallThread(QThread):
    sig_status = Signal(str)
    sig_progress = Signal(int)
    sig_max = Signal(int)
    sig_error = Signal(str)
    sig_done = Signal(str, str)  # version_id, game_dir

    def __init__(self, instance_root: Path):
        super().__init__()
        self.instance_root = instance_root

    def _translate_status(self, eng: str) -> str:
        # Простые переводы статусов установки
        mapping = {
            "Download": "Скачивание",
            "Install": "Установка", 
            "Extract": "Распаковка",
            "Install java runtime": "Установка Java",
            "Download cacerts": "Скачивание сертификатов",
            "Download assets": "Скачивание ресурсов",
            "Download libraries": "Скачивание библиотек",
            "Download natives": "Скачивание нативных файлов",
            "Download minecraft": "Скачивание Minecraft",
            "Download fabric": "Скачивание Fabric",
            "Validate": "Проверка",
            "Validate assets": "Проверка ресурсов",
            "Validate libraries": "Проверка библиотек",
        }
        # Сначала пробуем точные совпадения
        for key, ru in mapping.items():
            if eng.lower().startswith(key.lower()):
                return eng.replace(key, ru)
        
        # Если не нашли точное совпадение, ищем частичные
        for key, ru in mapping.items():
            if key.lower() in eng.lower():
                return eng.replace(key, ru)
        
        return eng

    def run(self):
        try:
            self.sig_status.emit("Подготовка установки...")
            def _cb_set_status(*args, **kwargs):
                s = kwargs.get("status") if "status" in kwargs else (args[0] if args else "")
                self.sig_status.emit(self._translate_status(str(s)))

            def _extract_int_from_args(args) -> int:
                for a in reversed(args):
                    try:
                        return int(a)
                    except Exception:
                        continue
                return 0

            def _cb_set_progress(*args, **kwargs):
                try:
                    val = int(kwargs.get("value")) if "value" in kwargs else _extract_int_from_args(args)
                except Exception:
                    val = 0
                self.sig_progress.emit(int(val))

            def _cb_set_max(*args, **kwargs):
                try:
                    val = int(kwargs.get("max")) if "max" in kwargs else _extract_int_from_args(args)
                except Exception:
                    val = 0
                self.sig_max.emit(int(val))

            # Не передаём callback внутрь библиотеки, чтобы избежать ошибок коллбеков
            callback = None
            # Обновляем статус сами
            _cb_set_status(status="Установка Minecraft 1.21.5/Fabric")
            version_id, game_dir = ensure_version_and_fabric(self.instance_root, callback)
            logging.info(f"Установлена версия: {version_id}")
            
            # Проверяем что установилось
            installed_versions = mll.utils.get_installed_versions(game_dir)
            logging.info(f"Установленные версии: {[v.get('id') for v in installed_versions]}")
            
            # Проверяем директории
            natives_dir = Path(game_dir) / "natives"
            assets_dir = Path(game_dir) / "assets"
            logging.info(f"Папка natives существует: {natives_dir.exists()}")
            logging.info(f"Папка assets существует: {assets_dir.exists()}")
            
            self.sig_done.emit(version_id, game_dir)
        except Exception as e:
            tb = traceback.format_exc()
            logging.exception("Ошибка в потоке установки")
            self.sig_error.emit(f"{e}\n\n{tb}")


class CopyFilesThread(QThread):
    sig_status = Signal(str)
    sig_progress = Signal(int)
    sig_max = Signal(int)
    sig_error = Signal(str)
    sig_done = Signal()

    def __init__(self, instance_root: Path):
        super().__init__()
        self.instance_root = instance_root

    def run(self):
        try:
            self.sig_status.emit("Подготовка копирования файлов...")
            
            # Получаем путь к папке Installation files
            installation_files_dir = get_installation_files_dir()
            
            if not installation_files_dir.exists():
                raise Exception(f"Папка Installation files не найдена: {installation_files_dir}")
            
            # Список папок для копирования
            folders_to_copy = [
                "assets",
                "libraries", 
                "versions",
                "mods",
                "config",
                "resourcepacks",
                "shaderpacks",
                "saves",
                "data",
                "defaultconfigs",
                "server-resource-packs",
                "emotes"
            ]
            
            # Список файлов для копирования
            files_to_copy = [
                "options.txt"
            ]
            
            total_items = len(folders_to_copy) + len(files_to_copy)
            copied_items = 0
            
            self.sig_max.emit(total_items)
            
            # Копируем папки
            for folder_name in folders_to_copy:
                src_folder = installation_files_dir / folder_name
                dst_folder = self.instance_root / folder_name
                
                if src_folder.exists():
                    self.sig_status.emit(f"Копирование папки {folder_name}...")
                    
                    # Создаем папку назначения
                    dst_folder.mkdir(parents=True, exist_ok=True)
                    
                    # Копируем содержимое папки
                    self._copy_folder_contents(src_folder, dst_folder)
                    
                    copied_items += 1
                    self.sig_progress.emit(copied_items)
                else:
                    logging.warning(f"Папка {folder_name} не найдена в Installation files")
            
            # Копируем файлы
            for file_name in files_to_copy:
                src_file = installation_files_dir / file_name
                dst_file = self.instance_root / file_name
                
                if src_file.exists():
                    self.sig_status.emit(f"Копирование файла {file_name}...")
                    
                    # Создаем папку назначения если нужно
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Копируем файл
                    shutil.copy2(src_file, dst_file)
                    
                    copied_items += 1
                    self.sig_progress.emit(copied_items)
                else:
                    logging.warning(f"Файл {file_name} не найден в Installation files")
            
            self.sig_status.emit("Копирование завершено")
            logging.info(f"Скопировано {copied_items} элементов из Installation files")
            self.sig_done.emit()
            
        except Exception as e:
            tb = traceback.format_exc()
            logging.exception("Ошибка в потоке копирования файлов")
            self.sig_error.emit(f"{e}\n\n{tb}")

    def _copy_folder_contents(self, src: Path, dst: Path):
        """Рекурсивно копирует содержимое папки"""
        for item in src.iterdir():
            src_path = src / item.name
            dst_path = dst / item.name
            
            if item.is_dir():
                dst_path.mkdir(exist_ok=True)
                self._copy_folder_contents(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)


class UpdateCheckThread(QThread):
    """Поток для проверки обновлений"""
    sig_updates_found = Signal(bool, bool, str, str)  # launcher_update, files_update, launcher_version, files_version
    sig_no_updates = Signal()
    sig_error = Signal(str)
    
    def run(self):
        try:
            if UPDATER_AVAILABLE:
                launcher_update, latest_version, latest_files_version = github_updater.check_for_updates()
                
                if launcher_update or latest_files_version:
                    self.sig_updates_found.emit(launcher_update, bool(latest_files_version), latest_version or "", latest_files_version or "")
                else:
                    self.sig_no_updates.emit()
            else:
                self.sig_error.emit("Модуль обновлений недоступен")
        except Exception as e:
            logging.exception("Ошибка в потоке проверки обновлений")
            self.sig_error.emit(str(e))


class DownloadThread(QThread):
    """Поток для скачивания обновлений"""
    sig_progress = Signal(int)
    sig_complete = Signal()
    sig_error = Signal(str)
    
    def __init__(self, update_type: str):
        super().__init__()
        self.update_type = update_type
    
    def run(self):
        try:
            if self.update_type == "launcher":
                # Скачиваем обновление лаунчера
                success = github_updater.download_launcher_update("LightShieldLauncher_new.exe")
                if success:
                    self.sig_complete.emit()
                else:
                    self.sig_error.emit("Не удалось скачать обновление лаунчера")
            
            elif self.update_type == "files":
                # Скачиваем обновление файлов
                success = github_updater.download_files_update("Installation files")
                if success:
                    self.sig_complete.emit()
                else:
                    self.sig_error.emit("Не удалось скачать обновление файлов")
            
        except Exception as e:
            logging.exception("Ошибка в потоке скачивания")
            self.sig_error.emit(str(e))


def sync_packs_and_validate(instance_root: Path) -> Tuple[bool, List[str]]:
    """Новая логика: просто копируем недостающие/обновлённые файлы из Installation files. Никакой валидации."""
    _ensure_game_directories(instance_root)
    copied, total = install_all_from_source(instance_root)
    print(f"Синхронизация из Installation files: скопировано {copied}/{total}")
    return True, []


def delete_foreign_files(instance_root: Path) -> None:
    """В новой схеме ничего не удаляем автоматически."""
    return





class LauncherWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Light Shield")
        self.setWindowIcon(QIcon())
        # Размер под правый лаунчер (примерно)
        self.setFixedSize(420, 760)
        # Кнопки: закрыть и свернуть; без разворота на весь экран
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint | Qt.MSWindowsFixedSizeDialogHint)
        self.setStyleSheet(self._style())

        # ВАЖНО: инициализируем корень и настройки до использования ниже
        self.instance_root = get_instance_root()
        self.launcher_settings = read_launcher_settings(self.instance_root)
        
        # Проверяем, первый ли это запуск
        self.is_first_run = not self._is_installation_complete()

        # header logo + buttons dummy
        logo = QLabel("LS")
        logo.setObjectName("logo")

        self.nickname = QLineEdit()
        self.nickname.setPlaceholderText("Ник")
        # заполняем сохранённым ником (с безопасным fallback)
        try:
            saved_nick = str(self.launcher_settings.get("nickname", "")).strip()
        except Exception:
            try:
                _ir = get_instance_root()
                _ls = read_launcher_settings(_ir)
                self.instance_root = getattr(self, "instance_root", _ir)
                self.launcher_settings = _ls
                saved_nick = str(_ls.get("nickname", "")).strip()
            except Exception:
                saved_nick = ""
        if saved_nick:
            self.nickname.setText(saved_nick)
        # Кнопки добавления модов/ресурспаков/шейдеров перенесены в настройки

        self.discord_btn = QPushButton("Дискорд")
        self.discord_btn.setObjectName("discordBtn")
        self.discord_btn.clicked.connect(self.on_discord)

        self.settings_btn = QPushButton("Настройки")
        self.settings_btn.clicked.connect(self.on_settings)

        # Создаем динамическую кнопку - "Установка" для первого запуска, "Играть" для последующих
        self.play_btn = QPushButton("Установка" if self.is_first_run else "Играть")
        self.play_btn.clicked.connect(self.on_install if self.is_first_run else self.on_play)
        
        # Если это первый запуск, делаем кнопку красной
        if self.is_first_run:
            self.play_btn.setStyleSheet("background-color:#ff4d4f;border:2px solid #ff4d4f;color:#ffffff;border-radius:18px;padding:10px 16px;font-weight:800;letter-spacing:.5px;")

        # Кнопка проверки файлов и чекбокс чистой установки
        self.check_files_btn = QPushButton("Проверка файлов")
        self.check_files_btn.clicked.connect(self.on_check_files)
        
        self.clean_install_chk = QCheckBox("Чистая установка")
        self.clean_install_chk.setToolTip("При включении сначала удаляет все файлы, затем заново копирует")
        
        # Кнопка обновления вайтлиста больше не нужна - логика перенесена в кнопку "Играть"

        self.status = QLabel("Готово")
        self.status.setObjectName("status")

        # Прогрессбар внизу + бейдж процента
        from PySide6.QtWidgets import QProgressBar
        self.progress_container = QFrame()
        self.progress_container.setObjectName("progressContainer")
        pc_layout = QVBoxLayout(self.progress_container)
        pc_layout.setContentsMargins(0, 0, 0, 0)
        self.progress = QProgressBar(self.progress_container)
        self.progress.setObjectName("progress")
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        pc_layout.addWidget(self.progress)
        self.progress_container.setVisible(False)
        self.progress_badge = QLabel("0%", self.progress_container)
        self.progress_badge.setObjectName("progressBadge")
        self.progress_badge.setAlignment(Qt.AlignCenter)
        self.progress_badge.setVisible(False)

        top = QHBoxLayout()
        top.addWidget(logo)
        top.addStretch(1)

        form = QVBoxLayout()
        form.addWidget(self.nickname)

        btns = QHBoxLayout()
        btns.addWidget(self.discord_btn)
        btns.addWidget(self.settings_btn)

        # Создаем основной виджет
        self.main_widget = QWidget()
        root = QVBoxLayout(self.main_widget)
        root.addLayout(top)
        root.addSpacing(8)
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.addLayout(form)
        card_layout.addSpacing(8)
        card_layout.addLayout(btns)
        card_layout.addSpacing(12)
        
        # Блок проверки файлов
        check_files_layout = QHBoxLayout()
        check_files_layout.addWidget(self.clean_install_chk)
        check_files_layout.addStretch(1)
        check_files_layout.addWidget(self.check_files_btn)
        card_layout.addLayout(check_files_layout)
        card_layout.addSpacing(8)
        
        # Блок вайтлиста убран - логика перенесена в кнопку "Играть"
        
        card_layout.addWidget(self.play_btn)
        root.addWidget(card)

        # Server status (dot + text), centered under the card (below "Играть")
        self.server_status_dot = QLabel()
        self.server_status_dot.setFixedSize(12, 12)
        self.server_status_dot.setObjectName("serverStatusDot")
        self.server_status_label = QLabel("")
        self.server_status_label.setObjectName("serverStatusLabel")
        server_line = QHBoxLayout()
        server_line.setAlignment(Qt.AlignCenter)
        server_line.addWidget(self.server_status_dot)
        server_line.addSpacing(8)
        server_line.addWidget(self.server_status_label)
        root.addLayout(server_line)
        root.addStretch(1)
        # install/status line remains at bottom
        root.addWidget(self.status)
        root.addWidget(self.progress_container)
        
        # Устанавливаем основной виджет
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.main_widget)


        # periodic server status check
        self._server_timer = QTimer(self)
        self._server_timer.timeout.connect(self._update_server_status)
        self._server_timer.start(5000)  # каждые 5 секунд
        self._update_server_status()
        
        # Проверка обновлений при запуске
        if UPDATER_AVAILABLE:
            self._check_for_updates()

    def set_status(self, text: str):
        self.status.setText(text)
        QApplication.processEvents()

    def _measure_server_ping(self, host: str, port: int, timeout_sec: float = 1.5) -> float | None:
        """Возвращает время TCP‑подключения в мс или None, если сервер недоступен."""
        try:
            start = time.perf_counter()
            with socket.create_connection((host, int(port)), timeout=timeout_sec):
                pass
            end = time.perf_counter()
            return (end - start) * 1000.0
        except Exception:
            return None

    def _update_server_status(self):
        ping_ms = self._measure_server_ping(SERVER_HOST, SERVER_PORT)
        if ping_ms is None:
            # red
            self.server_status_dot.setStyleSheet("background-color:#ff4d4f; border-radius:6px;")
            self.server_status_label.setText("Сервер недоступен")
            logging.warning("Сервер недоступен для пинга")
        else:
            self.server_status_dot.setStyleSheet("background-color:#23d160; border-radius:6px;")
            self.server_status_label.setText(f"Сервер онлайн • пинг {int(ping_ms)} мс")
            logging.info(f"Ping ok: {int(ping_ms)} мс")

    def on_discord(self):
        webbrowser.open("https://discord.gg/mBW5Tzpj")

    def on_open_game_dir(self):
        # Открыть проводник в папке установки игры
        path = str(self.instance_root)
        try:
            if sys.platform.startswith('win'):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', path])
            else:
                subprocess.Popen(['xdg-open', path])
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть папку: {e}")

    def on_settings(self):
        self._show_settings_screen()
        
    def on_back(self):
        self._show_main_screen()
        
    def on_save_settings(self):
        self.launcher_settings["max_memory_gb"] = self.ram_spin.value()
        # сохраняем никнейм из главного экрана
        try:
            self.launcher_settings["nickname"] = self.nickname.text().strip()
        except Exception:
            pass
        # Переключатель шейдеров удалён; настройка больше не сохраняется
        write_launcher_settings(self.instance_root, self.launcher_settings)
        self._show_main_screen()
    
    def on_add_mods(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Выберите моды (.jar)", str(Path.home()), "JAR файлы (*.jar)")
        if not files:
            return
        mods_dir = self.instance_root / "mods"
        mods_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        for f in files:
            try:
                src = Path(f)
                if src.suffix.lower() != ".jar":
                    continue
                (mods_dir / src.name).write_bytes(src.read_bytes())
                copied += 1
            except Exception:
                pass
        if copied:
            QMessageBox.information(self, "Моды добавлены", f"Скопировано модов: {copied}")
        try:
            track_user_added(self.instance_root, "mods", [Path(f).name for f in files if Path(f).suffix.lower()==".jar"])
        except Exception:
            pass

    def on_add_resourcepacks(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Выберите ресурспаки (.zip)", str(Path.home()), "ZIP файлы (*.zip)")
        if not files:
            return
        rp_dir = self.instance_root / "resourcepacks"
        rp_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        for f in files:
            try:
                src = Path(f)
                if src.suffix.lower() != ".zip":
                    continue
                (rp_dir / src.name).write_bytes(src.read_bytes())
                copied += 1
            except Exception:
                pass
        if copied:
            QMessageBox.information(self, "Ресурспаки добавлены", f"Скопировано ресурспаков: {copied}")
        try:
            track_user_added(self.instance_root, "resourcepacks", [Path(f).name for f in files if Path(f).suffix.lower()==".zip"])
        except Exception:
            pass

    def on_add_shaderpacks(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Выберите шейдеры (.zip/.jar)", str(Path.home()), "ZIP/JAR файлы (*.zip *.jar)")
        if not files:
            return
        sp_dir = self.instance_root / "shaderpacks"
        sp_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        for f in files:
            try:
                src = Path(f)
                if src.suffix.lower() not in [".zip", ".jar"]:
                    continue
                (sp_dir / src.name).write_bytes(src.read_bytes())
                copied += 1
            except Exception:
                pass
        if copied:
            QMessageBox.information(self, "Шейдеры добавлены", f"Скопировано шейдерпаков: {copied}")
        try:
            track_user_added(self.instance_root, "shaderpacks", [Path(f).name for f in files if Path(f).suffix.lower() in [".zip", ".jar"]])
        except Exception:
            pass
        
    def _show_settings_screen(self):
        # Создаем UI настроек если еще не создан
        if not hasattr(self, 'settings_widget'):
            self._create_settings_ui()
        
        # Показываем настройки
        self.main_widget.hide()
        self.settings_widget.show()
        
    def _show_main_screen(self):
        # Показываем основной экран
        if hasattr(self, 'settings_widget'):
            self.settings_widget.hide()
        self.main_widget.show()
        
    def _create_settings_ui(self):
        # Создаем виджет настроек
        self.settings_widget = QWidget()
        settings_layout = QVBoxLayout(self.settings_widget)
        
        # Кнопка назад
        back_btn = QPushButton("← Назад")
        back_btn.clicked.connect(self.on_back)
        
        # RAM настройка: слайдер + значение в реальном времени, ограничение максимумом ОЗУ
        ram_label = QLabel("Оперативная память (ГБ):")
        self.ram_spin = QSpinBox()
        max_ram = max(1, get_total_ram_gb())
        self.ram_spin.setRange(1, max_ram)
        self.ram_spin.setValue(min(int(self.launcher_settings.get("max_memory_gb", 4)), max_ram))
        self.ram_slider = QSlider(Qt.Horizontal)
        self.ram_slider.setRange(1, max_ram)
        self.ram_slider.setValue(self.ram_spin.value())
        # Лейаут слайдера
        ram_line = QHBoxLayout()
        ram_line.addWidget(self.ram_slider)
        ram_value = QLabel(f"{self.ram_slider.value()} ГБ")
        ram_value.setFixedWidth(60)
        ram_line.addWidget(ram_value)
        
        # Связь слайдера и спинбокса в обе стороны (в реальном времени)
        self.ram_slider.valueChanged.connect(self.ram_spin.setValue)
        self.ram_slider.valueChanged.connect(lambda v: ram_value.setText(f"{v} ГБ"))
        self.ram_spin.valueChanged.connect(self.ram_slider.setValue)
        
        # Убираем переключатель шейдеров — теперь управляется сборкой

        # Кнопки добавления модов/ресурспаков/шейдеров
        add_mods_btn = QPushButton("Добавить свои моды")
        add_mods_btn.clicked.connect(self.on_add_mods)
        add_rp_btn = QPushButton("Добавить свои ресурспаки")
        add_rp_btn.clicked.connect(self.on_add_resourcepacks)
        add_sp_btn = QPushButton("Добавить свои шейдеры")
        add_sp_btn.clicked.connect(self.on_add_shaderpacks)

        # Кнопка сохранить
        save_btn = QPushButton("Сохранить")
        save_btn.clicked.connect(self.on_save_settings)
        # Кнопка открыть папку игры
        open_dir_btn = QPushButton("Открыть папку с файлами")
        open_dir_btn.clicked.connect(self.on_open_game_dir)
        
        # Компоновка
        top_layout = QHBoxLayout()
        top_layout.addWidget(back_btn)
        top_layout.addStretch(1)
        
        form_layout = QVBoxLayout()
        form_layout.addWidget(ram_label)
        form_layout.addWidget(self.ram_spin)
        form_layout.addLayout(ram_line)
        form_layout.addSpacing(12)
        form_layout.addWidget(add_mods_btn)
        form_layout.addWidget(add_rp_btn)
        form_layout.addWidget(add_sp_btn)
        form_layout.addSpacing(20)
        form_layout.addWidget(open_dir_btn)
        form_layout.addStretch(1)
        form_layout.addWidget(save_btn)
        
        settings_layout.addLayout(top_layout)
        settings_layout.addSpacing(8)
        
        card = QFrame()
        card.setObjectName("card")
        card.setLayout(form_layout)
        settings_layout.addWidget(card)
        settings_layout.addStretch(1)
        
        # Добавляем в основной layout
        self.layout().addWidget(self.settings_widget)
        self.settings_widget.hide()

    def on_play(self):
        nick = self.nickname.text().strip()
        # Проверка пустого поля
        if not nick:
            self.nickname.setStyleSheet("background-color:#0f0f19;border:2px solid #ff4d4f;border-radius:12px;padding:10px 12px;color:#f0f0f0;")
            self.nickname.setPlaceholderText("Введите свой ник")
            self.nickname.setText("")
            self.nickname.setFocus()
            return
        
        # Проверка вайтлиста с автоматической синхронизацией
        if WHITELIST_AVAILABLE:
            try:
                # Сначала обновляем вайтлист из Discord
                self.set_status("Синхронизация вайтлиста...")
                whitelist_manager.force_update()
                
                # Теперь проверяем никнейм
                if not whitelist_manager.is_nickname_whitelisted(nick):
                    # Показываем ошибку в поле никнейма вместо всплывающего окна
                    self.nickname.setStyleSheet("background-color:#0f0f19;border:2px solid #ff4d4f;border-radius:12px;padding:10px 12px;color:#f0f0f0;")
                    self.nickname.setPlaceholderText("Такого ника нету в вайтлисте")
                    self.nickname.setText("")
                    self.nickname.setFocus()
                    return
                logging.info(f"Ник {nick} найден в вайтлисте")
            except Exception as e:
                logging.error(f"Ошибка при проверке вайтлиста: {e}")
                # Показываем ошибку в поле никнейма
                self.nickname.setStyleSheet("background-color:#0f0f19;border:2px solid #ff4d4f;border-radius:12px;padding:10px 12px;color:#f0f0f0;")
                self.nickname.setPlaceholderText("Ошибка проверки вайтлиста")
                self.nickname.setText("")
                self.nickname.setFocus()
                return
        else:
            logging.warning("Проверка вайтлиста отключена")
        # сохраняем ник и сбрасываем стиль
        # гарантируем, что корневая папка существует
        try:
            self.instance_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.launcher_settings["nickname"] = nick
        write_launcher_settings(self.instance_root, self.launcher_settings)
        self._reset_nick_style()
        logging.info("Нажата кнопка Играть; запуск Fabric 1.21.5")
        # Запускаем игру напрямую (файлы уже установлены)
        self.set_status("Запуск игры...")
        self._launch_fabric_game()

    def _reset_nick_style(self):
        self.nickname.setStyleSheet("")

    def _run_copy_then_launch(self):
        """Копирует файлы из Installation files и запускает игру"""
        if hasattr(self, "_copy_thread") and self._copy_thread.isRunning():
            return
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self._copy_thread = CopyFilesThread(self.instance_root)
        self._copy_thread.sig_status.connect(self.set_status)
        self._copy_thread.sig_progress.connect(self._on_progress_value)
        self._copy_thread.sig_max.connect(self._on_progress_max)
        self._copy_thread.sig_error.connect(self._on_copy_error)
        self._copy_thread.sig_done.connect(lambda: (self._hide_progress(), self._launch_fabric_game()))
        self._show_progress()
        self._copy_thread.start()

    def _on_copy_error(self, e: str):
        try:
            report_event("Ошибка копирования файлов", str(e))
        except Exception:
            pass
        QMessageBox.critical(self, "Ошибка копирования файлов", e)

    def _launch_fabric_game(self):
        """Запускает Minecraft Fabric 1.21.5"""
        nick = self.nickname.text().strip() or "Игрок"
        max_gb = int(self.launcher_settings.get("max_memory_gb", 4))
        xmx = f"-Xmx{max_gb}G"
        xms = f"-Xms{max(1, max_gb//2)}G"

        self.set_status("Запуск Fabric 1.21.5...")
        try:
            # Патч для старой версии библиотеки
            _patch_mll_get_libraries_for_classifiers()
            
            # Используем версию Fabric 1.21.5
            version_id = "Fabric 1.21.5"
            game_dir = str(self.instance_root)
            version_dir = Path(game_dir) / "versions" / version_id

            # Проверяем, что файлы Fabric существуют
            if not (version_dir / "Fabric 1.21.5.json").exists():
                raise FileNotFoundError(f"Файл конфигурации Fabric не найден: {version_dir / 'Fabric 1.21.5.json'}")

            # Находим Java
            java_exe = _get_java_executable(game_dir)
            
            # Формируем команду запуска для Fabric
            cmd = self._build_fabric_command(version_id, game_dir, nick, java_exe, xms, xmx)
            
            # Добавляем аргументы для подключения к серверу
            cmd.extend(["--quickPlayMultiplayer", f"{SERVER_HOST}:{SERVER_PORT}"])

            logging.info(f"Запуск команды: {' '.join(cmd)}")
            
            # Скрываем консоль на Windows
            if os.name == 'nt':  # Windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                subprocess.Popen(cmd, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW)
            else:  # Linux/Mac
                subprocess.Popen(cmd, creationflags=getattr(subprocess, 'DETACHED_PROCESS', 0))
            
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            report_event("Успешный запуск Fabric", f"Ник: {nick}\nВерсия: {version_id}\nВремя: {ts}")
            QTimer.singleShot(200, lambda: os._exit(0))
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            logging.exception("Ошибка запуска Fabric")
            QMessageBox.critical(self, "Ошибка запуска", f"{e}\n\n{tb}")

    def _build_fabric_command(self, version_id: str, game_dir: str, username: str, java_exe: str, xms: str, xmx: str) -> List[str]:
        """Строит команду запуска для Fabric"""
        version_dir = Path(game_dir) / "versions" / version_id
        natives_dir = version_dir / "natives"
        assets_dir = Path(game_dir) / "assets"
        
        # Читаем JSON конфигурацию
        with open(version_dir / f"{version_id}.json", 'r', encoding='utf-8') as f:
            version_data = json.load(f)
        
        # Основные аргументы JVM
        jvm_args = [
            java_exe,
            xms,
            xmx,
            "-Xss1M",
            f"-Djava.library.path={natives_dir}",
            f"-Djna.tmpdir={natives_dir}",
            f"-Dorg.lwjgl.system.SharedLibraryExtractPath={natives_dir}",
            f"-Dio.netty.native.workdir={natives_dir}",
            "-Dminecraft.launcher.brand=LightShieldLauncher",
            "-Dminecraft.launcher.version=1.0",
        ]
        
        # Формируем classpath
        classpath_parts = []
        
        # Добавляем основной JAR файл
        jar_file = version_dir / f"{version_id}.jar"
        if jar_file.exists():
            classpath_parts.append(str(jar_file))
        
        # Добавляем библиотеки
        libraries_dir = Path(game_dir) / "libraries"
        if "libraries" in version_data:
            # Создаем множество разрешенных библиотек из JSON
            allowed_libs = set()
            for lib in version_data["libraries"]:
                lib_name = lib["name"]
                allowed_libs.add(lib_name)
            
            # Создаем множество уже добавленных библиотек для предотвращения дублирования
            added_libs = set()
            
            for lib in version_data["libraries"]:
                # Получаем имя библиотеки
                lib_name = lib["name"]
                lib_parts = lib_name.split(":")
                if len(lib_parts) >= 3:
                    group, artifact, version = lib_parts[0], lib_parts[1], lib_parts[2]
                    classifier = lib_parts[3] if len(lib_parts) >= 4 else None
                    
                    # Строим путь к файлу
                    group_path = group.replace(".", "/")
                    jar_name = f"{artifact}-{version}{('-' + classifier) if classifier else ''}.jar"
                    lib_path = f"{group_path}/{artifact}/{version}/{jar_name}"
                    
                    lib_file = libraries_dir / lib_path
                    if lib_file.exists():
                        # Проверяем, не добавляли ли мы уже эту библиотеку
                        lib_key = f"{group}:{artifact}:{version}"
                        if lib_key not in added_libs:
                            classpath_parts.append(str(lib_file))
                            added_libs.add(lib_key)
                            logging.info(f"Добавлена библиотека: {lib_path}")
                        else:
                            logging.info(f"Пропущена дублирующаяся библиотека: {lib_path}")
                    else:
                        logging.warning(f"Библиотека не найдена: {lib_path}")
                        # Если файл не найден, не добавляем его в classpath
                        # Для критических библиотек (authlib) добавляем предупреждение
                        if "authlib" in lib_path:
                            logging.error(f"КРИТИЧЕСКАЯ БИБЛИОТЕКА НЕ НАЙДЕНА: {lib_path}")
                            logging.error("Это может привести к ошибке запуска Minecraft")
        
        # Добавляем classpath в аргументы
        if classpath_parts:
            jvm_args.extend(["-cp", os.pathsep.join(classpath_parts)])
        
        # Добавляем main class
        main_class = version_data.get("mainClass", "net.minecraft.client.main.Main")
        jvm_args.append(main_class)
        
        # Аргументы игры
        game_args = [
            "--username", username,
            "--version", version_id,
            "--gameDir", game_dir,
            "--assetsDir", str(assets_dir),
            "--assetIndex", version_data.get("assets", "24"),
            "--uuid", "0" * 32,
            "--accessToken", "",
            "--userProperties", "{}",
            "--userType", "mojang"
        ]
        
        return jvm_args + game_args

    # ---- background install thread orchestration ----
    def _run_install_then(self, cont):
        if hasattr(self, "_install_thread") and self._install_thread.isRunning():
            return
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self._install_thread = InstallThread(self.instance_root)
        self._install_thread.sig_status.connect(self.set_status)
        self._install_thread.sig_progress.connect(self._on_progress_value)
        self._install_thread.sig_max.connect(self._on_progress_max)
        self._install_thread.sig_error.connect(self._on_install_error)
        self._install_thread.sig_done.connect(lambda vid, gd: (self._hide_progress(), cont(vid, gd)))
        self._show_progress()
        self._install_thread.start()

    def _post_fabric_install_and_launch(self, version_id: str, game_dir: str):
        # После установки Fabric сразу запускаем игру
        self._launch_game(version_id, game_dir)

    def _launch_game(self, version_id: str, game_dir: str):
        nick = self.nickname.text().strip() or "Игрок"
        max_gb = int(self.launcher_settings.get("max_memory_gb", 4))
        xmx = f"-Xmx{max_gb}G"
        xms = f"-Xms{max(1, max_gb//2)}G"

        self.set_status("Запуск...")
        try:
            # Патч для старой версии библиотеки, чтобы поддержать координаты библиотек с классификатором
            _patch_mll_get_libraries_for_classifiers()
            # Просто используем версию 1.21.5
            selected_id = "1.21.5"

            options = {
                "username": nick,
                "uuid": "0" * 32,
                "token": "",
                "gameDirectory": game_dir,
                "jvmArguments": [xms, xmx],
                "server": SERVER_HOST,
                "port": SERVER_PORT,
            }
            try:
                cmd = mll.command.get_minecraft_command(selected_id, game_dir, options)
            except Exception:
                # Фолбэк: минимальный набор опций без server/port/jvmArguments — добавим вручную ниже
                minimal = {
                    "username": nick,
                    "uuid": "0" * 32,
                    "token": "",
                    "gameDirectory": game_dir,
                }
                cmd = mll.command.get_minecraft_command(selected_id, game_dir, minimal)
            cmd = [str(x) for x in cmd]
            cmd += ["--quickPlayMultiplayer", f"{SERVER_HOST}:{SERVER_PORT}"]

            exe = cmd[0]
            if exe.startswith('"') and exe.endswith('"'):
                exe = exe[1:-1]
            # Если указан абсолютный путь и его нет — подбираем Java
            if os.path.isabs(exe) and not os.path.exists(exe):
                jre = _get_java_executable(game_dir)
                cmd[0] = jre
                exe = jre
            # Если снова абсолютный путь и не существует — ошибка
            if os.path.isabs(exe) and not os.path.exists(exe):
                raise FileNotFoundError(f"Исполняемый файл Java не найден: {exe}")

            # Скрываем консоль на Windows
            if os.name == 'nt':  # Windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                subprocess.Popen(cmd, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW)
            else:  # Linux/Mac
                subprocess.Popen(cmd, creationflags=getattr(subprocess, 'DETACHED_PROCESS', 0))
            
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            report_event("Успешный запуск", f"Ник: {nick}\nВерсия: {selected_id}\nВремя: {ts}")
            QTimer.singleShot(200, lambda: os._exit(0))
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            logging.exception("Ошибка запуска")
            QMessageBox.critical(self, "Ошибка запуска", f"{e}\n\n{tb}")

    def on_check_files(self):
        # Кнопка «Проверить файлы»: скачивает файлы из интернета
        try:
            if not UPDATER_AVAILABLE:
                self.set_status("Ошибка: модуль обновлений недоступен")
                return
                
            if self.clean_install_chk.isChecked():
                self.set_status("Чистая установка...")
                # Удаляем все файлы из папки mc
                import shutil
                if self.instance_root.exists():
                    shutil.rmtree(self.instance_root)
                logging.info("Выполнена чистая установка - папка mc очищена")
            
            self.set_status("Скачивание файлов игры из интернета...")
            
            # Показываем прогресс
            self.progress.setValue(0)
            self.progress.setVisible(True)
            
            # Скачиваем файлы из интернета
            self._download_thread = DownloadThread("files")
            self._download_thread.sig_progress.connect(self._on_progress_value)
            self._download_thread.sig_complete.connect(self._on_files_download_complete)
            self._download_thread.sig_error.connect(self._on_download_error)
            
            self._show_progress()
            self._download_thread.start()
            
        except Exception as e:
            logging.exception(f"Ошибка при проверке файлов: {e}")
            QMessageBox.critical(self, "Ошибка", str(e))
            self.set_status("Ошибка проверки файлов")
    
    def _is_installation_complete(self) -> bool:
        """Проверяет, завершена ли первоначальная установка"""
        try:
            # Проверяем наличие основных файлов
            required_files = [
                self.instance_root / "versions" / "Fabric 1.21.5" / "Fabric 1.21.5.json",
                self.instance_root / "libraries",
                self.instance_root / "assets"
            ]
            
            for file_path in required_files:
                if not file_path.exists():
                    return False
            
            return True
        except Exception:
            return False
    
    def on_install(self):
        """Обработчик кнопки "Установка" для первого запуска"""
        nick = self.nickname.text().strip()
        # Проверка пустого поля
        if not nick:
            self.nickname.setStyleSheet("background-color:#0f0f19;border:2px solid #ff4d4f;border-radius:12px;padding:10px 12px;color:#f0f0f0;")
            self.nickname.setPlaceholderText("Введите свой ник")
            self.nickname.setText("")
            self.nickname.setFocus()
            return
        
        # Проверка вайтлиста с автоматической синхронизацией
        if WHITELIST_AVAILABLE:
            try:
                # Сначала обновляем вайтлист из Discord
                self.set_status("Синхронизация вайтлиста...")
                whitelist_manager.force_update()
                
                # Теперь проверяем никнейм
                if not whitelist_manager.is_nickname_whitelisted(nick):
                    # Показываем ошибку в поле никнейма
                    self.nickname.setStyleSheet("background-color:#0f0f19;border:2px solid #ff4d4f;border-radius:12px;padding:10px 12px;color:#f0f0f0;")
                    self.nickname.setPlaceholderText("Такого ника нету в вайтлисте")
                    self.nickname.setText("")
                    self.nickname.setFocus()
                    return
                logging.info(f"Ник {nick} найден в вайтлисте")
            except Exception as e:
                logging.error(f"Ошибка при проверке вайтлиста: {e}")
                # Показываем ошибку в поле никнейма
                self.nickname.setStyleSheet("background-color:#0f0f19;border:2px solid #ff4d4f;border-radius:12px;padding:10px 12px;color:#f0f0f0;")
                self.nickname.setPlaceholderText("Ошибка проверки вайтлиста")
                self.nickname.setText("")
                self.nickname.setFocus()
                return
        else:
            logging.warning("Проверка вайтлиста отключена")
        
        # Сохраняем ник и сбрасываем стиль
        try:
            self.instance_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self.launcher_settings["nickname"] = nick
        write_launcher_settings(self.instance_root, self.launcher_settings)
        self._reset_nick_style()
        
        logging.info("Нажата кнопка Установка; первичная установка файлов из интернета")
        # Устанавливаем файлы из интернета
        self.set_status("Первичная установка файлов из интернета...")
        self._run_download_then_install()
    
    def _run_download_then_install(self):
        """Скачивает файлы из интернета и затем устанавливает их"""
        if not UPDATER_AVAILABLE:
            self.set_status("Ошибка: модуль обновлений недоступен")
            return
            
        try:
            # Сначала скачиваем файлы
            self.set_status("Скачивание файлов игры...")
            self.progress.setValue(0)
            self.progress.setVisible(True)
            self._show_progress()
            
            # Скачиваем файлы в отдельном потоке
            self._download_thread = DownloadThread("files")
            self._download_thread.sig_progress.connect(self._on_progress_value)
            self._download_thread.sig_complete.connect(self._on_download_complete)
            self._download_thread.sig_error.connect(self._on_download_error)
            self._download_thread.start()
            
        except Exception as e:
            logging.error(f"Ошибка при запуске скачивания: {e}")
            self.set_status("Ошибка запуска скачивания")
    
    def _on_download_complete(self):
        """Обработка завершения скачивания файлов"""
        self.set_status("Файлы скачаны, начинаем установку...")
        # Теперь запускаем установку скачанных файлов
        self._run_install_then_switch_to_play()
    
    def _run_install_then_switch_to_play(self):
        """Устанавливает файлы и затем меняет кнопку на "Играть" """
        if hasattr(self, "_copy_thread") and self._copy_thread.isRunning():
            return
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self._copy_thread = CopyFilesThread(self.instance_root)
        self._copy_thread.sig_status.connect(self.set_status)
        self._copy_thread.sig_progress.connect(self._on_progress_value)
        self._copy_thread.sig_max.connect(self._on_progress_max)
        self._copy_thread.sig_error.connect(self._on_copy_error)
        self._copy_thread.sig_done.connect(self._on_install_complete)
        self._show_progress()
        self._copy_thread.start()
    
    def _on_install_complete(self):
        """Обработка завершения первичной установки"""
        self._hide_progress()
        self.set_status("Установка завершена! Теперь можно играть")
        
        # Меняем кнопку на "Играть"
        self.play_btn.setText("Играть")
        self.play_btn.clicked.disconnect()
        self.play_btn.clicked.connect(self.on_play)
        self.play_btn.setStyleSheet("")  # Возвращаем обычный стиль
        
        # Отмечаем установку как завершенную
        self.is_first_run = False
        
        # Показываем сообщение об успешной установке
        QMessageBox.information(self, "Установка завершена", "Все необходимые файлы установлены!\nТеперь вы можете играть.")
    
    def _check_for_updates(self):
        """Проверяет наличие обновлений при запуске"""
        try:
            if not UPDATER_AVAILABLE:
                return
                
            self.set_status("Проверка обновлений...")
            
            # Проверяем обновления в отдельном потоке
            self._update_check_thread = UpdateCheckThread()
            self._update_check_thread.sig_updates_found.connect(self._on_updates_found)
            self._update_check_thread.sig_no_updates.connect(self._on_no_updates)
            self._update_check_thread.sig_error.connect(self._on_update_check_error)
            self._update_check_thread.start()
            
        except Exception as e:
            logging.error(f"Ошибка при проверке обновлений: {e}")
    
    def _on_updates_found(self, launcher_update: bool, files_update: bool, launcher_version: str, files_version: str):
        """Обработка найденных обновлений"""
        if launcher_update:
            reply = QMessageBox.question(
                self, 
                "Обновление лаунчера", 
                f"Доступна новая версия лаунчера: {launcher_version}\n\nОбновить сейчас?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self._download_launcher_update()
        
        if files_update:
            reply = QMessageBox.question(
                self, 
                "Обновление файлов", 
                f"Доступна новая версия файлов игры: {files_version}\n\nОбновить сейчас?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self._download_files_update()
    
    def _on_no_updates(self):
        """Обработка отсутствия обновлений"""
        self.set_status("Готово")
    
    def _on_update_check_error(self, error: str):
        """Обработка ошибки проверки обновлений"""
        logging.error(f"Ошибка проверки обновлений: {error}")
        self.set_status("Готово")
    
    def _download_launcher_update(self):
        """Скачивает обновление лаунчера"""
        try:
            self.set_status("Скачивание обновления лаунчера...")
            
            # Скачиваем в отдельном потоке
            self._download_thread = DownloadThread("launcher")
            self._download_thread.sig_progress.connect(self._on_download_progress)
            self._download_thread.sig_complete.connect(self._on_launcher_update_complete)
            self._download_thread.sig_error.connect(self._on_download_error)
            self._download_thread.start()
            
        except Exception as e:
            logging.error(f"Ошибка при скачивании обновления лаунчера: {e}")
    
    def _download_files_update(self):
        """Скачивает обновление файлов"""
        try:
            self.set_status("Скачивание обновления файлов...")
            
            # Скачиваем в отдельном потоке
            self._download_thread = DownloadThread("files")
            self._download_thread.sig_progress.connect(self._on_download_progress)
            self._download_thread.sig_complete.connect(self._on_files_update_complete)
            self._download_thread.sig_error.connect(self._on_download_error)
            self._download_thread.start()
            
        except Exception as e:
            logging.error(f"Ошибка при скачивании обновления файлов: {e}")
    
    def _on_download_progress(self, progress: int):
        """Обработка прогресса скачивания"""
        self.progress.setValue(progress)
        self.progress.setVisible(True)
        self._show_progress()
    
    def _on_launcher_update_complete(self):
        """Обработка завершения обновления лаунчера"""
        self._hide_progress()
        QMessageBox.information(self, "Обновление завершено", "Лаунчер обновлен! Перезапустите приложение.")
        # Закрываем лаунчер для применения обновления
        QTimer.singleShot(1000, lambda: os._exit(0))
    
    def _on_files_update_complete(self):
        """Обработка завершения обновления файлов"""
        self._hide_progress()
        self.set_status("Файлы обновлены!")
        QMessageBox.information(self, "Обновление завершено", "Файлы игры обновлены!")
    
    def _on_download_error(self, error: str):
        """Обработка ошибки скачивания"""
        self._hide_progress()
        self.set_status("Ошибка обновления")
        QMessageBox.critical(self, "Ошибка обновления", f"Не удалось обновить: {error}")
    
    # Функции обновления вайтлиста больше не нужны - логика перенесена в кнопку "Играть"
    
    def _on_check_files_error(self, e: str):
        """Обработка ошибки при проверке файлов"""
        try:
            report_event("Ошибка проверки файлов", str(e))
        except Exception:
            pass
        QMessageBox.critical(self, "Ошибка проверки файлов", e)
        self._hide_progress()
        self.set_status("Ошибка проверки файлов")
    
    def _on_files_download_complete(self):
        """Обработка завершения скачивания файлов"""
        self._hide_progress()
        self.set_status("Файлы успешно скачаны из интернета!")
    
    def _on_check_files_done(self):
        """Обработка завершения проверки файлов"""
        self._hide_progress()
        self.set_status("Проверка файлов завершена - файлы успешно скопированы")
        # Убираем всплывающее окно, показываем только в статусе

    def _on_install_error(self, e: str):
        try:
            report_event("Ошибка установки", str(e))
        except Exception:
            pass
        QMessageBox.critical(self, "Ошибка установки", e)

    def _style(self) -> str:
        # Стилизация, визуально близкая к макету: тёмно‑зелёная тема, округлые элементы
        return """
        QWidget { background-color: #0a0a0f; color: #e6e6e6; font-family: Segoe UI, Arial; font-size: 14px; }
        #logo { font-size: 56px; color: #ffe300; font-weight: 900; text-shadow: 0 0 12px #ffd200; }
        #status { color: #00f0ff; }
        #serverStatusLabel { color: #9aa0a6; }
        QFrame#card { background-color: #0d0d14; border: 2px solid #2a2a33; border-radius: 16px; padding: 18px; }
        QLineEdit { background-color: #0f0f19; border: 2px solid #2c2c38; border-radius: 12px; padding: 10px 12px; color: #f0f0f0; }
        QLineEdit:focus { border-color: #00f0ff; box-shadow: 0 0 10px #00f0ff; }
        QPushButton { background-color: #111117; border: 2px solid #ffe300; color: #111117; border-radius: 18px; padding: 10px 16px; font-weight: 800; letter-spacing: .5px; }
        QPushButton { color: #111117; background-color: #ffe300; }
        QPushButton:hover { background-color: #fff172; }
        QPushButton:disabled { background-color: #3a3a42; border-color: #3a3a42; color: #9aa0a6; }
        QPushButton#discordBtn { background-color: #1977f3; border-color: #1977f3; color: #ffffff; }
        QPushButton#discordBtn:hover { background-color: #4690ff; }
        QCheckBox { color: #e6e6e6; spacing: 8px; }
        QCheckBox::indicator { width: 18px; height: 18px; border: 2px solid #2c2c38; border-radius: 4px; background-color: #0f0f19; }
        QCheckBox::indicator:checked { background-color: #ffe300; border-color: #ffe300; }
        QCheckBox::indicator:checked::after { content: "✓"; color: #111117; font-weight: bold; }
        QSlider::groove:horizontal { height: 10px; background: #2a2a33; border-radius: 5px; }
        QSlider::sub-page:horizontal { background: #00f0ff; border-radius: 5px; }
        QSlider::add-page:horizontal { background: #2a2a33; border-radius: 5px; }
        QSlider::handle:horizontal { background: #00f0ff; border: 2px solid #0ad; width: 18px; height: 18px; margin: -6px 0; border-radius: 9px; }
        QProgressBar { background-color: #14141c; border: 1px solid #2a2a33; border-radius: 10px; padding: 3px; height: 18px; }
        QProgressBar::chunk { background-color: #ffe300; border-radius: 8px; }
        #progressBadge { background-color: #000; border-radius: 10px; padding: 2px 8px; color: #e6e6e6; font-weight: 800; }
        """

    # --- progress helpers ---
    def _show_progress(self):
        self.progress_container.setVisible(True)
        self.progress_badge.setVisible(True)
        self._reposition_badge()

    def _hide_progress(self):
        self.progress_container.setVisible(False)
        self.progress_badge.setVisible(False)

    def _on_progress_max(self, m: int):
        self.progress.setMaximum(int(m) if m else 100)
        self._reposition_badge()

    def _on_progress_value(self, v: int):
        self.progress.setValue(int(v))
        maxv = self.progress.maximum() or 100
        pct = int((self.progress.value() / maxv) * 100)
        self.progress_badge.setText(f"{pct}%")
        self._reposition_badge()

    def _reposition_badge(self):
        bar_geo = self.progress.geometry()
        text = self.progress_badge.text()
        w = max(50, len(text) * 12)  # Увеличил ширину для "%"
        h = 22
        x = bar_geo.x() + (bar_geo.width() - w) // 2
        y = bar_geo.y() + (bar_geo.height() - h) // 2  # Центрирую внутри полоски
        self.progress_badge.setGeometry(x, y, w, h)


def main():
    _init_logging()
    app = QApplication(sys.argv)
    w = LauncherWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()


