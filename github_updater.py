import requests
import json
import zipfile
import os
import shutil
from pathlib import Path
import logging
from typing import Dict, Optional, Tuple

class GitHubUpdater:
    def __init__(self, repo_url: str, version_file_url: str):
        self.repo_url = repo_url
        self.version_file_url = version_file_url
        self.version_data = None
        
    def check_for_updates(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Проверяет наличие обновлений лаунчера и файлов"""
        try:
            # Получаем информацию о версиях
            response = requests.get(self.version_file_url, timeout=10)
            if response.status_code != 200:
                logging.error(f"Не удалось получить версию: {response.status_code}")
                return False, None, None
                
            self.version_data = response.json()
            
            # Читаем текущую версию лаунчера
            current_version = self._get_current_launcher_version()
            latest_version = self.version_data.get("launcher_version")
            
            # Читаем текущую версию файлов
            current_files_version = self._get_current_files_version()
            latest_files_version = self.version_data.get("files_version")
            
            launcher_update_available = current_version != latest_version
            files_update_available = current_files_version != latest_files_version
            
            return launcher_update_available, latest_version, latest_files_version
            
        except Exception as e:
            logging.error(f"Ошибка при проверке обновлений: {e}")
            return False, None, None
    
    def download_launcher_update(self, download_path: str) -> bool:
        """Скачивает обновление лаунчера"""
        try:
            if not self.version_data:
                return False
                
            download_url = self.version_data.get("launcher_download_url")
            if not download_url:
                return False
                
            # Скачиваем файл
            response = requests.get(download_url, timeout=30)
            if response.status_code != 200:
                return False
                
            # Сохраняем во временную папку
            temp_path = download_path + ".tmp"
            with open(temp_path, 'wb') as f:
                f.write(response.content)
                
            # Заменяем старый файл
            if os.path.exists(download_path):
                os.remove(download_path)
            os.rename(temp_path, download_path)
            
            # Обновляем версию
            self._save_launcher_version(self.version_data.get("launcher_version"))
            
            return True
            
        except Exception as e:
            logging.error(f"Ошибка при скачивании обновления лаунчера: {e}")
            return False
    
    def download_files_update(self, target_dir: str) -> bool:
        """Скачивает обновление файлов игры"""
        try:
            if not self.version_data:
                return False
                
            download_url = self.version_data.get("files_download_url")
            if not download_url:
                return False
                
            # Скачиваем ZIP архив
            response = requests.get(download_url, timeout=60)
            if response.status_code != 200:
                return False
                
            # Сохраняем во временный файл
            temp_zip = "temp_files.zip"
            with open(temp_zip, 'wb') as f:
                f.write(response.content)
                
            # Распаковываем
            with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                zip_ref.extractall("temp_extract")
            
            # Находим папку Installation files
            extracted_dir = Path("temp_extract")
            installation_files_dir = None
            
            for item in extracted_dir.iterdir():
                if item.is_dir() and item.name == "Installation files":
                    installation_files_dir = item
                    break
                elif item.is_dir() and (item / "Installation files").exists():
                    installation_files_dir = item / "Installation files"
                    break
            
            if not installation_files_dir:
                logging.error("Папка Installation files не найдена в архиве")
                return False
            
            # Копируем файлы
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            shutil.copytree(installation_files_dir, target_dir)
            
            # Обновляем версию файлов
            self._save_files_version(self.version_data.get("files_version"))
            
            # Очищаем временные файлы
            os.remove(temp_zip)
            shutil.rmtree("temp_extract")
            
            return True
            
        except Exception as e:
            logging.error(f"Ошибка при скачивании обновления файлов: {e}")
            return False
    
    def _get_current_launcher_version(self) -> str:
        """Получает текущую версию лаунчера"""
        try:
            version_file = Path("launcher_version.txt")
            if version_file.exists():
                return version_file.read_text().strip()
            return "1.0.0"  # Версия по умолчанию
        except Exception:
            return "1.0.0"
    
    def _save_launcher_version(self, version: str):
        """Сохраняет версию лаунчера"""
        try:
            with open("launcher_version.txt", 'w') as f:
                f.write(version)
        except Exception as e:
            logging.error(f"Ошибка при сохранении версии лаунчера: {e}")
    
    def _get_current_files_version(self) -> str:
        """Получает текущую версию файлов"""
        try:
            version_file = Path("files_version.txt")
            if version_file.exists():
                return version_file.read_text().strip()
            return "1.0.0"  # Версия по умолчанию
        except Exception:
            return "1.0.0"
    
    def _save_files_version(self, version: str):
        """Сохраняет версию файлов"""
        try:
            with open("files_version.txt", 'w') as f:
                f.write(version)
        except Exception as e:
            logging.error(f"Ошибка при сохранении версии файлов: {e}")

# Создаем глобальный экземпляр
# Замените на ваш репозиторий
github_updater = GitHubUpdater(
    repo_url="https://github.com/username/your-repo",
    version_file_url="https://raw.githubusercontent.com/username/your-repo/main/version.json"
)
