import logging
import json
import time
from pathlib import Path
from typing import List

class WhitelistManager:
    def __init__(self, token: str, channel_id: int):
        self.token = token
        self.channel_id = channel_id
        self.whitelist_cache = []
        self.cache_file = Path("whitelist_cache.json")
        self.last_update = 0
        self.cache_duration = 300  # 5 минут
        
        # Загружаем кэш при инициализации
        self._load_cache()
    
    def _load_cache(self):
        """Загружает кэш вайтлиста из файла"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.whitelist_cache = data.get('nicknames', [])
                    self.last_update = data.get('timestamp', 0)
                    logging.info(f"Загружен кэш вайтлиста: {len(self.whitelist_cache)} ников")
        except Exception as e:
            logging.warning(f"Не удалось загрузить кэш вайтлиста: {e}")
            self.whitelist_cache = []
    
    def _save_cache(self):
        """Сохраняет кэш вайтлиста в файл"""
        try:
            data = {
                'nicknames': self.whitelist_cache,
                'timestamp': self.last_update
            }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.warning(f"Не удалось сохранить кэш вайтлиста: {e}")
    
    def is_nickname_whitelisted(self, nickname: str) -> bool:
        """Проверяет, находится ли никнейм в вайтлисте"""
        # Проверяем кэш
        if nickname in self.whitelist_cache:
            return True
        
        # Если кэш устарел, обновляем его
        if time.time() - self.last_update > self.cache_duration:
            logging.info("Кэш вайтлиста устарел, обновляем...")
            self._update_whitelist_sync()
        
        return nickname in self.whitelist_cache
    
    def _update_whitelist_sync(self):
        """Синхронно обновляет вайтлист"""
        try:
            # Получаем вайтлист из Discord через HTTP API
            import requests
            
            # Формируем URL для получения сообщений из канала
            # Используем Discord Webhook или HTTP API
            headers = {
                'Authorization': f'Bot {self.token}',
                'Content-Type': 'application/json'
            }
            
            # Получаем сообщения из канала
            url = f"https://discord.com/api/v10/channels/{self.channel_id}/messages?limit=100"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                messages = response.json()
                nicknames = []
                
                for message in messages:
                    content = message.get('content', '').strip()
                    if content:
                        # Разбиваем на строки и извлекаем никнеймы
                        lines = content.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#') and not line.startswith('//'):
                                # Убираем лишние символы
                                nickname = line.split()[0] if line.split() else line
                                if nickname and len(nickname) <= 16:  # Максимальная длина никнейма Minecraft
                                    nicknames.append(nickname)
                
                # Обновляем кэш
                self.whitelist_cache = list(set(nicknames))  # Убираем дубликаты
                self.last_update = time.time()
                self._save_cache()
                logging.info(f"Вайтлист обновлен из Discord: {len(self.whitelist_cache)} никнеймов")
            else:
                logging.error(f"Ошибка при получении сообщений из Discord: {response.status_code}")
                # Если не удалось получить, используем старый кэш
                
        except Exception as e:
            logging.error(f"Ошибка при обновлении вайтлиста: {e}")
            # В случае ошибки используем старый кэш
    
    def get_whitelist(self) -> List[str]:
        """Возвращает текущий список вайтлиста"""
        return self.whitelist_cache.copy()
    
    def force_update(self):
        """Принудительно обновляет вайтлист"""
        logging.info("Принудительное обновление вайтлиста...")
        self._update_whitelist_sync()

# Создаем глобальный экземпляр менеджера
whitelist_manager = WhitelistManager(
    token="MTAxNDg0Nzc2ODMzMTgyNTI0Mg.Gs4k49.iMpeql1N_S6bzylcTlvK_09VkU0wmrtiEH2Hfk",
    channel_id=1405185990875938919
)
