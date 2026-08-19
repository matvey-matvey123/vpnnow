#!/usr/bin/env python3
"""
VPN Server Checker
Скрипт для проверки VPN серверов из подписок
Определяет рабочие серверы в нужных странах
"""

import base64
import json
import re
import sys
from datetime import datetime
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import socket

# Отключаем предупреждения SSL для ускорения работы
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VPNChecker:
    """Основной класс для проверки VPN серверов"""
    
    def __init__(self):
        """Инициализация и загрузка конфигурации"""
        with open('config.json', 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        self.countries = self.config['countries']
        self.max_servers = self.config['max_servers_per_country']
        self.timeout = self.config['timeout']
        self.output_file = self.config['output_file']
        
    def load_subscriptions(self) -> List[str]:
        """Загрузка ссылок на подписки из файла"""
        subscriptions = []
        try:
            with open('subscriptions.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Пропускаем пустые строки и комментарии
                    if line and not line.startswith('#'):
                        subscriptions.append(line)
        except FileNotFoundError:
            print("❌ Файл subscriptions.txt не найден")
            sys.exit(1)
        return subscriptions
    
    def fetch_subscription(self, url: str) -> str:
        """Получение содержимого подписки по URL"""
        try:
            response = requests.get(
                url, 
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            if response.status_code == 200:
                content = response.text
                # Проверяем, закодирован ли контент в base64
                if self.is_base64(content):
                    try:
                        content = base64.b64decode(content).decode('utf-8')
                    except:
                        pass
                return content
        except Exception as e:
            print(f"⚠️ Ошибка при загрузке {url}: {str(e)}")
        return ""
    
    def is_base64(self, s: str) -> bool:
        """Проверка, является ли строка base64"""
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s)
            return True
        except:
            return False
    
    def parse_vmess(self, config: str) -> Dict:
        """Парсинг VMess конфигурации"""
        try:
            if config.startswith('vmess://'):
                config = config.replace('vmess://', '')
                # Добавляем padding для корректного декодирования
                padding = '=' * (4 - len(config) % 4) if len(config) % 4 != 0 else ''
                config += padding
                decoded = base64.b64decode(config).decode('utf-8')
                data = json.loads(decoded)
                return {
                    'type': 'vmess',
                    'server': data.get('add', ''),
                    'port': int(data.get('port', 0)),
                    'country': self.detect_country(data.get('ps', '')),
                    'name': data.get('ps', 'Unknown')
                }
        except Exception as e:
            pass
        return None
    
    def parse_vless(self, config: str) -> Dict:
        """Парсинг VLESS конфигурации"""
        try:
            if config.startswith('vless://'):
                # vless://uuid@server:port?params#name
                match = re.match(r'vless://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?', config)
                if match:
                    uuid, server, port, params, name = match.groups()
                    return {
                        'type': 'vless',
                        'server': server,
                        'port': int(port),
                        'country': self.detect_country(name or ''),
                        'name': name or 'Unknown'
                    }
        except:
            pass
        return None
    
    def parse_trojan(self, config: str) -> Dict:
        """Парсинг Trojan конфигурации"""
        try:
            if config.startswith('trojan://'):
                # trojan://password@server:port?params#name
                match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?', config)
                if match:
                    password, server, port, params, name = match.groups()
                    return {
                        'type': 'trojan',
                        'server': server,
                        'port': int(port),
                        'country': self.detect_country(name or ''),
                        'name': name or 'Unknown'
                    }
        except:
            pass
        return None
    
    def parse_shadowsocks(self, config: str) -> Dict:
        """Парсинг Shadowsocks конфигурации"""
        try:
            if config.startswith('ss://'):
                # ss://base64(method:password)@server:port#name
                match = re.match(r'ss://([^@]+)@([^:]+):(\d+)(?:#(.*))?', config)
                if match:
                    encoded, server, port, name = match.groups()
                    # Декодируем method:password
                    padding = '=' * (4 - len(encoded) % 4) if len(encoded) % 4 != 0 else ''
                    decoded = base64.b64decode(encoded + padding).decode('utf-8')
                    return {
                        'type': 'shadowsocks',
                        'server': server,
                        'port': int(port),
                        'country': self.detect_country(name or ''),
                        'name': name or 'Unknown'
                    }
        except:
            pass
        return None
    
    def detect_country(self, name: str) -> str:
        """Определение страны из имени сервера"""
        name = name.lower()
        country_map = {
            'netherlands': ['netherlands', 'nl', 'holland', 'нидерланды', 'amsterdam'],
            'ukraine': ['ukraine', 'ua', 'ukr', 'украина', 'kyiv', 'kiev'],
            'germany': ['germany', 'de', 'ger', 'германия', 'berlin', 'frankfurt'],
            'latvia': ['latvia', 'lv', 'латвия', 'riga'],
            'united_kingdom': ['united kingdom', 'uk', 'gb', 'england', 'великобритания', 
                              'лондон', 'london', 'manchester'],
            'poland': ['poland', 'pl', 'польша', 'warsaw'],
            'finland': ['finland', 'fi', 'финляндия', 'helsinki'],
            'spain': ['spain', 'es', 'испания', 'madrid', 'barcelona'],
            'usa': ['usa', 'us', 'united states', 'америка', 'сша', 'new york', 
                   'los angeles', 'chicago', 'miami', 'dallas'],
            'lithuania': ['lithuania', 'lt', 'литва', 'vilnius'],
            'estonia': ['estonia', 'ee', 'эстония', 'tallinn'],
            'france': ['france', 'fr', 'франция', 'paris'],
            'india': ['india', 'in', 'индия', 'mumbai', 'delhi'],
            'canada': ['canada', 'ca', 'канада', 'toronto', 'vancouver'],
            'russia': ['russia', 'ru', 'россия', 'moscow', 'москва', 'saint petersburg']
        }
        
        # Проверяем каждую страну
        for country in self.countries:
            for keyword in country_map.get(country, []):
                if keyword in name:
                    return country
        return 'unknown'
    
    def check_server(self, server_info: Dict) -> Tuple[Dict, bool]:
        """Проверка доступности сервера"""
        try:
            server = server_info['server']
            port = server_info['port']
            
            # Пытаемся установить TCP соединение
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((server, port))
            sock.close()
            
            if result == 0:
                return server_info, True
            return server_info, False
        except:
            return server_info, False
    
    def process_subscriptions(self):
        """Основной метод обработки подписок"""
        print("🔄 Загрузка подписок...")
        subscriptions = self.load_subscriptions()
        print(f"📥 Найдено {len(subscriptions)} подписок")
        
        all_servers = []
        
        # Обрабатываем каждую подписку
        for i, sub_url in enumerate(subscriptions, 1):
            print(f"📥 [{i}/{len(subscriptions)}] Загрузка: {sub_url[:50]}...")
            content = self.fetch_subscription(sub_url)
            if content:
                # Разделяем на строки и парсим конфигурации
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Парсим в зависимости от типа
                    if line.startswith('vmess://'):
                        server = self.parse_vmess(line)
                    elif line.startswith('vless://'):
                        server = self.parse_vless(line)
                    elif line.startswith('trojan://'):
                        server = self.parse_trojan(line)
                    elif line.startswith('ss://'):
                        server = self.parse_shadowsocks(line)
                    else:
                        continue
                    
                    # Добавляем только серверы из нужных стран
                    if server and server['country'] in self.countries:
                        all_servers.append(server)
        
        print(f"\n📊 Найдено {len(all_servers)} серверов из выбранных стран")
        
        # Проверяем серверы
        print("🔍 Проверка доступности серверов...")
        working_servers = {country: [] for country in self.countries}
        checked = 0
        
        # Используем многопоточность для ускорения
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self.check_server, server) for server in all_servers]
            
            for future in as_completed(futures):
                server_info, is_working = future.result()
                checked += 1
                
                if is_working and server_info['country'] in self.countries:
                    country = server_info['country']
                    if len(working_servers[country]) < self.max_servers:
                        working_servers[country].append(server_info)
                
                # Обновляем прогресс
                print(f"✓ Проверено {checked}/{len(all_servers)} серверов", end='\r')
        
        print("\n" + "="*60)
        print("📋 РЕЗУЛЬТАТЫ ПРОВЕРКИ:")
        print("="*60)
        
        # Сохраняем результаты в файл
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Рабочие VPN серверы\n")
            f.write(f"# Дата проверки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Всего рабочих серверов: {sum(len(s) for s in working_servers.values())}\n\n")
            
            for country in self.countries:
                if working_servers[country]:
                    print(f"\n📍 {country.upper()}: {len(working_servers[country])} серверов")
                    f.write(f"## {country.upper()} ({len(working_servers[country])} серверов)\n")
                    
                    for server in working_servers[country]:
                        print(f"  ✅ {server['type'].upper()} - {server['server']}:{server['port']} - {server['name']}")
                        f.write(f"  - {server['type'].upper()} | {server['server']}:{server['port']} | {server['name']}\n")
                    
                    f.write("\n")
                else:
                    print(f"\n❌ {country.upper()}: нет рабочих серверов")
        
        total_working = sum(len(servers) for servers in working_servers.values())
        print(f"\n{'='*60}")
        print(f"✅ ИТОГО рабочих серверов: {total_working}")
        print(f"💾 Результаты сохранены в {self.output_file}")
        print(f"{'='*60}")

if __name__ == "__main__":
    # Создаем экземпляр класса и запускаем проверку
    checker = VPNChecker()
    checker.process_subscriptions()
