#!/usr/bin/env python3
import base64
import json
import re
import sys
from datetime import datetime
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote
import requests
import socket
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VPNChecker:
    def __init__(self):
        with open('config.json', 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        self.countries = self.config['countries']
        self.max_servers = self.config['max_servers_per_country']
        self.timeout = self.config['timeout']
        self.output_file = self.config['output_file']
        
    def load_subscriptions(self) -> List[str]:
        subscriptions = []
        try:
            with open('subscriptions.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        subscriptions.append(line)
        except FileNotFoundError:
            print("File not found")
            sys.exit(1)
        return subscriptions
    
    def fetch_subscription(self, url: str) -> str:
        try:
            response = requests.get(url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                content = response.text
                if self.is_base64(content):
                    try:
                        content = base64.b64decode(content).decode('utf-8')
                    except:
                        pass
                return content
        except:
            pass
        return ""
    
    def is_base64(self, s: str) -> bool:
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s)
            return True
        except:
            return False
    
    def decode_name(self, name: str) -> str:
        """Декодирование имени сервера"""
        try:
            # Декодируем URL-encoded
            decoded = unquote(name)
            # Декодируем Unicode escape sequences
            decoded = decoded.encode('utf-8').decode('unicode_escape', errors='ignore')
            return decoded
        except:
            return name
    
    def parse_vmess(self, config: str) -> Dict:
        try:
            if config.startswith('vmess://'):
                config_data = config.replace('vmess://', '')
                padding = '=' * (4 - len(config_data) % 4) if len(config_data) % 4 != 0 else ''
                config_data += padding
                decoded = base64.b64decode(config_data).decode('utf-8')
                data = json.loads(decoded)
                name = self.decode_name(data.get('ps', ''))
                return {
                    'type': 'vmess',
                    'server': data.get('add', ''),
                    'port': int(data.get('port', 0)),
                    'country': self.detect_country(name),
                    'name': name,
                    'original': config
                }
        except:
            pass
        return None
    
    def parse_vless(self, config: str) -> Dict:
        try:
            if config.startswith('vless://'):
                # Расширенный regex для разных форматов
                match = re.match(r'vless://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?', config)
                if match:
                    uuid, server, port, params, name = match.groups()
                    name = self.decode_name(name or '')
                    return {
                        'type': 'vless',
                        'server': server,
                        'port': int(port),
                        'country': self.detect_country(name),
                        'name': name,
                        'original': config
                    }
        except:
            pass
        return None
    
    def parse_trojan(self, config: str) -> Dict:
        try:
            if config.startswith('trojan://'):
                match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?', config)
                if match:
                    password, server, port, params, name = match.groups()
                    name = self.decode_name(name or '')
                    return {
                        'type': 'trojan',
                        'server': server,
                        'port': int(port),
                        'country': self.detect_country(name),
                        'name': name,
                        'original': config
                    }
        except:
            pass
        return None
    
    def parse_shadowsocks(self, config: str) -> Dict:
        try:
            if config.startswith('ss://'):
                match = re.match(r'ss://([^@]+)@([^:]+):(\d+)(?:#(.*))?', config)
                if match:
                    encoded, server, port, name = match.groups()
                    name = self.decode_name(name or '')
                    return {
                        'type': 'shadowsocks',
                        'server': server,
                        'port': int(port),
                        'country': self.detect_country(name),
                        'name': name,
                        'original': config
                    }
        except:
            pass
        return None
    
    def detect_country(self, name: str) -> str:
        """Улучшенное определение страны"""
        name_lower = name.lower()
        
        # Расширенный список ключевых слов
        country_map = {
            'netherlands': ['netherlands', 'nl', 'holland', 'нидерланд', 'amsterdam', '🇳🇱'],
            'ukraine': ['ukraine', 'ua', 'ukr', 'украин', 'kyiv', 'kiev', '🇺🇦'],
            'germany': ['germany', 'de', 'ger', 'герман', 'berlin', 'frankfurt', 'düsseldorf', '🇩🇪'],
            'latvia': ['latvia', 'lv', 'латви', 'riga', '🇱🇻'],
            'united_kingdom': ['united kingdom', 'uk', 'gb', 'england', 'britain', 'великобритан', 
                              'лондон', 'london', 'manchester', '🇬🇧'],
            'poland': ['poland', 'pl', 'польш', 'warsaw', '🇵🇱'],
            'finland': ['finland', 'fi', 'финлянд', 'helsinki', '🇫🇮'],
            'spain': ['spain', 'es', 'испан', 'madrid', 'barcelona', '🇪🇸'],
            'usa': ['usa', 'us', 'united states', 'америк', 'сша', 'new york', 
                   'los angeles', 'chicago', 'miami', 'dallas', '🇺🇸'],
            'lithuania': ['lithuania', 'lt', 'литв', 'vilnius', '🇱🇹'],
            'estonia': ['estonia', 'ee', 'эстон', 'tallinn', '🇪🇪'],
            'france': ['france', 'fr', 'франц', 'paris', '🇫🇷'],
            'india': ['india', 'in', 'инди', 'mumbai', 'delhi', '🇮🇳'],
            'canada': ['canada', 'ca', 'канад', 'toronto', 'vancouver', '🇨🇦'],
            'russia': ['russia', 'ru', 'росси', 'moscow', 'москв', '🇷🇺']
        }
        
        for country in self.countries:
            for keyword in country_map.get(country, []):
                if keyword in name_lower:
                    return country
        return 'unknown'
    
    def check_server(self, server_info: Dict) -> Tuple[Dict, bool]:
        try:
            server = server_info['server']
            port = server_info['port']
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Уменьшаем таймаут для скорости
            result = sock.connect_ex((server, port))
            sock.close()
            return server_info, result == 0
        except:
            return server_info, False
    
    def process_subscriptions(self):
        print("Loading subscriptions...")
        subscriptions = self.load_subscriptions()
        
        all_servers = []
        seen_servers = set()  # Для удаления дубликатов
        
        for sub_url in subscriptions:
            print(f"Processing: {sub_url[:50]}...")
            content = self.fetch_subscription(sub_url)
            if content:
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    server = None
                    if line.startswith('vmess://'):
                        server = self.parse_vmess(line)
                    elif line.startswith('vless://'):
                        server = self.parse_vless(line)
                    elif line.startswith('trojan://'):
                        server = self.parse_trojan(line)
                    elif line.startswith('ss://'):
                        server = self.parse_shadowsocks(line)
                    
                    if server and server['country'] in self.countries:
                        # Удаляем дубликаты
                        server_key = f"{server['server']}:{server['port']}"
                        if server_key not in seen_servers:
                            seen_servers.add(server_key)
                            all_servers.append(server)
        
        print(f"Found {len(all_servers)} unique servers")
        
        # Проверяем серверы
        working_servers = {country: [] for country in self.countries}
        checked = 0
        
        # 100 потоков
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.check_server, server) for server in all_servers]
            
            for future in as_completed(futures):
                try:
                    server_info, is_working = future.result(timeout=5)
                    checked += 1
                    
                    if is_working and server_info['country'] in self.countries:
                        country = server_info['country']
                        if len(working_servers[country]) < self.max_servers:
                            working_servers[country].append(server_info)
                except:
                    checked += 1
                
                if checked % 50 == 0:
                    print(f"Checked: {checked}/{len(all_servers)}")
        
        # Сохраняем чистые конфигурации
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for country in self.countries:
                for server in working_servers[country]:
                    f.write(server['original'] + '\n')
        
        # Выводим статистику
        total = sum(len(s) for s in working_servers.values())
        print(f"\nWorking servers: {total}")
        for country in self.countries:
            if working_servers[country]:
                print(f"{country}: {len(working_servers[country])}")
        
        print(f"\nSaved to {self.output_file}")

if __name__ == "__main__":
    checker = VPNChecker()
    checker.process_subscriptions()
