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
        
        # Российские прокси для проверки
        self.russian_proxies = [
            "http://45.8.158.176:10801",
            "http://31.172.67.43:443",
            "http://171.22.134.12:443",
            "http://185.246.152.159:443",
            "http://91.132.197.5:443",
            "http://65.21.240.108:443",
            "http://65.109.134.191:80",
            "http://95.216.186.191:80"
        ]
        
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
    
    def fetch_subscription_via_proxy(self, url: str, proxy: str = None) -> str:
        """Загрузка подписки через прокси"""
        try:
            proxies = {'http': proxy, 'https': proxy} if proxy else None
            response = requests.get(
                url, 
                timeout=15, 
                verify=False, 
                headers={'User-Agent': 'Mozilla/5.0'},
                proxies=proxies
            )
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
    
    def fetch_subscription(self, url: str) -> str:
        """Загрузка подписки с fallback на прокси"""
        # Сначала пробуем напрямую
        content = self.fetch_subscription_via_proxy(url)
        if content:
            return content
        
        # Если не получилось, пробуем через российские прокси
        for proxy in self.russian_proxies:
            content = self.fetch_subscription_via_proxy(url, proxy)
            if content:
                print(f"Loaded via proxy: {proxy}")
                return content
        
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
            decoded = unquote(name)
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
        
        # Сначала проверяем полные названия
        for country in self.countries:
            for keyword in country_map.get(country, []):
                if keyword in name_lower:
                    return country
        
        # Если не нашли, пробуем по IP
        return 'unknown'
    
    def check_server_from_russia(self, server_info: Dict) -> Tuple[Dict, bool]:
        """Проверка сервера через российские прокси"""
        server = server_info['server']
        port = server_info['port']
        
        # Сначала пробуем напрямую
        if self.check_tcp(server, port):
            return server_info, True
        
        # Если напрямую не работает, пробуем через российские прокси
        for proxy_addr in self.russian_proxies:
            try:
                # Извлекаем IP и порт прокси
                proxy_ip = proxy_addr.replace('http://', '').split(':')[0]
                proxy_port = int(proxy_addr.replace('http://', '').split(':')[1])
                
                # Проверяем через SOCKS5 прокси
                import socks
                socks.set_default_proxy(socks.SOCKS5, proxy_ip, proxy_port)
                socket.socket = socks.socksocket
                
                if self.check_tcp(server, port):
                    return server_info, True
            except:
                continue
        
        return server_info, False
    
    def check_tcp(self, server: str, port: int) -> bool:
        """Простая проверка TCP соединения"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((server, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_server(self, server_info: Dict) -> Tuple[Dict, bool]:
        """Основная проверка сервера"""
        # Пробуем разные способы проверки
        methods = [
            self.check_tcp,
            lambda s, p: self.check_tcp_via_proxy(s, p),
            lambda s, p: self.check_tcp_via_http(s, p)
        ]
        
        for method in methods:
            try:
                if method(server_info['server'], server_info['port']):
                    return server_info, True
            except:
                continue
        
        return server_info, False
    
    def check_tcp_via_proxy(self, server: str, port: int) -> bool:
        """Проверка через HTTP прокси"""
        for proxy in self.russian_proxies:
            try:
                import socks
                proxy_ip = proxy.replace('http://', '').split(':')[0]
                proxy_port = int(proxy.replace('http://', '').split(':')[1])
                
                socks.set_default_proxy(socks.SOCKS5, proxy_ip, proxy_port)
                socket.socket = socks.socksocket
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((server, port))
                sock.close()
                
                if result == 0:
                    return True
            except:
                continue
        return False
    
    def check_tcp_via_http(self, server: str, port: int) -> bool:
        """Проверка через HTTP запрос"""
        for proxy in self.russian_proxies:
            try:
                response = requests.get(
                    f"http://{server}:{port}",
                    timeout=3,
                    proxies={'http': proxy, 'https': proxy},
                    verify=False
                )
                if response.status_code < 500:
                    return True
            except:
                continue
        return False
    
    def process_subscriptions(self):
        print("Loading subscriptions...")
        subscriptions = self.load_subscriptions()
        
        all_servers = []
        seen_servers = set()
        
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
                    server_info, is_working = future.result(timeout=10)
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
