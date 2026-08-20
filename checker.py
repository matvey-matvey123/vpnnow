#!/usr/bin/env python3
import base64
import json
import re
import sys
from datetime import datetime
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        self.original_configs = {}  # Сохраняем оригинальные конфигурации
        
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
    
    def decode_url(self, text: str) -> str:
        """Декодирование URL-encoded текста"""
        try:
            from urllib.parse import unquote
            return unquote(text)
        except:
            return text
    
    def parse_vmess(self, config: str) -> Dict:
        try:
            if config.startswith('vmess://'):
                config_data = config.replace('vmess://', '')
                padding = '=' * (4 - len(config_data) % 4) if len(config_data) % 4 != 0 else ''
                config_data += padding
                decoded = base64.b64decode(config_data).decode('utf-8')
                data = json.loads(decoded)
                name = self.decode_url(data.get('ps', ''))
                return {
                    'type': 'vmess',
                    'server': data.get('add', ''),
                    'port': int(data.get('port', 0)),
                    'country': self.detect_country(name),
                    'name': name,
                    'original': config  # Сохраняем оригинальную конфигурацию
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
                    name = self.decode_url(name or '')
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
                    name = self.decode_url(name or '')
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
                    name = self.decode_url(name or '')
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
        name = self.decode_url(name.lower())
        country_map = {
            'netherlands': ['netherlands', 'nl', 'holland', 'нидерланды', 'amsterdam'],
            'ukraine': ['ukraine', 'ua', 'ukr', 'украина', 'kyiv', 'kiev'],
            'germany': ['germany', 'de', 'ger', 'германия', 'berlin', 'frankfurt', 'düsseldorf'],
            'latvia': ['latvia', 'lv', 'латвия', 'riga'],
            'united_kingdom': ['united kingdom', 'uk', 'gb', 'england', 'великобритания', 'лондон', 'london'],
            'poland': ['poland', 'pl', 'польша', 'warsaw'],
            'finland': ['finland', 'fi', 'финляндия', 'helsinki'],
            'spain': ['spain', 'es', 'испания', 'madrid', 'barcelona'],
            'usa': ['usa', 'us', 'united states', 'америка', 'сша', 'new york', 'los angeles'],
            'lithuania': ['lithuania', 'lt', 'литва', 'vilnius'],
            'estonia': ['estonia', 'ee', 'эстония', 'tallinn'],
            'france': ['france', 'fr', 'франция', 'paris'],
            'india': ['india', 'in', 'индия', 'mumbai', 'delhi'],
            'canada': ['canada', 'ca', 'канада', 'toronto', 'vancouver'],
            'russia': ['russia', 'ru', 'россия', 'moscow', 'москва']
        }
        
        for country in self.countries:
            for keyword in country_map.get(country, []):
                if keyword in name:
                    return country
        return 'unknown'
    
    def check_server(self, server_info: Dict) -> Tuple[Dict, bool]:
        try:
            server = server_info['server']
            port = server_info['port']
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((server, port))
            sock.close()
            return server_info, result == 0
        except:
            return server_info, False
    
    def process_subscriptions(self):
        print("Loading subscriptions...")
        subscriptions = self.load_subscriptions()
        
        all_servers = []
        
        for sub_url in subscriptions:
            content = self.fetch_subscription(sub_url)
            if content:
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
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
                    
                    if server and server['country'] in self.countries:
                        all_servers.append(server)
        
        print(f"Found {len(all_servers)} servers")
        
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
        
        # Сохраняем только чистые конфигурации
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for country in self.countries:
                if working_servers[country]:
                    for server in working_servers[country]:
                        # Записываем оригинальную конфигурацию без изменений
                        f.write(server['original'] + '\n')
        
        total = sum(len(s) for s in working_servers.values())
        print(f"Working servers: {total}")
        print(f"Saved to {self.output_file}")

if __name__ == "__main__":
    checker = VPNChecker()
    checker.process_subscriptions()
