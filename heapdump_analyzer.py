#!/usr/bin/env python3
import re
import sys
import mmap
import json
import threading
import math
import hashlib
import binascii
from pathlib import Path
from collections import defaultdict, OrderedDict
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
import argparse
import time


class HeapForensicAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.content: Optional[str] = None
        self.analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.string_stats = defaultdict(int)
        self.class_metadata = defaultdict(lambda: {'count': 0, 'samples': set(), 'locations': set()})
        self.unique_strings = set()
        self.severity_weights = OrderedDict([
            ('critical', 5),
            ('high', 4),
            ('medium', 3),
            ('low', 2),
            ('info', 1)
        ])
        
        self.compiled_patterns = self._compile_patterns()
        self.threat_intel = self._load_threat_intel()
        self.crypto_indicators = self._load_crypto_indicators()
        self.sensitive_keywords = self._load_sensitive_keywords()
        self.heap_structures = self._identify_heap_structures()
        self.string_entropy_threshold = 4.5
        self.max_credential_distance = 300
        self.max_session_length = 5000

    def _compile_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Compile advanced regex patterns for forensic analysis"""
        return {
            'credentials': {
                'patterns': [
                    (re.compile(r'(?i)(password|passwd|pwd|secret)[=:]\s*[\'"]?([^\s\'",;>{}\[\]\n]{6,})'), 3, 'high'),
                    (re.compile(r'(?i)(api[_-]?key|secret|token)[=:]\s*[\'"]?([a-z0-9_-]{20,50})'), 3, 'high'),
                    (re.compile(r'(?i)(aws_?access_?key_?id|aws_?secret_?access_?key)\s*[=:]\s*[\'"]?([a-z0-9/+]{20,40})'), 3, 'critical'),
                    (re.compile(r'(?i)(bearer|basic)\s+([a-z0-9-._~+/]+=*)'), 2, 'high'),
                    (re.compile(r'(?i)(client_?id|client_?secret)[=:]\s*[\'"]?([a-z0-9_-]{10,50})'), 3, 'high')
                ],
                'description': "Authentication credentials and secrets"
            },
            'usernames': {
                'patterns': [
                    (re.compile(r'(?i)(username|user|login|uid)[=:]\s*[\'"]?([^\s\'",;>{}\[\]\n]{3,})'), 3, 'medium'),
                    (re.compile(r'[a-z][a-z0-9_-]{2,30}(?=\W)'), 1, 'low'),
                    (re.compile(r'([a-z][a-z0-9_-]{2,30})@[a-z0-9.-]+\.[a-z]{2,6}'), 1, 'medium')
                ],
                'description': "User identifiers and login names"
            },
            'tokens': {
                'patterns': [
                    (re.compile(r'\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+\b'), 1, 'high'),
                    (re.compile(r'[a-f0-9]{32,}'), 1, 'medium'),
                    (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), 1, 'medium')
                ],
                'description': "Session tokens and unique identifiers"
            },
            'connections': {
                'patterns': [
                    (re.compile(r'((jdbc|mysql|postgresql|mongodb)://[^\s\'"]+?password=[^\s\'",&]+)'), 1, 'high'),
                    (re.compile(r'(https?://[^:\s]+:[^@\s]+@[^\s\'"]+)'), 1, 'high'),
                    (re.compile(r'(?i)datasource.+?(username|password)=[^\s\'"]+'), 1, 'high')
                ],
                'description': "Database and service connections"
            },
            'security': {
                'patterns': [
                    (re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END \1 PRIVATE KEY-----'), 1, 'critical'),
                    (re.compile(r'<password>[^<]+</password>'), 1, 'high'),
                    (re.compile(r'(?i)security[-_]?token[=:]\s*[\'"]?([^\s\'"]+)'), 2, 'high')
                ],
                'description': "Security configurations and keys"
            },
            'configurations': {
                'patterns': [
                    (re.compile(r'(?i)(debug|testing|dev)[=:]\s*[\'"]?(true|1|enable)'), 2, 'medium'),
                    (re.compile(r'(?i)log[-_]?level[=:]\s*[\'"]?(debug|trace)'), 2, 'low')
                ],
                'description': "Application configuration values"
            },
            'http_requests': {
                'patterns': [
                    (re.compile(r'(?i)(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|CONNECT|TRACE)\s+https?://[^\s\'"]+'), 1, 'medium'),
                    (re.compile(r'(?i)Host:\s*([^\s\'"]+)'), 1, 'low'),
                    (re.compile(r'(?i)Path:\s*([^\s\'"]+)'), 1, 'low'),
                    (re.compile(r'(?i)User-Agent:\s*([^\n\'"]+)'), 1, 'low'),
                    (re.compile(r'(?i)(curl|wget)\s+.+\s+https?://[^\s\'"]+'), 1, 'medium'),
                    (re.compile(r'^Host:\s+\S+$', re.MULTILINE), 1, 'medium'),
                    (re.compile(r'(?i)^Host:\s+\S+$.*?(?:\n.*?){0,10}', re.MULTILINE | re.DOTALL), 1, 'medium')
                ],
                'description': "HTTP requests found in memory"
            },
            'authorization': {
                'patterns': [
                    (re.compile(r'(?i)Authorization:\s*(Bearer\s+[a-z0-9-._~+/]+=*)'), 1, 'critical'),
                    (re.compile(r'(?i)Authorization:\s*(Basic\s+[a-z0-9+/]+=*)'), 1, 'high'),
                    (re.compile(r'(?i)api[-_]?key:\s*([a-z0-9-]+)'), 1, 'high'),
                    (re.compile(r'(?i)x-api-key:\s*([a-z0-9-]+)'), 1, 'high'),
                    (re.compile(r'(?i)session[-_]?id:\s*([a-z0-9-]+)'), 1, 'high'),
                    (re.compile(r'(?i)cookie:\s*.*session(?:id)?=([a-z0-9-]+)'), 1, 'high')
                ],
                'description': "Authorization headers and API keys"
            },
            'iocs': {
                'patterns': [
                    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 1, 'medium'),
                    (re.compile(r'(?i)([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}'), 1, 'low'),
                    (re.compile(r'[0-9a-fA-F]{32}'), 1, 'medium'),
                    (re.compile(r'[0-9a-fA-F]{64}'), 1, 'medium')
                ],
                'description': "Indicators of Compromise"
            },
            'auth_pairs': {
                'patterns': [
                    (re.compile(r'(?i)(?:user|username|login|uid)[=:]\s*[\'"]?([^\s\'",;>{}\[\]\n]{3,})[\'"]?\s*(?:password|passwd|pwd)[=:]\s*[\'"]?([^\s\'",;>{}\[\]\n]{6,})'), 3, 'critical'),
                    (re.compile(r'(?i)(?:password|passwd|pwd)[=:]\s*[\'"]?([^\s\'",;>{}\[\]\n]{6,})[\'"]?\s*(?:user|username|login|uid)[=:]\s*[\'"]?([^\s\'",;>{}\[\]\n]{3,})'), 3, 'critical'),
                    (re.compile(r'(?i)"username"\s*:\s*"([^"]+)"\s*,\s*"password"\s*:\s*"([^"]+)"'), 3, 'critical'),
                    (re.compile(r'(?i)<username>([^<]+)</username>\s*<password>([^<]+)</password>'), 3, 'critical'),
                    (re.compile(r'(?i)(?:user|username|login|uid)\s*=\s*([^\s;&]+)\s*&\s*(?:password|passwd|pwd)\s*=\s*([^\s;&]+)'), 3, 'critical')
                ],
                'description': "Username-password pairs found together"
            },
            'crypto_material': {
                'patterns': [
                    (re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END \1 PRIVATE KEY-----'), 1, 'critical'),
                    (re.compile(r'-----BEGIN (CERTIFICATE|PUBLIC KEY)-----[\s\S]+?-----END \1-----'), 1, 'high'),
                    (re.compile(r'(?i)(ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+)\s+[a-z0-9/+]+=*\s*'), 1, 'high'),
                    (re.compile(r'(?i)(md5|sha1|sha256|sha512):[a-f0-9]{32,128}'), 1, 'medium')
                ],
                'description': "Cryptographic keys and certificates"
            },
            'memory_artifacts': {
                'patterns': [
                    (re.compile(r'java\.lang\.String @ 0x[0-9a-f]+:\s*"(.*)"'), 1, 'info'),
                    (re.compile(r'java\.lang\.Class @ 0x[0-9a-f]+:\s*(.*)'), 1, 'info'),
                    (re.compile(r'instance of (.*) @ 0x[0-9a-f]+'), 1, 'info')
                ],
                'description': "Memory structure artifacts"
            }
        }

    def _load_threat_intel(self) -> Dict[str, Set[str]]:
        """Load threat intelligence data from external sources"""
        return {
            'known_malicious_ips': {'192.168.1.100', '10.0.0.5', '185.143.223.47'},
            'suspicious_domains': {'evil.com', 'malware.net', 'phishing.org'},
            'vulnerable_versions': {'Log4j 2.0-beta9', 'Apache Struts 2.3.5', 'Spring Framework 4.3.0'},
            'malicious_strings': {'eval(base64_decode(', 'shell_exec(', 'phpinfo()'},
            'attack_patterns': {'../../etc/passwd', '%00', '${jndi:ldap://'}
        }

    def _load_crypto_indicators(self) -> Dict[str, Any]:
        """Load indicators for cryptographic material detection"""
        return {
            'key_patterns': [
                re.compile(r'[A-Za-z0-9+/=]{40,}'),
                re.compile(r'[0-9a-f]{64}'),
                re.compile(r'[0-9a-f]{128}')
            ],
            'entropy_threshold': 4.8
        }

    def _load_sensitive_keywords(self) -> Dict[str, List[str]]:
        """Load sensitive keywords for contextual analysis"""
        return {
            'security': ['password', 'secret', 'token', 'key', 'credential', 'auth'],
            'database': ['jdbc', 'connection', 'query', 'sql', 'mongo', 'redis'],
            'config': ['url', 'host', 'port', 'endpoint', 'api', 'config'],
            'financial': ['creditcard', 'ssn', 'account', 'bank', 'payment']
        }

    def _identify_heap_structures(self) -> Dict[str, Any]:
        """Identify common heap structures for better analysis"""
        return {
            'java_string': re.compile(r'java\.lang\.String @ 0x[0-9a-f]+:\s*"(.*)"'),
            'java_class': re.compile(r'java\.lang\.Class @ 0x[0-9a-f]+:\s*(.*)'),
            'array': re.compile(r'array of (.*) @ 0x[0-9a-f]+'),
            'instance': re.compile(r'instance of (.*) @ 0x[0-9a-f]+')
        }

    def load_heap_dump(self) -> bool:
        """Memory-map the heap dump file with improved error handling and preprocessing"""
        try:
            if not self.file_path.exists():
                raise FileNotFoundError(f"File {self.file_path} not found")
                
            file_size = self.file_path.stat().st_size
            if file_size > 1024**3:
                print(f"[!] Warning: Large file ({file_size/1024/1024:.2f} MB), analysis may be slow")
                
            with self.file_path.open('rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    self.content = mm.read().decode('utf-8', errors='ignore')
            
            print(f"[*] Loaded {file_size/1024/1024:.2f} MB of data")
            return True
            
        except Exception as e:
            print(f"[!] Failed to load heap dump: {str(e)}", file=sys.stderr)
            return False

    def analyze_strings(self) -> None:
        """Advanced string analysis with entropy calculation and contextual analysis"""
        print("\n[+] Performing deep string analysis with entropy and contextual checks...")
        
        string_refs = re.finditer(
            r'java/lang/String @ 0x[0-9a-f]+:.*?\n\s*.*?\n\s*.*?\n\s*"(.*)"', 
            self.content,
            re.DOTALL
        )
        
        for match in string_refs:
            s = match.group(1).strip()
            if 0 < len(s) < 1024:
                self.unique_strings.add(s)
                self.string_stats[len(s)] += 1
                
                entropy = self.calculate_entropy(s)
                if entropy > self.string_entropy_threshold and len(s) > 16:
                    if 'high_entropy_strings' not in self.class_metadata:
                        self.class_metadata['high_entropy_strings'] = {'count': 0, 'samples': set(), 'locations': set()}
                    self.class_metadata['high_entropy_strings']['count'] += 1
                    truncated = s[:100] + ('...' if len(s) > 100 else '')
                    self.class_metadata['high_entropy_strings']['samples'].add(truncated)
                    self.class_metadata['high_entropy_strings']['locations'].add(match.start())
                
                if '.' in s and len(s) < 256:
                    class_name = s.split(' ')[0]
                    self.class_metadata[class_name]['count'] += 1
                    if len(self.class_metadata[class_name]['samples']) < 5:
                        self.class_metadata[class_name]['samples'].add(s)
                    self.class_metadata[class_name]['locations'].add(match.start())
                
                self._check_sensitive_context(s, match.start())

    def _check_sensitive_context(self, string: str, offset: int) -> None:
        """Check if string appears in sensitive contexts"""
        for category, keywords in self.sensitive_keywords.items():
            if any(keyword.lower() in string.lower() for keyword in keywords):
                if f'sensitive_{category}' not in self.class_metadata:
                    self.class_metadata[f'sensitive_{category}'] = {'count': 0, 'samples': set(), 'locations': set()}
                self.class_metadata[f'sensitive_{category}']['count'] += 1
                self.class_metadata[f'sensitive_{category}']['samples'].add(string[:200])
                self.class_metadata[f'sensitive_{category}']['locations'].add(offset)

    def calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string with improved accuracy"""
        if not string:
            return 0
        entropy = 0
        length = len(string)
        for x in range(256):
            p_x = float(string.count(chr(x))) / length
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def detect_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Run all detection patterns with enhanced validation and threat intel checks"""
        results = defaultdict(lambda: {'matches': [], 'count': 0, 'threat_matches': 0})
        
        for category, config in self.compiled_patterns.items():
            for pattern, groups, severity in config['patterns']:
                for match in pattern.finditer(self.content):
                    value, context = self._extract_match_values(match, groups)
                    
                    if value and self.validate_finding(category, value):
                        is_threat = self.check_threat_intel(category, value)
                        if is_threat:
                            results[category]['threat_matches'] += 1
                            
                        results[category]['matches'].append({
                            'value': value,
                            'context': context,
                            'severity': severity,
                            'offset': match.start(),
                            'is_threat': is_threat,
                            'entropy': self.calculate_entropy(value) if category in ['credentials', 'tokens'] else None
                        })
                        results[category]['count'] += 1
        
        return results

    def _extract_match_values(self, match: re.Match, groups: int) -> Tuple[Optional[str], Optional[str]]:
        """Extract values from regex matches"""
        if groups == 1:
            return match.group(0), None
        elif match.lastindex >= 2 and match.group(2):
            return match.group(2), match.group(1)
        return None, None

    def validate_finding(self, category: str, value: str) -> bool:
        """Validate findings to reduce false positives"""
        if len(value) < 3:
            return False
            
        if category == 'usernames':
            if re.search(r'[\\/<>\[\]{}]', value):
                return False
                
        elif category == 'credentials':
            if len(value) < 6 or not re.search(r'[a-zA-Z0-9]', value):
                return False
                
        return True

    def check_threat_intel(self, category: str, value: str) -> bool:
        """Check if value matches known threat indicators"""
        if category == 'iocs':
            if value in self.threat_intel['known_malicious_ips']:
                return True
            if any(d in value for d in self.threat_intel['suspicious_domains']):
                return True
        elif category == 'configurations':
            if any(v in value for v in self.threat_intel['vulnerable_versions']):
                return True
        elif category in ['credentials', 'tokens']:
            if any(m in value.lower() for m in self.threat_intel['malicious_strings']):
                return True
        return False

    def detect_crypto_material(self) -> List[Dict[str, Any]]:
        """Specialized detection for cryptographic material"""
        crypto_findings = []
        
        if 'high_entropy_strings' in self.class_metadata:
            for sample in self.class_metadata['high_entropy_strings']['samples']:
                if self.calculate_entropy(sample) > self.crypto_indicators['entropy_threshold']:
                    crypto_findings.append({
                        'type': 'high_entropy_key',
                        'value': sample,
                        'entropy': self.calculate_entropy(sample),
                        'severity': 'high'
                    })
        
        for pattern in self.crypto_indicators['key_patterns']:
            for match in pattern.finditer(self.content):
                value = match.group(0)
                crypto_findings.append({
                    'type': 'crypto_pattern',
                    'value': value,
                    'pattern': pattern.pattern,
                    'severity': 'medium' if len(value) < 64 else 'high'
                })
        
        return crypto_findings

    def detect_memory_structures(self) -> Dict[str, Any]:
        """Identify and analyze memory structures in the heap dump"""
        structures = defaultdict(list)
        
        for name, pattern in self.heap_structures.items():
            for match in pattern.finditer(self.content):
                value = match.group(1) if match.lastindex else match.group(0)
                structures[name].append({
                    'value': value,
                    'offset': match.start(),
                    'context': self._get_context(match.start(), 50)
                })
        
        return dict(structures)

    def _get_context(self, offset: int, length: int) -> str:
        """Get surrounding context from the heap dump"""
        start = max(0, offset - length)
        end = min(len(self.content), offset + length)
        return self.content[start:end]

    def detect_attack_patterns(self) -> List[Dict[str, Any]]:
        """Detect known attack patterns and exploitation attempts"""
        attack_findings = []
        
        for pattern in self.threat_intel['attack_patterns']:
            escaped = re.escape(pattern)
            regex = re.compile(escaped, re.IGNORECASE)
            for match in regex.finditer(self.content):
                attack_findings.append({
                    'type': 'attack_pattern',
                    'pattern': pattern,
                    'value': match.group(0),
                    'offset': match.start(),
                    'severity': 'critical' if 'jndi' in pattern.lower() else 'high'
                })
        
        return attack_findings

    def analyze_object_references(self) -> Dict[str, Any]:
        """Analyze object references and relationships in the heap"""
        references = defaultdict(list)
        ref_pattern = re.compile(r'@ 0x[0-9a-f]+ references (.*?)\n', re.IGNORECASE)
        
        for match in ref_pattern.finditer(self.content):
            refs = match.group(1).split(', ')
            for ref in refs:
                ref = ref.strip()
                if ref:
                    references[ref].append(match.start())
        
        return {
            'object_references': dict(references),
            'most_referenced': sorted(references.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        }

    def find_credential_pairs(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced credential pair detection with contextual analysis"""
        pairs = []
        
        if 'auth_pairs' in findings:
            for match in findings['auth_pairs']['matches']:
                if len(match['value']) == 2:
                    pairs.append({
                        'username': match['value'][0],
                        'password': match['value'][1],
                        'source': 'direct_pair',
                        'distance': 0,
                        'context': match.get('context', ''),
                        'severity': 'critical'
                    })
        
        if 'usernames' in findings and 'credentials' in findings:
            username_offsets = [(m['offset'], m['value'], m.get('context', '')) 
                              for m in findings['usernames']['matches']]
            password_offsets = [(m['offset'], m['value'], m.get('context', '')) 
                              for m in findings['credentials']['matches']]
            
            for u_offset, username, u_context in username_offsets[:1000]:
                closest = None
                for p_offset, password, p_context in password_offsets:
                    distance = abs(u_offset - p_offset)
                    if distance < self.max_credential_distance:
                        if closest is None or distance < closest['distance']:
                            combined_context = f"{u_context}\n...\n{p_context}" if u_context and p_context else ""
                            closest = {
                                'username': username,
                                'password': password,
                                'source': 'proximity',
                                'distance': distance,
                                'context': combined_context,
                                'severity': 'high' if distance < 100 else 'medium'
                            }
                
                if closest:
                    pairs.append(closest)
        
        unique_pairs = {}
        for pair in pairs:
            key = (pair['username'], pair['password'])
            if key not in unique_pairs or pair['distance'] < unique_pairs[key]['distance']:
                unique_pairs[key] = pair
        
        scored_pairs = []
        for pair in unique_pairs.values():
            score = 0
            if pair['source'] == 'direct_pair':
                score += 100
            score += max(0, 100 - pair['distance'] // 5)
            if pair.get('severity') == 'critical':
                score += 50
            
            pair['confidence_score'] = min(100, score)
            scored_pairs.append(pair)
        
        return sorted(scored_pairs, key=lambda x: (-x['confidence_score'], x['distance']))[:100]

    def analyze_http_sessions(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Advanced HTTP session reconstruction with timeline analysis"""
        sessions = []
        
        if 'http_requests' not in findings or 'authorization' not in findings:
            return sessions
        
        timeline = []
        for req in findings['http_requests']['matches']:
            timeline.append({
                'type': 'request',
                'offset': req['offset'],
                'value': req['value'],
                'severity': req['severity'],
                'context': req.get('context', '')
            })
        
        for auth in findings['authorization']['matches']:
            timeline.append({
                'type': 'auth',
                'offset': auth['offset'],
                'value': auth['value'],
                'severity': auth['severity'],
                'context': auth.get('context', '')
            })
        
        timeline.sort(key=lambda x: x['offset'])
        
        current_session = []
        for event in timeline:
            if event['type'] == 'request':
                if current_session:
                    sessions.append(self._analyze_http_session(current_session))
                    current_session = []
                current_session.append(event)
            elif event['type'] == 'auth' and current_session:
                if event['offset'] - current_session[-1]['offset'] < self.max_session_length:
                    current_session.append(event)
        
        if current_session:
            sessions.append(self._analyze_http_session(current_session))
        
        for session in sessions:
            score = 0
            score += min(50, session['request_count'] * 5)
            if any('/api/' in req or '/admin/' in req for req in session['requests']):
                score += 30
            if session['max_severity'] == 'critical':
                score += 50
            
            session['confidence_score'] = min(100, score)
        
        return sorted(sessions, key=lambda x: (-x['confidence_score'], -x['request_count']))[:50]

    def _analyze_http_session(self, session_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze a single HTTP session with enhanced details"""
        session = {
            'requests': [],
            'auth_tokens': set(),
            'start_offset': session_events[0]['offset'],
            'end_offset': session_events[-1]['offset'],
            'request_count': 0,
            'max_severity': 'low',
            'endpoints': set(),
            'methods': set(),
            'user_agents': set()
        }
        
        for event in session_events:
            if event['type'] == 'request':
                session['requests'].append({
                    'raw': event['value'],
                    'offset': event['offset'],
                    'context': event.get('context', '')
                })
                session['request_count'] += 1
                
                method_match = re.search(r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s', event['value'])
                if method_match:
                    session['methods'].add(method_match.group(1))
                
                url_match = re.search(r'https?://[^\s\'"]+', event['value'])
                if url_match:
                    session['endpoints'].add(url_match.group(0))
                
                ua_match = re.search(r'User-Agent:\s*([^\n\'"]+)', event['value'])
                if ua_match:
                    session['user_agents'].add(ua_match.group(1))
            else:
                session['auth_tokens'].add(event['value'])
                if self.severity_weights.get(event['severity'], 0) > self.severity_weights.get(session['max_severity'], 0):
                    session['max_severity'] = event['severity']
        
        return session

    def generate_report(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive forensic report with enhanced details"""
        report = {
            'metadata': self._generate_metadata(),
            'findings': {},
            'sessions': self.analyze_http_sessions(findings),
            'credential_pairs': self.find_credential_pairs(findings),
            'class_metadata': dict(sorted(self.class_metadata.items(), 
                                       key=lambda x: x[1]['count'], 
                                       reverse=True)[:50]),
            'crypto_material': self.detect_crypto_material(),
            'memory_structures': self.detect_memory_structures(),
            'attack_patterns': self.detect_attack_patterns(),
            'object_references': self.analyze_object_references(),
            'risk_analysis': self._calculate_enhanced_risks(findings)
        }
        
        for category, config in self.compiled_patterns.items():
            if category in findings:
                report['findings'][category] = {
                    'description': config['description'],
                    'count': findings[category]['count'],
                    'threat_matches': findings[category]['threat_matches'],
                    'samples': [self._sanitize_match(m) for m in findings[category]['matches'][:20]],
                    'max_severity': max((m['severity'] for m in findings[category]['matches']), 
                                  key=lambda x: self.severity_weights.get(x, 0)) 
                                  if findings[category]['matches'] else 'none',
                    'locations': [m['offset'] for m in findings[category]['matches'][:100]]
                }
        
        return report

    def _generate_metadata(self) -> Dict[str, Any]:
        """Generate report metadata"""
        return {
            'filename': str(self.file_path),
            'analysis_time': self.analysis_time,
            'total_strings': len(self.unique_strings),
            'unique_classes': len(self.class_metadata),
            'string_stats': dict(sorted(self.string_stats.items(), 
                                      key=lambda x: x[1], 
                                      reverse=True)[:10])
        }

    def _sanitize_match(self, match: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize match data for reporting"""
        return {
            'value': match['value'][:200] + ('...' if len(match['value']) > 200 else ''),
            'severity': match['severity'],
            'is_threat': match.get('is_threat', False),
            'entropy': match.get('entropy')
        }

    def _calculate_enhanced_risks(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate detailed risk scores with weighted components"""
        risks = {
            'score': 0,
            'components': defaultdict(int),
            'critical_findings': [],
            'weighted_components': {
                'credentials': 5,
                'auth_pairs': 10,
                'crypto_material': 8,
                'authorization': 7,
                'attack_patterns': 9,
                'sessions': 6
            }
        }
        
        for category, data in findings.items():
            for match in data['matches']:
                weight = self.severity_weights.get(match['severity'], 0)
                risks['components'][category] += weight
                
                if match['severity'] == 'critical':
                    risks['critical_findings'].append({
                        'category': category,
                        'value': match['value'][:100],
                        'context': match.get('context'),
                        'offset': match['offset']
                    })
        
        weighted_score = 0
        max_possible = 0
        
        for category, weight in risks['weighted_components'].items():
            if category in risks['components']:
                weighted_score += risks['components'][category] * weight
                max_possible += 100 * weight
        
        if max_possible > 0:
            risks['score'] = min(100, (weighted_score / max_possible) * 100)
        
        risks['indicators'] = self._identify_risk_indicators(findings)
        
        return risks

    def _identify_risk_indicators(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify specific risk indicators in the findings"""
        indicators = []
        
        if 'crypto_material' in findings:
            for match in findings['crypto_material']['matches']:
                if match['severity'] == 'critical':
                    indicators.append({
                        'type': 'exposed_private_key',
                        'severity': 'critical',
                        'description': 'Private cryptographic key found in memory'
                    })
        
        if 'attack_patterns' in findings:
            for pattern in findings['attack_patterns']:
                if 'jndi' in pattern['pattern'].lower():
                    indicators.append({
                        'type': 'log4j_exploit_attempt',
                        'severity': 'critical',
                        'description': 'Potential Log4j exploit attempt detected'
                    })
        
        if 'authorization' in findings:
            token_count = len(findings['authorization']['matches'])
            if token_count > 5:
                indicators.append({
                    'type': 'multiple_auth_tokens',
                    'severity': 'high',
                    'description': f'Multiple ({token_count}) authentication tokens found in memory'
                })
        
        return indicators

    def save_report(self, report: Dict[str, Any], format: str = 'json') -> None:
        """Save report in multiple formats with enhanced options"""
        base_name = self.file_path.stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{base_name}_forensic_report_{timestamp}.{format.lower()}"
        
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
            elif format.lower() == 'html':
                self._generate_html_report(report, filename)
            elif format.lower() == 'text':
                self._generate_text_report(report, filename)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
            print(f"[+] {format.upper()} report saved to {filename}")
        except Exception as e:
            print(f"[!] Failed to save report: {str(e)}", file=sys.stderr)

    def _generate_text_report(self, report: Dict[str, Any], filename: str) -> None:
        """Generate detailed text report with forensic findings"""
        with open(filename, 'w') as f:
            f.write(f"Heap Dump Forensic Analysis Report\n{'='*60}\n")
            f.write(f"File: {report['metadata']['filename']}\n")
            f.write(f"Analyzed: {report['metadata']['analysis_time']}\n")
            f.write(f"Total strings: {report['metadata']['total_strings']:,}\n")
            f.write(f"Unique classes: {report['metadata']['unique_classes']}\n")
            f.write(f"\nOverall Risk Score: {report['risk_analysis']['score']:.1f}/100\n")
            
            if report['risk_analysis']['indicators']:
                f.write("\nKey Risk Indicators:\n" + '-'*60 + "\n")
                for indicator in report['risk_analysis']['indicators']:
                    f.write(f"[{indicator['severity'].upper()}] {indicator['type']}: {indicator['description']}\n")
            
            if report['risk_analysis']['critical_findings']:
                f.write("\nCritical Findings:\n" + '-'*60 + "\n")
                for finding in report['risk_analysis']['critical_findings']:
                    f.write(f"[{finding['category']}] {finding['value']}\n")
                    if finding.get('context'):
                        f.write(f"Context: {finding['context'][:200]}...\n\n")
            
            if report['sessions']:
                f.write("\nHTTP Sessions (Top 5):\n" + '-'*60 + "\n")
                for i, session in enumerate(report['sessions'][:5], 1):
                    f.write(f"\nSession {i} (Confidence: {session['confidence_score']}%)\n")
                    f.write(f"Requests: {session['request_count']}\n")
                    f.write(f"Methods: {', '.join(session['methods'])}\n")
                    f.write(f"Auth Tokens: {len(session['auth_tokens'])}\n")
                    f.write(f"Sample Endpoints:\n")
                    for endpoint in list(session['endpoints'])[:3]:
                        f.write(f"- {endpoint[:120]}{'...' if len(endpoint) > 120 else ''}\n")
            
            if report['credential_pairs']:
                f.write("\nCredential Pairs Found (Top 20):\n" + '-'*60 + "\n")
                for i, pair in enumerate(report['credential_pairs'][:20], 1):
                    f.write(f"\nPair {i} (Confidence: {pair['confidence_score']}%)\n")
                    f.write(f"Source: {pair['source']}, Distance: {pair['distance']} bytes\n")
                    f.write(f"Username: {pair['username']}\n")
                    f.write(f"Password: {pair['password']}\n")
                    if pair.get('context'):
                        f.write(f"Context:\n{pair['context'][:300]}...\n")
            
            if report['crypto_material']:
                f.write("\nCryptographic Material Found:\n" + '-'*60 + "\n")
                for item in report['crypto_material']:
                    f.write(f"\nType: {item['type']}\n")
                    f.write(f"Value: {item['value'][:100]}...\n")
                    if 'entropy' in item:
                        f.write(f"Entropy: {item['entropy']:.2f}\n")
            
            f.write("\nDetailed Findings Summary:\n" + '-'*60 + "\n")
            for category, data in report['findings'].items():
                if data['count'] > 0:
                    f.write(f"\n{category.upper()} ({data['count']} found, {data['threat_matches']} threats)\n")
                    f.write(f"Description: {data['description']}\n")
                    f.write(f"Max Severity: {data['max_severity']}\n")
                    for i, match in enumerate(data['samples'][:5], 1):
                        f.write(f"{i}. {match['value']}\n")
            
            f.write("\nMemory Analysis:\n" + '-'*60 + "\n")
            f.write(f"Most Common Classes:\n")
            for class_name, meta in list(report['class_metadata'].items())[:10]:
                f.write(f"- {class_name}: {meta['count']} instances\n")
            
            if 'high_entropy_strings' in report['class_metadata']:
                f.write(f"\nHigh Entropy Strings: {report['class_metadata']['high_entropy_strings']['count']}\n")
            
            if report['object_references']:
                f.write("\nMost Referenced Objects:\n")
                for obj, refs in report['object_references']['most_referenced']:
                    f.write(f"- {obj}: referenced {len(refs)} times\n")

    def _generate_html_report(self, report: Dict[str, Any], filename: str) -> None:
        """Generate interactive HTML report with enhanced visualization"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Heap Dump Forensic Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2em; line-height: 1.6; }}
        .critical {{ color: #d9534f; font-weight: bold; }}
        .high {{ color: #f0ad4e; }}
        .medium {{ color: #5bc0de; }}
        .low {{ color: #5cb85c; }}
        .info {{ color: #777; }}
        pre {{ background: #f5f5f5; padding: 1em; border-radius: 4px; overflow-x: auto; }}
        .card {{ border: 1px solid #ddd; border-radius: 4px; padding: 1em; margin-bottom: 1em; }}
        .card-header {{ font-weight: bold; margin-bottom: 0.5em; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 1em; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .risk-meter {{ 
            height: 20px; 
            background: linear-gradient(to right, #5cb85c, #f0ad4e, #d9534f);
            border-radius: 4px;
            margin-bottom: 1em;
        }}
        .risk-indicator {{
            height: 100%;
            width: {report['risk_analysis']['score']}%;
            background-color: rgba(255,255,255,0.3);
        }}
    </style>
</head>
<body>
    <h1>Heap Dump Forensic Analysis Report</h1>
    <p>Generated: {report['metadata']['analysis_time']}</p>
    
    <div class="card">
        <div class="card-header">Analysis Summary</div>
        <p>File: {report['metadata']['filename']}</p>
        <p>Total strings analyzed: {report['metadata']['total_strings']:,}</p>
        <p>Unique classes identified: {report['metadata']['unique_classes']}</p>
    </div>
    
    <div class="card">
        <div class="card-header">Risk Assessment</div>
        <p>Overall Risk Score: {report['risk_analysis']['score']:.1f}/100</p>
        <div class="risk-meter">
            <div class="risk-indicator"></div>
        </div>
        
        <h3>Risk Indicators</h3>
        <table>
            <tr><th>Type</th><th>Severity</th><th>Description</th></tr>
            {"".join(
                f"<tr class='{indicator['severity']}'>"
                f"<td>{indicator['type']}</td>"
                f"<td>{indicator['severity']}</td>"
                f"<td>{indicator['description']}</td>"
                f"</tr>"
                for indicator in report['risk_analysis']['indicators'])
            }
        </table>
    </div>
    
    <div class="card">
        <div class="card-header">Critical Findings</div>
        <table>
            <tr><th>Category</th><th>Value</th><th>Context</th></tr>
            {"".join(
                f"<tr class='critical'>"
                f"<td>{finding['category']}</td>"
                f"<td>{finding['value']}</td>"
                f"<td>{finding.get('context', '')[:100]}{'...' if len(finding.get('context', '')) > 100 else ''}</td>"
                f"</tr>"
                for finding in report['risk_analysis']['critical_findings'])
            }
        </table>
    </div>
    
    <div class="card">
        <div class="card-header">HTTP Sessions (Top 5)</div>
        {"".join(
            f"<div style='margin-bottom: 1em; border-bottom: 1px solid #eee; padding-bottom: 1em;'>"
            f"<h3>Session {i+1} (Confidence: {session['confidence_score']}%)</h3>"
            f"<p>Requests: {session['request_count']} | Methods: {', '.join(session['methods'])}</p>"
            f"<p>Auth Tokens: {len(session['auth_tokens'])}</p>"
            f"<h4>Endpoints:</h4>"
            f"<ul>{"".join(f"<li>{endpoint[:120]}{'...' if len(endpoint) > 120 else ''}</li>" for endpoint in list(session['endpoints'])[:3])}</ul>"
            f"</div>"
            for i, session in enumerate(report['sessions'][:5]))
        }
    </div>
    
    <div class="card">
        <div class="card-header">Credential Pairs (Top 20)</div>
        <table>
            <tr><th>#</th><th>Username</th><th>Password</th><th>Source</th><th>Distance</th><th>Confidence</th></tr>
            {"".join(
                f"<tr>"
                f"<td>{i+1}</td>"
                f"<td>{pair['username']}</td>"
                f"<td>{pair['password']}</td>"
                f"<td>{pair['source']}</td>"
                f"<td>{pair['distance']}</td>"
                f"<td>{pair['confidence_score']}%</td>"
                f"</tr>"
                for i, pair in enumerate(report['credential_pairs'][:20]))
            }
        </table>
    </div>
    
    <div class="card">
        <div class="card-header">Cryptographic Material</div>
        <table>
            <tr><th>Type</th><th>Value</th><th>Entropy</th></tr>
            {"".join(
                f"<tr>"
                f"<td>{item['type']}</td>"
                f"<td><pre style='margin:0;'>{item['value'][:100]}{'...' if len(item['value']) > 100 else ''}</pre></td>"
                f"<td>{item.get('entropy', 'N/A')}</td>"
                f"</tr>"
                for item in report['crypto_material'])
            }
        </table>
    </div>
    
    <div class="card">
        <div class="card-header">Detailed Findings</div>
        {"".join(
            f"<div style='margin-bottom: 1em;'>"
            f"<h3>{cat.upper()} ({data['count']} found, {data['threat_matches']} threats)</h3>"
            f"<p>{data['description']} | Max Severity: <span class='{data['max_severity']}'>{data['max_severity']}</span></p>"
            f"<h4>Samples:</h4>"
            f"<ol>{"".join(f"<li><pre>{sample['value']}</pre></li>" for sample in data['samples'])}</ol>"
            f"</div>"
            for cat, data in report['findings'].items() if data['count'] > 0)
        }
    </div>
    
    <div class="card">
        <div class="card-header">Memory Analysis</div>
        <h3>Most Common Classes</h3>
        <table>
            <tr><th>Class</th><th>Count</th><th>Samples</th></tr>
            {"".join(
                f"<tr>"
                f"<td>{class_name}</td>"
                f"<td>{meta['count']}</td>"
                f"<td>{"<br>".join(meta['samples'])}</td>"
                f"</tr>"
                for class_name, meta in list(report['class_metadata'].items())[:10])
            }
        </table>
        
        <h3>Object References</h3>
        <table>
            <tr><th>Object</th><th>Reference Count</th></tr>
            {"".join(
                f"<tr>"
                f"<td>{obj}</td>"
                f"<td>{len(refs)}</td>"
                f"</tr>"
                for obj, refs in report['object_references']['most_referenced'])
            }
        </table>
    </div>
</body>
</html>
        """
        with open(filename, 'w') as f:
            f.write(html)

    def run_analysis(self, output_formats: list[str]) -> bool:

        if not self.load_heap_dump():
            return False

        print("Heapdump Analyzer by Ghost and Furious")

        print("[+] Starting advanced forensic analysis...")
        start_time = datetime.now()

        print("  [*] Performing string analysis...")
        self.analyze_strings()

        print("  [*] Detecting security patterns...")
        findings = self.detect_patterns()

        print("  [*] Running advanced forensic analysis...")
        report = self.generate_report(findings)

        print("  [*] Generating reports...")
        for fmt in output_formats:
            self.save_report(report, fmt)

        duration = (datetime.now() - start_time).total_seconds()

        print("\n[+] Analysis Complete")
        print(f"  Analysis duration: {duration:.2f} seconds")
        print(f"  Unique strings analyzed: {len(self.unique_strings):,}")
        print(f"  Critical findings: {len(report['risk_analysis']['critical_findings'])}")
        print(f"  HTTP sessions reconstructed: {len(report['sessions'])}")
        print(f"  Credential pairs found: {len(report['credential_pairs'])}")
        print(f"  Cryptographic material detected: {len(report['crypto_material'])}")
        print(f"  Threat intelligence matches: {sum(f['threat_matches'] for f in report['findings'].values())}")
        print(f"  Overall risk score: {report['risk_analysis']['score']:.1f}/100")

        return True

if __name__ == "__main__":



    parser = argparse.ArgumentParser(
        description="HeapForensicAnalyzer: A tool for forensic analysis of Java heap dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python heapdump_analyzer.py -f heapdump.hprof -o json         # Only generate JSON report
  python heapdump_analyzer.py -f heapdump.hprof -o html         # Only generate HTML report
  python heapdump_analyzer.py -f heapdump.hprof --all           # Generate JSON, HTML, and TXT reports
"""
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        required=True,
        help="Path to the Java heap dump file to analyze"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        choices=["json", "html", "text"],
        help="Specify output format: json, html, or text"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate all reports (json, html, and text)"
    )

    args = parser.parse_args()

    analyzer = HeapForensicAnalyzer(args.file)

    if args.all:
        output_formats = ["json", "html", "text"]
    elif args.output:
        output_formats = [args.output]
    else:
        print("[!] No output format specified. Use -o or --all")
        sys.exit(1)

    if not analyzer.run_analysis(output_formats):
        sys.exit(1)
                                           
