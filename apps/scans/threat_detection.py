# apps/scans/threat_detection.py
import re
import socket
import requests
from urllib.parse import urlparse
import tldextract
import hashlib
import logging
from django.conf import settings
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime

logger = logging.getLogger(__name__)

class ThreatDetector:
    """محرك الكشف عن التهديدات في الروابط"""
    
    def __init__(self):
        self.results = {
            'safe': None,
            'score': 0,
            'details': [],
            'threats_found': [],
            'domain_info': {},
            'ip_info': {}
        }
        
        # النطاقات الموثوقة
        self.trusted_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'youtube.com',
            'linkedin.com', 'github.com', 'microsoft.com', 'apple.com',
            'instagram.com', 'whatsapp.com', 'amazon.com'
        ]
        
        # النطاقات المشبوهة
        self.suspicious_tlds = [
            'xyz', 'top', 'work', 'date', 'racing', 'gdn', 'mom',
            'loan', 'download', 'review', 'trade', 'webcam', 'click',
            'online', 'site', 'website', 'space', 'tk', 'ml', 'ga', 'cf'
        ]
    
    def detect(self, url):
        """البدء في عملية الكشف"""
        logger.info(f"بدء فحص الرابط: {url}")
        
        # تنسيق الرابط
        url = self._normalize_url(url)
        
        # استخراج معلومات النطاق
        try:
            extracted = tldextract.extract(url)
            full_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        except:
            full_domain = url
        
        self.results['domain'] = full_domain
        self.results['full_url'] = url
        
        # تنفيذ الفحوصات
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self._check_blacklist, url, full_domain): 'blacklist',
                executor.submit(self._check_url_structure, url, full_domain): 'structure',
                executor.submit(self._check_domain_reputation, full_domain): 'reputation',
                executor.submit(self._check_ip_reputation, full_domain): 'ip',
                executor.submit(self._check_ssl_certificate, url): 'ssl',
                executor.submit(self._check_content, url): 'content',
            }
            
            for future in as_completed(futures):
                check_name = futures[future]
                try:
                    result = future.result(timeout=10)
                    if result:
                        self._process_check_result(check_name, result)
                except Exception as e:
                    logger.error(f"خطأ في فحص {check_name}: {e}")
        
        # حساب النتيجة النهائية
        self._calculate_final_score()
        
        return self.results
    
    def _normalize_url(self, url):
        """تنسيق الرابط"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def _check_blacklist(self, url, domain):
        """التحقق من القوائم السوداء"""
        threats = []
        
        try:
            from .models import Blacklist
            if Blacklist.objects.filter(link=url).exists() or Blacklist.objects.filter(domain=domain).exists():
                threats.append({
                    'type': 'blacklist',
                    'severity': 5,
                    'description': 'الرابط محظور'
                })
                self.results['details'].append('⚠️ الرابط محظور')
            else:
                self.results['details'].append('✓ الرابط غير محظور')
        except:
            pass
        
        # Google Safe Browsing
        if hasattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY') and settings.GOOGLE_SAFE_BROWSING_API_KEY:
            try:
                gsb_result = self._check_google_safe_browsing(url)
                if gsb_result:
                    threats.extend(gsb_result)
            except:
                pass
        
        # VirusTotal
        if hasattr(settings, 'VIRUSTOTAL_API_KEY') and settings.VIRUSTOTAL_API_KEY:
            try:
                vt_result = self._check_virustotal(url)
                if vt_result:
                    threats.extend(vt_result)
            except:
                pass
        
        return threats
    
    def _check_google_safe_browsing(self, url):
        """التحقق عبر Google Safe Browsing"""
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            
            payload = {
                "client": {"clientId": "safeclick", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if 'matches' in data:
                    threats = []
                    for match in data['matches']:
                        threats.append({
                            'type': 'google_safe',
                            'severity': 5,
                            'description': 'تهديد من Google',
                            'source': 'Google'
                        })
                    return threats
        except:
            pass
        return []
    
    def _check_virustotal(self, url):
        """التحقق عبر VirusTotal"""
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            response = requests.get(api_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    return [{
                        'type': 'virustotal',
                        'severity': 5,
                        'description': f'{malicious} محرك يشتبه',
                        'source': 'VirusTotal'
                    }]
        except:
            pass
        return []
    
    def _check_url_structure(self, url, domain):
        """التحقق من بنية الرابط"""
        threats = []
        score_impact = 0
        
        # HTTPS
        if not url.startswith('https://'):
            threats.append({
                'type': 'no_https',
                'severity': 3,
                'description': 'لا يستخدم HTTPS'
            })
            self.results['details'].append('⚠️ لا يستخدم HTTPS')
            score_impact += 15
        
        # وجود @
        if '@' in url:
            threats.append({
                'type': 'suspicious_char',
                'severity': 4,
                'description': 'يحتوي على @'
            })
            self.results['details'].append('⚠️ يحتوي على @')
            score_impact += 20
        
        # عنوان IP
        ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        if ip_pattern.search(domain):
            threats.append({
                'type': 'ip_address',
                'severity': 4,
                'description': 'يستخدم عنوان IP'
            })
            self.results['details'].append('⚠️ يستخدم IP')
            score_impact += 20
        
        # نطاق مشبوه
        try:
            extracted = tldextract.extract(url)
            if extracted.suffix in self.suspicious_tlds:
                threats.append({
                    'type': 'suspicious_tld',
                    'severity': 3,
                    'description': f'امتداد {extracted.suffix}'
                })
                self.results['details'].append(f'⚠️ امتداد {extracted.suffix}')
                score_impact += 10
        except:
            pass
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _check_domain_reputation(self, domain):
        """التحقق من سمعة النطاق"""
        threats = []
        score_impact = 0
        
        try:
            import whois
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                age = (datetime.datetime.now() - creation_date).days
                
                if age < 7:
                    threats.append({
                        'type': 'very_new_domain',
                        'severity': 5,
                        'description': 'نطاق جديد جداً'
                    })
                    self.results['details'].append('⚠️ نطاق جديد جداً')
                    score_impact += 25
                elif age < 30:
                    threats.append({
                        'type': 'new_domain',
                        'severity': 4,
                        'description': 'نطاق جديد'
                    })
                    self.results['details'].append('⚠️ نطاق جديد')
                    score_impact += 15
        except:
            pass
        
        # نطاق موثوق
        if domain in self.trusted_domains or any(domain.endswith(f".{td}") for td in self.trusted_domains):
            self.results['details'].append('✓ نطاق موثوق')
            score_impact -= 20
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _check_ip_reputation(self, domain):
        """التحقق من عنوان IP"""
        threats = []
        score_impact = 0
        
        try:
            ip_address = socket.gethostbyname(domain)
            self.results['ip_address'] = ip_address
            
            if ip_address.startswith(('10.', '192.168.', '172.')):
                threats.append({
                    'type': 'private_ip',
                    'severity': 3,
                    'description': 'IP خاص'
                })
                self.results['details'].append('⚠️ IP خاص')
                score_impact += 10
        except socket.gaierror:
            threats.append({
                'type': 'dns_error',
                'severity': 4,
                'description': 'لا يمكن حل النطاق'
            })
            self.results['details'].append('⚠️ لا يمكن حل النطاق')
            score_impact += 20
        except:
            pass
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _check_ssl_certificate(self, url):
        """التحقق من شهادة SSL"""
        threats = []
        score_impact = 0
        
        if not url.startswith('https://'):
            return {'threats': threats}
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            hostname = urlparse(url).netloc
            ctx = ssl.create_default_context()
            
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            
            if cert and 'notAfter' in cert:
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (expiry - datetime.now()).days
                
                if days < 0:
                    threats.append({
                        'type': 'expired_ssl',
                        'severity': 4,
                        'description': 'شهادة منتهية'
                    })
                    self.results['details'].append('⚠️ شهادة منتهية')
                    score_impact += 20
                elif days < 7:
                    threats.append({
                        'type': 'expiring_ssl',
                        'severity': 2,
                        'description': 'شهادة قريبة الانتهاء'
                    })
                    self.results['details'].append('⚠️ شهادة قريبة الانتهاء')
                    score_impact += 5
                else:
                    self.results['details'].append('✓ شهادة صالحة')
        except:
            self.results['details'].append('⚠️ لا يمكن التحقق من SSL')
            score_impact += 5
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _check_content(self, url):
        """التحقق من محتوى الصفحة"""
        threats = []
        score_impact = 0
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
            
            self.results['server_info'] = response.headers.get('Server', 'Unknown')
            self.results['response_time'] = response.elapsed.total_seconds()
            
            # كلمات مشبوهة
            suspicious_keywords = ['login', 'signin', 'password', 'credit', 'bank', 'paypal']
            content_lower = response.text.lower()
            
            found = [kw for kw in suspicious_keywords if kw in content_lower]
            if len(found) > 2:
                threats.append({
                    'type': 'suspicious_content',
                    'severity': 3,
                    'description': 'محتوى مشبوه'
                })
                self.results['details'].append('⚠️ محتوى مشبوه')
                score_impact += 10
        except:
            self.results['details'].append('⚠️ لا يمكن الوصول للمحتوى')
            score_impact += 5
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _process_check_result(self, check_name, result):
        """معالجة نتائج الفحص"""
        if not result:
            return
        
        if 'threats' in result:
            for threat in result['threats']:
                if threat not in self.results['threats_found']:
                    self.results['threats_found'].append(threat)
        
        if 'score_impact' in result:
            self.results['score'] += result['score_impact']
    
    def _calculate_final_score(self):
        """حساب النتيجة النهائية"""
        threat_count = len(self.results['threats_found'])
        total_severity = sum(t.get('severity', 1) for t in self.results['threats_found'])
        
        # النتيجة الأساسية
        base_score = 100
        
        # خصم التهديدات
        if threat_count > 0:
            base_score -= min(90, total_severity * 6)
        
        # النتيجة النهائية
        final_score = max(0, min(100, base_score - self.results['score']))
        self.results['score'] = final_score
        
        # تحديد الحالة النهائية (ناتج واحد فقط)
        if final_score >= 70:
            self.results['safe'] = True
            self.results['final_status'] = 'آمن'
            self.results['final_message'] = '✓ هذا الرابط آمن'
            if not self.results['details']:
                self.results['details'] = ['✓ الرابط آمن']
        elif final_score >= 40:
            self.results['safe'] = None
            self.results['final_status'] = 'مشبوه'
            self.results['final_message'] = '⚠️ هذا الرابط مشبوه، يرجى الحذر'
            if '⚠️' not in str(self.results['details']):
                self.results['details'].insert(0, '⚠️ الرابط مشبوه')
        else:
            self.results['safe'] = False
            self.results['final_status'] = 'خطير'
            self.results['final_message'] = '🔴 هذا الرابط خطير! تجنب فتحه'
            if '🔴' not in str(self.results['details']):
                self.results['details'].insert(0, '🔴 تحذير: رابط خطير')
        
        self.results['threats_count'] = len(self.results['threats_found'])
        
        logger.info(f"النتيجة النهائية: {final_score}% - {self.results['final_status']}")