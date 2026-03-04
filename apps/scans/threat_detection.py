# apps/scans/threat_detection.py
import re
import socket
import requests
from urllib.parse import urlparse
import tldextract
import hashlib
import json
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
        
        # قوائم النطاقات المعروفة
        self.trusted_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'youtube.com',
            'linkedin.com', 'github.com', 'microsoft.com', 'apple.com',
            'instagram.com', 'whatsapp.com', 'amazon.com', 'netflix.com',
            'zoom.us', 'mozilla.org', 'wikipedia.org', 'yahoo.com',
            'bing.com', 'duckduckgo.com', 'telegram.org', 'spotify.com'
        ]
        
        # النطاقات شديدة الخطورة
        self.suspicious_tlds = [
            'xyz', 'top', 'work', 'date', 'racing', 'gdn', 'mom',
            'loan', 'download', 'review', 'trade', 'webcam', 'click',
            'online', 'site', 'website', 'space', 'tech', 'store',
            'shop', 'live', 'pro', 'fun', 'club', 'life', 'world',
            'info', 'biz', 'tk', 'ml', 'ga', 'cf', 'link', 'win'
        ]
        
        # الكلمات المفتاحية للتصيد
        self.phishing_keywords = [
            'login', 'signin', 'account', 'verify', 'secure',
            'update', 'confirm', 'password', 'credit', 'paypal',
            'bank', 'apple', 'microsoft', 'amazon', 'facebook',
            'instagram', 'whatsapp', 'netflix', 'تسجيل', 'دخول',
            'حساب', 'تأكيد', 'كلمة المرور', 'بنك', 'بطاقة'
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
        
        # تنفيذ الفحوصات بالتوازي
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
                    self.results['details'].append(f"⚠️ فشل فحص {check_name}")
        
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
            # التحقق من قاعدة البيانات المحلية
            from .models import Blacklist
            if Blacklist.objects.filter(link=url).exists() or Blacklist.objects.filter(domain=domain).exists():
                threats.append({
                    'type': 'blacklist',
                    'severity': 5,
                    'description': 'الرابط موجود في القائمة السوداء'
                })
                self.results['details'].append('⚠️ هذا الرابط موجود في قاعدة البيانات السوداء')
            else:
                self.results['details'].append('✓ الرابط غير مدرج في القائمة السوداء')
        except Exception as e:
            logger.error(f"خطأ في فحص blacklist: {e}")
        
        # التحقق من Google Safe Browsing (إذا كان المفتاح موجوداً)
        if hasattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY') and settings.GOOGLE_SAFE_BROWSING_API_KEY:
            try:
                gsb_result = self._check_google_safe_browsing(url)
                if gsb_result:
                    threats.extend(gsb_result)
            except Exception as e:
                logger.error(f"Google Safe Browsing error: {e}")
                self.results['details'].append('⚠️ تعذر الاتصال بـ Google Safe Browsing')
        else:
            self.results['details'].append('ℹ️ فحص Google Safe Browsing غير متاح')
        
        # التحقق من VirusTotal (إذا كان المفتاح موجوداً)
        if hasattr(settings, 'VIRUSTOTAL_API_KEY') and settings.VIRUSTOTAL_API_KEY:
            try:
                vt_result = self._check_virustotal(url)
                if vt_result:
                    threats.extend(vt_result)
            except Exception as e:
                logger.error(f"VirusTotal error: {e}")
                self.results['details'].append('⚠️ تعذر الاتصال بـ VirusTotal')
        else:
            self.results['details'].append('ℹ️ فحص VirusTotal غير متاح')
        
        return threats
    
    def _check_google_safe_browsing(self, url):
        """التحقق عبر Google Safe Browsing API"""
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            
            payload = {
                "client": {
                    "clientId": "safeclick",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
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
                        threat_type_ar = {
                            'MALWARE': 'برمجيات خبيثة',
                            'SOCIAL_ENGINEERING': 'تصيد احتيالي',
                            'UNWANTED_SOFTWARE': 'برمجيات غير مرغوب فيها',
                            'POTENTIALLY_HARMFUL_APPLICATION': 'تطبيقات ضارة محتملة'
                        }.get(match['threatType'], match['threatType'])
                        
                        threats.append({
                            'type': match['threatType'].lower(),
                            'severity': 5,
                            'description': f'تم اكتشاف {threat_type_ar}',
                            'source': 'Google Safe Browsing'
                        })
                    
                    self.results['details'].append(f'⚠️ Google Safe Browsing: تم اكتشاف {len(threats)} تهديد')
                    return threats
                else:
                    self.results['details'].append('✓ Google Safe Browsing: لا توجد تهديدات')
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Google Safe Browsing API connection error: {e}")
        except Exception as e:
            logger.error(f"Google Safe Browsing API error: {e}")
        
        return []
    
    def _check_virustotal(self, url):
        """التحقق عبر VirusTotal API"""
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            headers = {
                "x-apikey": settings.VIRUSTOTAL_API_KEY
            }
            
            response = requests.get(api_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0 or suspicious > 0:
                    threats = [{
                        'type': 'malicious' if malicious > 0 else 'suspicious',
                        'severity': 5 if malicious > 0 else 4,
                        'count': malicious + suspicious,
                        'description': f'{malicious + suspicious} محرك مضاد فيروس يشتبه بهذا الرابط',
                        'source': 'VirusTotal'
                    }]
                    
                    self.results['details'].append(f'⚠️ VirusTotal: {malicious + suspicious} محرك يشتبه بالرابط')
                    return threats
                else:
                    self.results['details'].append('✓ VirusTotal: جميع المحركات تعتبر الرابط آمناً')
            
            elif response.status_code == 404:
                self._submit_to_virustotal(url)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API connection error: {e}")
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        
        return []
    
    def _submit_to_virustotal(self, url):
        """إرسال رابط لتحليله في VirusTotal"""
        try:
            api_url = "https://www.virustotal.com/api/v3/urls"
            headers = {
                "x-apikey": settings.VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = {"url": url}
            
            response = requests.post(api_url, headers=headers, data=data, timeout=5)
            
            if response.status_code == 200:
                self.results['details'].append('✓ تم إرسال الرابط لتحليله في VirusTotal')
            
        except Exception as e:
            logger.error(f"VirusTotal submit error: {e}")
    
    def _check_url_structure(self, url, domain):
        """التحقق من بنية الرابط"""
        threats = []
        score_impact = 0
        
        # التحقق من استخدام HTTPS (أهمية عالية)
        if url.startswith('https://'):
            self.results['details'].append('✓ الرابط يستخدم بروتوكول HTTPS آمن')
        else:
            threats.append({
                'type': 'no_https',
                'severity': 4,  # زيادة الخطورة
                'description': 'الرابط لا يستخدم بروتوكول HTTPS'
            })
            self.results['details'].append('⚠️ خطر: الرابط لا يستخدم بروتوكول HTTPS')
            score_impact += 20  # زيادة تأثير النتيجة
        
        # التحقق من وجود @ في الرابط (خطير جداً)
        if '@' in url:
            threats.append({
                'type': 'suspicious_char',
                'severity': 5,
                'description': 'الرابط يحتوي على رمز @ مما يشير إلى محاولة تصيد'
            })
            self.results['details'].append('⚠️ خطر: الرابط يحتوي على رمز @ المشبوه')
            score_impact += 30
        
        # التحقق من استخدام IP بدلاً من النطاق
        ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        if ip_pattern.search(domain):
            threats.append({
                'type': 'ip_address',
                'severity': 5,
                'description': 'الرابط يستخدم عنوان IP بدلاً من اسم النطاق'
            })
            self.results['details'].append('⚠️ خطر: الرابط يستخدم عنوان IP بدلاً من اسم النطاق')
            score_impact += 25
        
        # التحقق من النطاقات الفرعية الكثيرة
        subdomains = domain.split('.')
        if len(subdomains) > 3:
            threats.append({
                'type': 'many_subdomains',
                'severity': 3,
                'description': 'الرابط يحتوي على نطاقات فرعية كثيرة'
            })
            self.results['details'].append('⚠️ تحذير: نطاقات فرعية كثيرة')
            score_impact += 10
        
        # التحقق من امتداد النطاق المشبوه
        try:
            extracted = tldextract.extract(url)
            if extracted.suffix in self.suspicious_tlds:
                threats.append({
                    'type': 'suspicious_tld',
                    'severity': 4,
                    'description': f'امتداد النطاق {extracted.suffix} غير موثوق'
                })
                self.results['details'].append(f'⚠️ تحذير: امتداد النطاق {extracted.suffix} مشبوه')
                score_impact += 15
        except:
            pass
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _check_domain_reputation(self, domain):
        """التحقق من سمعة النطاق"""
        threats = []
        score_impact = 0
        domain_info = {}
        
        try:
            import whois
            w = whois.whois(domain)
            
            domain_info['registrar'] = w.registrar
            domain_info['creation_date'] = str(w.creation_date) if w.creation_date else None
            
            # حساب عمر النطاق (أهمية عالية جداً)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if creation_date:
                    age = (datetime.datetime.now() - creation_date).days
                    domain_info['age_days'] = age
                    
                    # نطاقات جديدة جداً = خطيرة
                    if age < 7:  # أقل من أسبوع
                        threats.append({
                            'type': 'very_new_domain',
                            'severity': 5,
                            'description': 'النطاق جديد جداً (أقل من أسبوع)'
                        })
                        self.results['details'].append('⚠️ خطر: النطاق جديد جداً (أقل من أسبوع)')
                        score_impact += 25
                    elif age < 30:  # أقل من شهر
                        threats.append({
                            'type': 'new_domain',
                            'severity': 4,
                            'description': 'النطاق جديد (أقل من شهر)'
                        })
                        self.results['details'].append('⚠️ تحذير: النطاق جديد (أقل من شهر)')
                        score_impact += 20
                    elif age < 90:  # أقل من 3 أشهر
                        threats.append({
                            'type': 'recent_domain',
                            'severity': 3,
                            'description': 'النطاق حديث (أقل من 3 أشهر)'
                        })
                        self.results['details'].append('⚠️ تنبيه: النطاق حديث (أقل من 3 أشهر)')
                        score_impact += 10
            
            # النطاقات الموثوقة تخفض الخطورة
            if domain in self.trusted_domains or any(domain.endswith(f".{td}") for td in self.trusted_domains):
                self.results['details'].append('✓ النطاق معروف وموثوق')
                score_impact -= 20  # تخفيض كبير للنطاقات الموثوقة
            
        except ImportError:
            logger.error("WHOIS module not installed")
        except Exception as e:
            logger.error(f"WHOIS error: {e}")
        
        self.results['domain_info'] = domain_info
        return {'threats': threats, 'score_impact': score_impact, 'domain_info': domain_info}
    
    def _check_ip_reputation(self, domain):
        """التحقق من سمعة عنوان IP"""
        threats = []
        ip_info = {}
        score_impact = 0
        
        try:
            ip_address = socket.gethostbyname(domain)
            ip_info['ip'] = ip_address
            
            # التحقق من IP خاص
            if ip_address.startswith(('10.', '192.168.', '172.')):
                threats.append({
                    'type': 'private_ip',
                    'severity': 4,
                    'description': 'الرابط يشير إلى عنوان IP خاص'
                })
                self.results['details'].append('⚠️ تحذير: الرابط يشير إلى شبكة داخلية')
                score_impact += 15
            
            self.results['ip_address'] = ip_address
            
        except socket.gaierror:
            ip_info['error'] = 'لا يمكن حل النطاق'
            threats.append({
                'type': 'dns_resolution',
                'severity': 5,
                'description': 'لا يمكن حل النطاق - قد يكون غير صالح'
            })
            self.results['details'].append('⚠️ خطر: لا يمكن العثور على النطاق')
            score_impact += 25
        except Exception as e:
            logger.error(f"IP lookup error: {e}")
        
        self.results['ip_info'] = ip_info
        return {'threats': threats, 'score_impact': score_impact, 'ip_info': ip_info}
    
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
            
            # التحقق من تاريخ انتهاء الشهادة
            if cert and 'notAfter' in cert:
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.now()).days
                
                if days_remaining < 0:
                    threats.append({
                        'type': 'expired_ssl',
                        'severity': 5,
                        'description': 'شهادة SSL منتهية الصلاحية'
                    })
                    self.results['details'].append('⚠️ خطر: شهادة SSL منتهية الصلاحية')
                    score_impact += 25
                elif days_remaining < 7:
                    threats.append({
                        'type': 'expiring_ssl',
                        'severity': 3,
                        'description': f'شهادة SSL ستنتهي بعد {days_remaining} أيام'
                    })
                    self.results['details'].append(f'⚠️ تنبيه: شهادة SSL ستنتهي قريباً')
                    score_impact += 10
                else:
                    self.results['details'].append('✓ شهادة SSL صالحة')
            
        except socket.gaierror:
            self.results['details'].append('⚠️ لا يمكن التحقق من SSL')
        except Exception as e:
            logger.error(f"SSL check error: {e}")
        
        return {'threats': threats, 'score_impact': score_impact}
    
    def _check_content(self, url):
        """التحقق من محتوى الصفحة"""
        threats = []
        score_impact = 0
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
            
            self.results['server_info'] = response.headers.get('Server', 'غير معروف')
            self.results['response_time'] = response.elapsed.total_seconds()
            
            # التحقق من وجود إعادة توجيه كثيرة
            if response.history:
                redirect_count = len(response.history)
                if redirect_count > 2:
                    threats.append({
                        'type': 'multiple_redirects',
                        'severity': 3,
                        'description': f'الرابط يقوم بإعادة توجيه متعددة ({redirect_count})'
                    })
                    self.results['details'].append(f'⚠️ تحذير: إعادة توجيه متعددة')
                    score_impact += 15
            
            # البحث عن كلمات التصيد
            content_lower = response.text.lower()
            found_keywords = [kw for kw in self.phishing_keywords if kw in content_lower]
            
            if len(found_keywords) > 3:  # إذا وجد أكثر من 3 كلمات
                threats.append({
                    'type': 'phishing_content',
                    'severity': 4,
                    'description': 'الصفحة تحتوي على كلمات تصيد احتيالي'
                })
                self.results['details'].append('⚠️ خطر: الصفحة تحتوي على كلمات تصيد احتيالي')
                score_impact += 20
            elif found_keywords:
                threats.append({
                    'type': 'suspicious_content',
                    'severity': 2,
                    'description': 'الصفحة تحتوي على كلمات مشبوهة'
                })
                self.results['details'].append('⚠️ تنبيه: محتوى مشبوه محتمل')
                score_impact += 10
            
            # التحقق من وجود نموذج كلمة مرور
            if 'input' in content_lower and 'password' in content_lower:
                threats.append({
                    'type': 'login_form',
                    'severity': 2,
                    'description': 'الصفحة تحتوي على نموذج تسجيل دخول'
                })
                self.results['details'].append('ℹ️ الصفحة تحتوي على نموذج تسجيل دخول')
            
        except requests.exceptions.Timeout:
            threats.append({
                'type': 'timeout',
                'severity': 3,
                'description': 'الرابط لا يستجيب'
            })
            self.results['details'].append('⚠️ الرابط لا يستجيب')
            score_impact += 15
        except requests.exceptions.ConnectionError:
            threats.append({
                'type': 'connection_error',
                'severity': 4,
                'description': 'لا يمكن الاتصال بالرابط'
            })
            self.results['details'].append('⚠️ لا يمكن الاتصال بالرابط')
            score_impact += 20
        except Exception as e:
            logger.error(f"Content check error: {e}")
        
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
        
        for key in ['domain_info', 'ip_info', 'ip_address', 'server_info', 'response_time']:
            if key in result and result[key]:
                self.results[key] = result[key]
    
    def _calculate_final_score(self):
        """حساب النتيجة النهائية"""
        threat_count = len(self.results['threats_found'])
        total_severity = sum(t.get('severity', 1) for t in self.results['threats_found'])
        
        # النتيجة الأساسية
        base_score = 100
        
        # خصم صارم للتهديدات
        if threat_count > 0:
            # كل تهديد يخصم 15-30 نقطة حسب شدته
            base_score -= min(95, total_severity * 7)
        
        # تطبيق تأثير النتيجة من الفحوصات
        final_score = max(0, min(100, base_score - self.results['score']))
        self.results['score'] = final_score
        
        # تصنيف صارم جداً
        if final_score >= 70:  # عالية جداً
            self.results['safe'] = True
            if len(self.results['details']) == 0:
                self.results['details'].append('✓ الرابط آمن')
        elif final_score >= 40:  # متوسطة
            self.results['safe'] = None
            self.results['details'].insert(0, '⚠️ تحذير: الرابط مشبوه - يرجى توخي الحذر')
        else:  # منخفضة
            self.results['safe'] = False
            self.results['details'].insert(0, '🚫 خطر: هذا الرابط خطير! تجنب فتحه تماماً')
        
        self.results['threats_count'] = len(self.results['threats_found'])
        
        logger.info(f"نتيجة الفحص: {final_score}% - آمن: {self.results['safe']}")