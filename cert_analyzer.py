import os
import subprocess
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import json
from collections import defaultdict
import platform

class CertificateAnalyzer:
    def __init__(self):
        self.os_type = self._detect_os()
        if self.os_type not in ['windows', 'macos']:
            raise SystemError("This tool only supports Windows and macOS")
            
        self.results = {
            'total_certs': 0,
            'issuers': defaultdict(int),
            'validity_periods': [],
            'algorithms': defaultdict(int),
            'expired_certs': 0,
            'cert_details': []
        }

    def _detect_os(self):
        """실행 중인 OS 탐지"""
        system = platform.system().lower()
        if system == 'darwin':
            return 'macos'
        elif system == 'windows':
            return 'windows'
        return system

    def _get_cert_paths(self):
        """OS별 인증서 경로 반환"""
        paths = {
            'windows': [
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\certmgr.msc')
            ],
            'macos': [
                '/System/Library/Keychains/SystemRootCertificates.keychain'
            ]
        }
        return paths.get(self.os_type, [])

    def extract_issuer_name(self, cert):
        """발급자 이름 추출"""
        issuer = cert.issuer
        oids = [
            NameOID.ORGANIZATION_NAME,
            NameOID.COMMON_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME
        ]
        
        name_parts = []
        for oid in oids:
            try:
                attrs = issuer.get_attributes_for_oid(oid)
                if attrs:
                    name_parts.append(attrs[0].value)
            except:
                continue
        
        if name_parts:
            name_parts = list(dict.fromkeys(name_parts))
            return " - ".join(name_parts)
        return str(issuer)

    def get_windows_certs(self):
        """Windows 인증서 추출"""
        try:
            # PowerShell 명령어로 인증서 추출
            cmd = [
                'powershell',
                '-Command',
                'Get-ChildItem -Path Cert:\\LocalMachine\\Root | ForEach-Object { [System.Convert]::ToBase64String($_.RawData) }'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error executing PowerShell command: {result.stderr}")
                return []
            
            certs = []
            for cert_b64 in result.stdout.strip().split('\n'):
                if cert_b64:
                    import base64
                    cert_der = base64.b64decode(cert_b64)
                    try:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        certs.append(cert)
                    except Exception as e:
                        print(f"Error loading certificate: {e}")
            return certs
        except Exception as e:
            print(f"Error getting Windows certificates: {e}")
            return []

    def get_macos_certs(self):
        """macOS 인증서 추출"""
        try:
            cmd = ['security', 'find-certificate', '-a', '-p', '/System/Library/Keychains/SystemRootCertificates.keychain']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Error executing security command: {result.stderr}")
                return []
            
            certs = []
            current_cert = []
            for line in result.stdout.splitlines():
                if '-----BEGIN CERTIFICATE-----' in line:
                    current_cert = [line]
                elif '-----END CERTIFICATE-----' in line:
                    current_cert.append(line)
                    cert_data = '\n'.join(current_cert)
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                        certs.append(cert)
                    except Exception as e:
                        print(f"Error loading certificate: {e}")
                elif current_cert:
                    current_cert.append(line)
            
            return certs
        except Exception as e:
            print(f"Error getting macOS certificates: {e}")
            return []

    def analyze_certs(self):
        """인증서 분석 실행"""
        print(f"Analyzing certificates on {self.os_type}...")
        
        if self.os_type == 'windows':
            certs = self.get_windows_certs()
        else:  # macOS
            certs = self.get_macos_certs()
        
        for cert in certs:
            self.analyze_cert(cert)
        
        return self._generate_report()

    def analyze_cert(self, cert):
        """개별 인증서 분석"""
        try:
            issuer = self.extract_issuer_name(cert)
            valid_from = cert.not_valid_before_utc
            valid_to = cert.not_valid_after_utc
            validity_period = (valid_to - valid_from).days
            
            signature_algorithm = cert.signature_algorithm_oid._name
            if signature_algorithm.startswith('SHA'):
                signature_algorithm = signature_algorithm.replace('_', '-')
            
            is_ecc = 'ecdsa' in signature_algorithm.lower()
            algorithm_type = 'ECC' if is_ecc else 'RSA'
            
            cert_info = {
                'issuer': issuer.strip(),
                'valid_from': valid_from.isoformat(),
                'valid_to': valid_to.isoformat(),
                'validity_period': validity_period,
                'signature_algorithm': signature_algorithm,
                'algorithm_type': algorithm_type,
                'is_expired': datetime.datetime.now(datetime.timezone.utc) > valid_to,
                'serial_number': format(cert.serial_number, 'X')
            }
            
            self._update_results(cert_info)
            
        except Exception as e:
            print(f"Error analyzing certificate: {e}")

    def _update_results(self, cert_info):
        """결과 데이터 업데이트"""
        self.results['total_certs'] += 1
        self.results['issuers'][cert_info['issuer']] += 1
        self.results['validity_periods'].append(cert_info['validity_period'])
        self.results['algorithms'][cert_info['signature_algorithm']] += 1
        if cert_info['is_expired']:
            self.results['expired_certs'] += 1
        self.results['cert_details'].append(cert_info)

    def _generate_report(self):
        """분석 보고서 생성"""
        if not self.results['validity_periods']:
            return None
            
        avg_validity = sum(self.results['validity_periods']) / len(self.results['validity_periods'])
        
        issuer_stats = {}
        for cert in self.results['cert_details']:
            issuer = cert['issuer']
            if issuer not in issuer_stats:
                issuer_stats[issuer] = {
                    'count': 0,
                    'avg_validity': [],
                    'algorithms': defaultdict(int),
                    'algorithm_types': defaultdict(int)
                }
            issuer_stats[issuer]['count'] += 1
            issuer_stats[issuer]['avg_validity'].append(cert['validity_period'])
            issuer_stats[issuer]['algorithms'][cert['signature_algorithm']] += 1
            issuer_stats[issuer]['algorithm_types'][cert['algorithm_type']] += 1
        
        for issuer in issuer_stats:
            validity_days = issuer_stats[issuer]['avg_validity']
            issuer_stats[issuer]['avg_validity'] = sum(validity_days) / len(validity_days)
        
        algorithm_types = defaultdict(int)
        for cert in self.results['cert_details']:
            algorithm_types[cert['algorithm_type']] += 1
        
        report = {
            'os_type': self.os_type,
            'total_certificates': self.results['total_certs'],
            'top_issuers': dict(sorted(issuer_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:15]),
            'average_validity_days': avg_validity,
            'expired_certificates': self.results['expired_certs'],
            'signature_algorithms': dict(self.results['algorithms']),
            'algorithm_types': dict(algorithm_types),
            'certificates': self.results['cert_details']
        }
        
        return report

def save_report(report, output_path):
    """보고서를 JSON 파일로 저장"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    try:
        analyzer = CertificateAnalyzer()
        report = analyzer.analyze_certs()
        
        if report:
            save_report(report, f'cert_report_{analyzer.os_type}.json')
            print(f"\n=== {analyzer.os_type.upper()} 인증서 분석 결과 ===")
            print(f"총 인증서 수: {report['total_certificates']}")
            
            print("\n주요 발급기관 (상위 15개):")
            for issuer, stats in report['top_issuers'].items():
                print(f"- {issuer}:")
                print(f"  인증서 수: {stats['count']}개")
                print(f"  평균 유효기간: {stats['avg_validity'] / 365:.1f}년")
                print(f"  알고리즘 분포: {dict(stats['algorithms'])}")
                print(f"  알고리즘 타입: {dict(stats['algorithm_types'])}")
            
            print(f"\n전체 평균 유효기간: {report['average_validity_days'] / 365:.1f}년")
            print(f"만료된 인증서 수: {report['expired_certificates']}")
            
            print("\n서명 알고리즘 분포:")
            for algo, count in report['signature_algorithms'].items():
                print(f"- {algo}: {count}개")
                
            print("\n알고리즘 타입 분포:")
            for type_name, count in report['algorithm_types'].items():
                print(f"- {type_name}: {count}개 ({count/report['total_certificates']*100:.1f}%)")
    except SystemError as e:
        print(f"Error: {e}")
        print("This tool only supports Windows and macOS operating systems.")