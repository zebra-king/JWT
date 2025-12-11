"""
JWT安全审计引擎主模块
核心功能：JWT解码、漏洞检测、报告生成
"""

import base64
import json
import os
import sys
from typing import Dict, Tuple, List

# 添加当前目录到路径，以便导入detectors
sys.path.append(os.path.dirname(__file__))

def decode_jwt(token: str) -> Tuple[Dict, Dict, str]:
    """
    解码JWT令牌
    
    Args:
        token: JWT字符串
        
    Returns:
        (header字典, payload字典, 签名字符串)
        
    Raises:
        ValueError: JWT格式无效时抛出
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("JWT必须有header.payload.signature三部分")
        
        # Base64Url解码函数
        def base64url_decode(data: str) -> bytes:
            # 添加必要的填充
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            # Base64Url -> Base64
            data = data.replace('-', '+').replace('_', '/')
            return base64.b64decode(data)
        
        # 解码头部和载荷
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
        
        return header, payload, parts[2]
    
    except Exception as e:
        raise ValueError(f"JWT解码失败: {e}")

class JWTAuditor:
    """JWT安全审计器"""
    
    def __init__(self):
        self.detectors = []
        self._load_detectors()
    
    def _load_detectors(self):
        """动态加载所有检测器"""
        import importlib
    
        detectors_dir = os.path.join(os.path.dirname(__file__), 'detectors')
    
        if os.path.exists(detectors_dir):
            for filename in os.listdir(detectors_dir):
                if filename.endswith('.py') and filename != '__init__.py':
                    module_name = filename[:-3]  # 去掉.py后缀
                    try:
                        # 使用相对导入
                        if '.' in __name__:
                            # 如果auditor是被导入的，使用相对路径
                            base_package = __name__.rsplit('.', 1)[0]
                            full_module_name = f'{base_package}.detectors.{module_name}'
                        else:
                            # 如果auditor是主模块
                            full_module_name = f'detectors.{module_name}'
                    
                        # 使用importlib动态导入
                        module = importlib.import_module(full_module_name)
                    
                        if hasattr(module, 'detect'):
                            self.detectors.append(module.detect)
                            print(f"✅ 加载检测器: {module_name}")
                    except ImportError as e:
                        print(f"❌ 加载检测器 {module_name} 失败: {e}")
                    except AttributeError as e:
                        print(f"❌ 检测器 {module_name} 缺少detect函数: {e}")
    
    def audit(self, jwt_token: str) -> Dict:
        """
        执行JWT安全审计
        
        Args:
            jwt_token: 要审计的JWT字符串
            
        Returns:
            完整的审计结果字典
        """
        try:
            # 1. 解码JWT
            header, payload, signature = decode_jwt(jwt_token)
            
            # 2. 运行所有检测器
            findings = []
            for detector in self.detectors:
                try:
                    result = detector(header, payload, signature)
                    if result:  # 只添加有结果的检测
                        findings.append(result)
                except Exception as e:
                    print(f"⚠️ 检测器执行失败: {e}")
                    continue
            
            # 3. 计算安全评分和汇总
            security_score = 100
            critical_vulns = 0
            high_vulns = 0
            
            for finding in findings:
                if finding.get('vulnerable', False):
                    severity = finding.get('severity', 'LOW')
                    if severity == 'CRITICAL':
                        security_score -= 40
                        critical_vulns += 1
                    elif severity == 'HIGH':
                        security_score -= 30
                        high_vulns += 1
                    elif severity == 'MEDIUM':
                        security_score -= 20
                    elif severity == 'LOW':
                        security_score -= 10
            
            security_score = max(0, security_score)  # 确保不低于0
            
            return {
                'success': True,
                'jwt_token': jwt_token,
                'jwt_short': jwt_token[:30] + '...' if len(jwt_token) > 30 else jwt_token,
                'header': header,
                'payload': payload,
                'signature_length': len(signature),
                'findings': findings,
                'security_score': security_score,
                'summary': {
                    'total_checks': len(findings),
                    'vulnerabilities_found': sum(1 for f in findings if f.get('vulnerable', False)),
                    'critical_vulnerabilities': critical_vulns,
                    'high_vulnerabilities': high_vulns,
                    'status': 'SAFE' if security_score >= 80 else 'UNSAFE'
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'jwt_token': jwt_token
            }

def print_audit_report(audit_result: Dict):
    """打印格式化的审计报告"""
    if not audit_result['success']:
        print(f"❌ 审计失败: {audit_result['error']}")
        return
    
    data = audit_result
    summary = data['summary']
    
    print("\n" + "="*60)
    print("🔐 JWT SECURITY AUDIT REPORT")
    print("="*60)
    
    # 基本信息
    print(f"\n📄 JWT: {data['jwt_short']}")
    print(f"🔢 算法: {data['header'].get('alg', '未指定')}")
    print(f"📊 安全评分: {data['security_score']}/100")
    
    # 安全状态
    status_icon = "🟢" if summary['status'] == 'SAFE' else "🔴"
    print(f"📈 状态: {status_icon} {summary['status']}")
    
    # 统计信息
    print(f"\n📋 检测统计:")
    print(f"   检查总数: {summary['total_checks']}")
    print(f"   发现漏洞: {summary['vulnerabilities_found']}")
    print(f"   严重漏洞: {summary['critical_vulnerabilities']}")
    print(f"   高危漏洞: {summary['high_vulnerabilities']}")
    
    # 详细发现
    if data['findings']:
        print(f"\n🔍 详细检测结果:")
        print("-" * 40)
        
        for i, finding in enumerate(data['findings'], 1):
            vulnerable = finding.get('vulnerable', False)
            severity = finding.get('severity', 'INFO')
            
            # 选择图标和颜色
            icon = "❌" if vulnerable else "✅"
            color = {
                'CRITICAL': '🔴',
                'HIGH': '🟠', 
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': '⚪'
            }.get(severity, '⚪')
            
            print(f"{i}. {icon} {color} [{severity}] {finding['detector']}")
            print(f"   {finding['description']}")
            
            if vulnerable:
                if finding.get('recommendation'):
                    print(f"   💡 建议: {finding['recommendation']}")
                if finding.get('exploit_poc'):
                    print(f"   💥 POC: {finding['exploit_poc'][:80]}...")
            
            print()  # 空行分隔
    
    print("="*60)

# 测试函数
def test_auditor():
    """测试审计器功能"""
    test_jwts = {
        "安全JWT": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "None算法漏洞": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "无效JWT": "invalid.jwt.token"
    }
    
    auditor = JWTAuditor()
    
    for name, token in test_jwts.items():
        print(f"\n🧪 测试: {name}")
        print("-" * 30)
        
        result = auditor.audit(token)
        print_audit_report(result)

if __name__ == "__main__":
    test_auditor()