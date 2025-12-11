"""
None算法漏洞检测器
严重性：CRITICAL
CWE-303: 使用密码学弱点的认证绕过
"""

def detect(header: dict, payload: dict, signature: str) -> dict:
    """
    检测JWT是否使用危险的'none'算法
    
    Args:
        header: JWT头部
        payload: JWT载荷  
        signature: JWT签名
        
    Returns:
        检测结果字典
    """
    algorithm = header.get('alg', '').lower()
    
    if algorithm == 'none':
        return {
            'vulnerable': True,
            'severity': 'CRITICAL',
            'detector': 'NoneAlgorithm',
            'description': 'JWT使用"none"算法，攻击者可完全绕过签名验证',
            'recommendation': '立即停止使用none算法，改用HS256/RS256等安全算法',
            'exploit_poc': _generate_exploit_poc(header, payload),
            'cvss_score': 9.1,
            'cwe': 'CWE-303'
        }
    
    return {
        'vulnerable': False,
        'severity': 'LOW', 
        'detector': 'NoneAlgorithm',
        'description': '未检测到None算法漏洞',
        'cvss_score': 0.0
    }

def _generate_exploit_poc(header: dict, payload: dict) -> str:
    """生成攻击验证POC"""
    import base64
    import json
    
    # 修改头部为none算法
    exploit_header = header.copy()
    exploit_header['alg'] = 'none'
    
    # Base64Url编码
    def base64url_encode(data: dict) -> str:
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
        return encoded.rstrip('=')
    
    header_b64 = base64url_encode(exploit_header)
    payload_b64 = base64url_encode(payload)
    
    # None算法的JWT没有签名部分
    return f"{header_b64}.{payload_b64}."

# 测试函数
if __name__ == "__main__":
    # 测试用例
    test_cases = [
        ({'alg': 'HS256', 'typ': 'JWT'}, {}, "", "安全算法"),
        ({'alg': 'none', 'typ': 'JWT'}, {'user': 'admin'}, "", "危险算法"),
        ({'alg': 'RS256'}, {}, "", "安全算法"),
    ]
    
    print("🧪 None算法检测器测试")
    print("=" * 50)
    
    for header, payload, signature, description in test_cases:
        result = detect(header, payload, signature)
        status = "❌ 漏洞" if result['vulnerable'] else "✅ 安全"
        print(f"{status} | {description}")
        if result['vulnerable']:
            print(f"   攻击POC: {result['exploit_poc']}")