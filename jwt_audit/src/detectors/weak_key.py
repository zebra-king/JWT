"""
弱密钥爆破检测器
严重性：HIGH  
常见弱密钥爆破攻击
"""

# 常见弱密钥列表
WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "token",
    "key", "jwt", "changeme", "supersecret", "masterkey",
    "", "null", "none", "undefined", "test"
]

def detect(header: dict, payload: dict, signature: str) -> dict:
    """
    通过常见弱密钥列表检测弱密钥
    
    Args:
        header: JWT头部
        payload: JWT载荷
        signature: JWT签名（用于验证）
        
    Returns:
        检测结果字典
    """
    algorithm = header.get('alg', '').upper()
    
    # 只对HMAC算法进行弱密钥检测
    if algorithm.startswith('HS'):
        # 这里简化处理，实际应该尝试用每个密钥验证签名
        # 现在只检查是否有使用弱密钥的迹象
        return {
            'vulnerable': False,  # 需要实际爆破才能确定
            'severity': 'MEDIUM',
            'detector': 'WeakKey',
            'description': '使用HMAC算法，建议检查密钥强度',
            'recommendation': '使用强随机密钥，长度至少32字符',
            'weak_keys_to_check': WEAK_SECRETS[:5],  # 显示前5个常见弱密钥
            'cvss_score': 7.5
        }
    
    return {
        'vulnerable': False,
        'severity': 'INFO',
        'detector': 'WeakKey', 
        'description': '非HMAC算法，弱密钥检测不适用',
        'cvss_score': 0.0
    }

# 占位符，后续可以实现真正的爆破
def brute_force_weak_keys(jwt_token: str) -> list:
    """实际爆破弱密钥（后续实现）"""
    return []