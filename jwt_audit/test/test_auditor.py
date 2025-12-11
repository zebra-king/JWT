"""
JWT安全审计工具测试套件
包含单元测试和集成测试
"""

import unittest
import sys
import os
import json
import base64

# ========== 修复导入路径 ==========
# 获取当前测试文件所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取项目根目录（jwt_audit的父目录）
project_root = os.path.dirname(current_dir)
# 获取src目录路径
src_dir = os.path.join(project_root, 'src')

# 将src目录添加到Python路径
sys.path.insert(0, src_dir)

print(f"✅ 项目根目录: {project_root}")
print(f"✅ src目录: {src_dir}")
print(f"✅ Python路径: {sys.path}")

# 现在可以安全导入
try:
    from auditor import JWTAuditor, decode_jwt
    print("✅ 模块导入成功!")
except ImportError as e:
    print(f"❌ 导入失败: {e}")
    print("请检查文件路径和模块结构")
    exit(1)

class TestJWTAuditor(unittest.TestCase):
    """JWT审计器测试类"""
    
    def setUp(self):
        """测试前置设置"""
        self.auditor = JWTAuditor()
        
        # 测试用的JWT令牌
        self.valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.none_alg_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        self.invalid_jwt = "invalid.jwt.token"
    
    def test_decode_valid_jwt(self):
        """测试有效的JWT解码"""
        header, payload, signature = decode_jwt(self.valid_jwt)
        
        self.assertEqual(header['alg'], 'HS256')
        self.assertEqual(header['typ'], 'JWT')
        self.assertEqual(payload['sub'], '1234567890')
        self.assertEqual(payload['name'], 'John Doe')
        self.assertTrue(len(signature) > 0)
    
    def test_decode_invalid_jwt(self):
        """测试无效的JWT解码"""
        with self.assertRaises(ValueError):
            decode_jwt(self.invalid_jwt)
    
    def test_audit_safe_jwt(self):
        """测试安全JWT的审计"""
        result = self.auditor.audit(self.valid_jwt)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['header']['alg'], 'HS256')
        self.assertGreaterEqual(result['security_score'], 80)  # 安全JWT应该高分
        self.assertEqual(result['summary']['status'], 'SAFE')
    
    def test_audit_none_algorithm(self):
        """测试None算法漏洞检测"""
        result = self.auditor.audit(self.none_alg_jwt)
        
        self.assertTrue(result['success'])
        
        # 检查是否检测到漏洞
        vulnerabilities_found = result['summary']['vulnerabilities_found']
        self.assertGreater(vulnerabilities_found, 0)
        
        # 检查安全评分应该较低
        self.assertLess(result['security_score'], 80)
        self.assertEqual(result['summary']['status'], 'UNSAFE')
        
        # 检查具体漏洞信息
        critical_vulns = result['summary']['critical_vulnerabilities']
        self.assertGreaterEqual(critical_vulns, 1)
    
    def test_audit_invalid_token(self):
        """测试无效令牌的审计"""
        result = self.auditor.audit(self.invalid_jwt)
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_detectors_loaded(self):
        """测试检测器是否成功加载"""
        self.assertGreater(len(self.auditor.detectors), 0, "没有加载任何检测器")
    
    def test_jwt_structure_validation(self):
        """测试JWT结构验证"""
        # 测试部分不足的JWT
        short_jwt = "header.payload"  # 缺少签名部分
        with self.assertRaises(ValueError):
            decode_jwt(short_jwt)
        
        # 测试部分过多的JWT
        long_jwt = "header.payload.signature.extra"  # 多余部分
        with self.assertRaises(ValueError):
            decode_jwt(long_jwt)

class TestJWTEncoding(unittest.TestCase):
    """JWT编码相关测试"""
    
    def test_base64url_encoding(self):
        """测试Base64Url编码解码"""
        test_data = {"alg": "HS256", "typ": "JWT"}
        json_str = json.dumps(test_data, separators=(',', ':'))
        
        # 标准Base64编码
        standard_b64 = base64.b64encode(json_str.encode()).decode()
        
        # Base64Url编码（替换字符，去除填充）
        url_b64 = standard_b64.replace('+', '-').replace('/', '_').rstrip('=')
        
        # 应该能正确解码
        padding = 4 - len(url_b64) % 4
        if padding != 4:
            url_b64 += "=" * padding
        url_b64 = url_b64.replace('-', '+').replace('_', '/')
        decoded = base64.b64decode(url_b64).decode()
        
        self.assertEqual(json.loads(decoded), test_data)

def run_all_tests():
    """运行所有测试并生成报告"""
    print("🧪 开始JWT安全审计工具测试")
    print("=" * 50)
    
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestJWTAuditor)
    suite.addTests(loader.loadTestsFromTestCase(TestJWTEncoding))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 生成测试报告
    print("\n" + "=" * 50)
    print("📊 测试报告")
    print("=" * 50)
    print(f"运行测试: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    
    if result.failures:
        print(f"\n❌ 失败的测试:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback.splitlines()[-1]}")
    
    if result.errors:
        print(f"\n⚠️ 错误的测试:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback.splitlines()[-1]}")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    # 运行所有测试
    success = run_all_tests()
    
    # 退出码
    exit(0 if success else 1)