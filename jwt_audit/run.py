#!/usr/bin/env python3
"""
JWT安全审计工具 - 统一启动脚本
解决所有导入问题，支持多种运行方式
"""

import sys
import os
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('jwt-audit')

def setup_environment():
    """设置Python环境，确保正确导入"""
    
    # 获取当前脚本所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 项目根目录（jwt_audit的父目录）
    project_root = os.path.dirname(current_dir)
    
    # src目录路径
    src_dir = os.path.join(current_dir, 'src')
    
    # 添加必要的路径到Python路径
    paths_to_add = [
        project_root,      # 项目根目录（Cryptography）
        current_dir,       # jwt_audit目录
        src_dir,           # src源代码目录
    ]
    
    for path in paths_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)
            logger.debug(f"✅ 添加路径: {path}")
    
    # 环境变量（用于调试）
    os.environ['JWT_AUDIT_PROJECT_ROOT'] = project_root
    os.environ['JWT_AUDIT_SRC_DIR'] = src_dir
    
    logger.info(f"🔧 项目根目录: {project_root}")
    logger.info(f"📁 源代码目录: {src_dir}")
    logger.info(f"🐍 Python路径: {sys.path[:3]}...")  # 只显示前3个

def import_and_run():
    """导入模块并运行CLI"""
    try:
        # 尝试从src导入
        from src.cli import cli
        
        logger.info("✅ 模块导入成功！")
        logger.info("🚀 启动JWT安全审计工具...")
        
        # 运行CLI
        cli()
        
    except ImportError as e:
        logger.error(f"❌ 导入失败: {e}")
        logger.error("💡 尝试备用导入方式...")
        
        # 备用方案：直接运行CLI文件
        try:
            cli_path = os.path.join(os.path.dirname(__file__), 'src', 'cli.py')
            if os.path.exists(cli_path):
                logger.info(f"🔧 执行: {cli_path}")
                
                # 使用exec直接执行CLI文件
                with open(cli_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                # 创建执行环境
                env = {
                    '__name__': '__main__',
                    '__file__': cli_path,
                }
                
                # 执行代码
                exec(code, env)
            else:
                logger.error(f"❌ 找不到CLI文件: {cli_path}")
                
        except Exception as exec_error:
            logger.error(f"❌ 执行失败: {exec_error}")
            sys.exit(1)

def check_dependencies():
    """检查必要的依赖是否安装"""
    required_packages = ['click', 'pyjwt', 'cryptography', 'rich']
    missing = []
    
    for package in required_packages:
        try:
            __import__(package)
            logger.debug(f"✅ {package} 已安装")
        except ImportError:
            missing.append(package)
    
    if missing:
        logger.warning(f"⚠️  缺少依赖: {', '.join(missing)}")
        logger.info("💡 运行: pip install -r requirements.txt")
        return False
    
    return True

def main():
    """主函数"""
    print("="*60)
    print("🔐 JWT Security Audit Tool v0.1.0")
    print("="*60)
    
    # 1. 设置环境
    setup_environment()
    
    # 2. 检查依赖
    if not check_dependencies():
        logger.warning("继续运行，但部分功能可能不可用...")
    
    # 3. 导入并运行
    import_and_run()

if __name__ == '__main__':
    main()