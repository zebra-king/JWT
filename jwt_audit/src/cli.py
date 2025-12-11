"""
JWT安全审计工具命令行接口
支持单token审计、批量审计、文件输入输出
"""

import click
import json
from .auditor import JWTAuditor, print_audit_report

@click.group()
def cli():
    """JWT安全审计工具 - 检测JWT令牌中的安全漏洞"""
    pass

@cli.command()
@click.argument('token')
@click.option('--json-output', '-j', is_flag=True, help='JSON格式输出')
@click.option('--output', '-o', type=click.Path(), help='输出到文件')
def audit(token, json_output, output):
    """审计单个JWT令牌"""
    auditor = JWTAuditor()
    result = auditor.audit(token)
    
    if json_output:
        output_data = json.dumps(result, indent=2, ensure_ascii=False)
    else:
        output_data = result
    
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            if json_output:
                f.write(output_data)
            else:
                # 简化输出到文件
                f.write(f"JWT: {result.get('jwt_short', 'N/A')}\n")
                f.write(f"安全评分: {result.get('security_score', 0)}/100\n")
                f.write(f"状态: {result.get('summary', {}).get('status', 'UNKNOWN')}\n")
        click.echo(f"✅ 结果已保存到: {output}")
    else:
        if json_output:
            click.echo(output_data)
        else:
            print_audit_report(result)

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text', help='输出格式')
def batch(file, format):
    """批量审计文件中的JWT令牌（每行一个）"""
    try:
        with open(file, 'r', encoding='utf-8') as f:
            tokens = [line.strip() for line in f if line.strip()]
        
        if not tokens:
            click.echo("❌ 文件为空或没有有效的JWT令牌")
            return
        
        auditor = JWTAuditor()
        results = []
        
        with click.progressbar(tokens, label='审计进度') as bar:
            for token in bar:
                result = auditor.audit(token)
                results.append(result)
        
        # 汇总统计
        total = len(results)
        successful = sum(1 for r in results if r.get('success', False))
        vulnerabilities = sum(1 for r in results 
                            if r.get('success', False) and 
                            r.get('summary', {}).get('vulnerabilities_found', 0) > 0)
        
        if format == 'json':
            click.echo(json.dumps({
                'batch_summary': {
                    'total_tokens': total,
                    'successful_audits': successful,
                    'tokens_with_vulnerabilities': vulnerabilities
                },
                'results': results
            }, indent=2, ensure_ascii=False))
        else:
            click.echo(f"\n📊 批量审计完成!")
            click.echo(f"   总计令牌: {total}")
            click.echo(f"   成功审计: {successful}")
            click.echo(f"   存在漏洞: {vulnerabilities}")
            
            # 显示有漏洞的令牌
            vulnerable_tokens = [r for r in results 
                               if r.get('success', False) and 
                               r.get('summary', {}).get('vulnerabilities_found', 0) > 0]
            
        if vulnerable_tokens:
                click.echo(f"\n🔴 存在漏洞的令牌:")
                for result in vulnerable_tokens:
                    click.echo(f"   {result['jwt_short']} - 评分: {result['security_score']}/100")
    
    except Exception as e:
        click.echo(f"❌ 批量审计失败: {e}")

@cli.command()
def detectors():
    """列出所有可用的检测器"""
    auditor = JWTAuditor()
    click.echo("🔍 可用的漏洞检测器:")
    click.echo("=" * 40)
    
    for i, detector in enumerate(auditor.detectors, 1):
        # 获取检测器信息
        dummy_result = detector({}, {}, "")
        click.echo(f"{i}. {dummy_result.get('detector', 'Unknown')}")
        click.echo(f"   描述: {dummy_result.get('description', 'No description')}")
        click.echo(f"   默认严重性: {dummy_result.get('severity', 'UNKNOWN')}")
        click.echo()

@cli.command()
@click.argument('token')
def decode(token):
    """仅解码JWT，不进行安全审计"""
    from .auditor import decode_jwt
    try:
        header, payload, signature = decode_jwt(token)
        click.echo("✅ JWT解码成功!")
        click.echo("\n📄 头部:")
        click.echo(json.dumps(header, indent=2, ensure_ascii=False))
        click.echo("\n📋 载荷:")
        click.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        click.echo(f"\n🔏 签名长度: {len(signature)} 字符")
        click.echo(f"签名: {signature[:50]}..." if len(signature) > 50 else signature)
    except Exception as e:
        click.echo(f"❌ 解码失败: {e}")

if __name__ == '__main__':
    cli()