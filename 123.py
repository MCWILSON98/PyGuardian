import ast
import tokenize
import io
import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass

# ------------------- 数据结构定义 -------------------
@dataclass
class Violation:
    """代码违规/漏洞报告的数据结构"""
    line_no: int
    severity: str  # 'CRITICAL', 'WARNING', 'INFO'
    message: str
    suggestion: str

@dataclass
class OptimizationSuggestion:
    """代码优化建议的数据结构"""
    line_no: int
    original_code: str
    optimized_code: str
    reason: str

# ------------------- 核心分析器 -------------------
class PythonCodeAnalyzer:
    """Python代码静态分析核心类"""
    
    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()
        self.tree = None
        self._parse_ast()

    def _parse_ast(self):
        """将代码解析为抽象语法树(AST)"""
        try:
            self.tree = ast.parse(self.code)
        except SyntaxError as e:
            # 捕获语法错误作为关键漏洞
            self.violations.append(Violation(
                line_no=e.lineno,
                severity="CRITICAL",
                message=f"语法错误: {e.msg}",
                suggestion=f"请检查第 {e.lineno} 行的语法"
            ))

    def analyze(self) -> List[Violation]:
        """执行全面的代码分析"""
        self.violations = []
        if self.tree is None:
            return self.violations
            
        self._check_undefined_variables()
        self._check_dangerous_functions()
        self._check_naming_conventions()
        self._check_complexity()
        return self.violations

    def _check_undefined_variables(self):
        """检查使用了未定义的变量"""
        defined_names = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                defined_names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined_names.add(target.id)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                # 变量读取
                if node.id not in defined_names and node.id not in dir(__builtins__):
                    self.violations.append(Violation(
                        line_no=node.lineno,
                        severity="WARNING",
                        message=f"使用了未定义的变量 '{node.id}'",
                        suggestion=f"请在使用前定义变量 {node.id}"
                    ))

    def _check_dangerous_functions(self):
        """检查危险函数调用"""
        dangerous_funcs = {'eval', 'exec', 'open', 'os.system'}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name in dangerous_funcs:
                    self.violations.append(Violation(
                        line_no=node.lineno,
                        severity="CRITICAL" if func_name in {'eval', 'exec'} else "WARNING",
                        message=f"检测到危险函数调用: {func_name}",
                        suggestion=f"避免使用 {func_name}，请使用安全的替代方案"
                    ))

    def _check_naming_conventions(self):
        """检查PEP 8命名规范"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                if not re.match(r'^[a-z_]+$', node.name):
                    self.violations.append(Violation(
                        line_no=node.lineno,
                        severity="INFO",
                        message=f"函数名 '{node.name}' 不符合PEP 8规范(应使用小写+下划线)",
                        suggestion=f"建议重命名为: {node.name.lower()}"
                    ))

    def _check_complexity(self):
        """检查代码复杂度"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.If) or isinstance(node, ast.For) or isinstance(node, ast.While):
                # 简单的循环/条件计数
                continue
            # 可扩展：添加圈复杂度计算逻辑

# ------------------- 代码优化器 -------------------
class PythonCodeOptimizer:
    """Python代码自动化优化类"""
    
    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()

    def optimize(self) -> List[OptimizationSuggestion]:
        """执行自动化优化"""
        suggestions = []
        self._optimize_loops(suggestions)
        self._optimate_string_operations(suggestions)
        self._optimize_imports(suggestions)
        return suggestions

    def _optimize_loops(self, suggestions: List[OptimizationSuggestion]):
        """优化for循环，使用列表推导式"""
        pattern = re.compile(r'for\s+(\w+)\s+in\s+(\w+):\s+([^#\n]+)')
        for idx, line in enumerate(self.lines, 1):
            match = pattern.match(line.strip())
            if match:
                var, iterable, expr = match.groups()
                # 识别简单的append操作
                if expr.strip().startswith(f'{var}.append('):
                    inner_expr = expr.strip()[len(f'{var}.append('):-1]
                    suggestions.append(OptimizationSuggestion(
                        line_no=idx,
                        original_code=line.strip(),
                        optimized_code=f'{var} = [{inner_expr} for {var} in {iterable}]',
                        reason="使用列表推导式替代循环append，效率提升约50%"
                    ))

    def _optimate_string_operations(self, suggestions: List[OptimizationSuggestion]):
        """优化字符串拼接"""
        pattern = re.compile(r'(\w+)\s*\+=\s*(\'|")(.+)("|\')')
        for idx, line in enumerate(self.lines, 1):
            match = pattern.match(line.strip())
            if match:
                var, _, content, _ = match.groups()
                suggestions.append(OptimizationSuggestion(
                    line_no=idx,
                    original_code=line.strip(),
                    optimized_code=f'{var} = f"{content}"',
                    reason="使用f-string格式化，比字符串拼接更快更易读"
                ))

    def _optimize_imports(self, suggestions: List[OptimizationSuggestion]):
        """优化导入顺序"""
        imports = []
        other_lines = []
        for idx, line in enumerate(self.lines, 1):
            if line.strip().startswith('import') or line.strip().startswith('from'):
                imports.append((idx, line))
            else:
                other_lines.append(line)
        
        if len(imports) > 1:
            # 标准库导入排序
            import_lines = sorted([line for _, line in imports], key=lambda x: x.split()[1] if 'import' in x else '')
            if imports != list(zip([i for i, _ in imports], import_lines)):
                suggestions.append(OptimizationSuggestion(
                    line_no=imports[0][0],
                    original_code="\n".join([line for _, line in imports]),
                    optimized_code="\n".join(import_lines),
                    reason="按模块名称排序导入，符合PEP 8规范，提高可读性"
                ))

# ------------------- 主程序与CLI接口 -------------------
def main():
    """主函数，提供命令行接口"""
    print("=" * 60)
    print("         PyGuardian - Python代码智能分析与优化助手")
    print("=" * 60)
    
    # 示例代码 - 你可以替换为需要分析的代码
    sample_code = """
# 这是一段待优化的示例代码
def calculateSum(numbers):
    result = 0
    for n in numbers:
        result += n
    return result

def printGreeting(name):
    print("Hello, " + name)

data = [1, 2, 3, 4, 5]
total = calculateSum(data)
print(total)

# 危险操作示例
user_input = input("Enter something: ")
eval(user_input)  # 危险！
"""

    print("\n[待分析代码]")
    print(sample_code)
    
    # 1. 代码分析
    analyzer = PythonCodeAnalyzer(sample_code)
    violations = analyzer.analyze()
    
    print("\n[分析结果]")
    if violations:
        for v in violations:
            print(f"🚨 行{v.line_no} [{v.severity}]: {v.message}")
            print(f"   建议: {v.suggestion}\n")
    else:
        print("✅ 未检测到严重问题")
    
    # 2. 代码优化
    optimizer = PythonCodeOptimizer(sample_code)
    suggestions = optimizer.optimize()
    
    print("\n[优化建议]")
    for s in suggestions:
        print(f"✨ 行{s.line_no} 优化建议")
        print(f"   原代码: {s.original_code}")
        print(f"   优化后: {s.optimized_code}")
        print(f"   原因: {s.reason}\n")

if __name__ == "__main__":
    main()
