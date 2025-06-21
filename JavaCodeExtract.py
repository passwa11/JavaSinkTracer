"""
@File：JavaCodeExtract.py
@Time：2025/06/21 09:27
@Auth：Tr0e
@Github：https://github.com/Tr0e
@Description：基于javalang库，从Java源代码项目提取函数源码
"""
import os
import javalang

def extract_method_definition(root_dir, class_name, method_name):
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if not filename.endswith('.java'):
                continue
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                content = ''.join(lines)
                tree = javalang.parse.parse(content)
            except (IOError, javalang.parser.JavaSyntaxError, IndexError):
                continue
            for node_type in (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration):
                for _, node in tree.filter(node_type):
                    if node.name == class_name:
                        for method in node.methods:
                            if method.name == method_name and method.position:
                                definition = _extract_code_block(lines, method.position.line - 1)
                                return filepath, definition
    return None, None


def _extract_code_block(lines, start_index):
    code_lines = []
    brace_depth = 0
    started = False
    for line in lines[start_index:]:
        code_lines.append(line)
        if not started and '{' in line:
            brace_depth += line.count('{') - line.count('}')
            started = True
        elif started:
            brace_depth += line.count('{') - line.count('}')
        if started and brace_depth == 0:
            break
    return ''.join(code_lines)


if __name__ == "__main__":
    root_directory = r"D:\Code\Java\JavaVulHunter"
    path, code = extract_method_definition(root_directory, "TomcatFilterMemShell", "doFilter")
    if path:
        print(f"Found in {path}:\n{code}")
    else:
        print("未找到匹配的类或方法！")