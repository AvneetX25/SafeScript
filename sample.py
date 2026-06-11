
from scanner.classifier import VulnerabilityClassifier

clf = VulnerabilityClassifier()

# These are genuinely safe patterns
safe_examples = [
    # Pure math
    "def multiply(a, b):\n    return a * b",
    
    # Safe string formatting
    "def greet(name: str) -> str:\n    return f'Hello, {name}!'",
    
    # Safe file read with no user input
    "def read_config():\n    with open('config.json', 'r') as f:\n        return f.read()",
    
    # Safe list operation
    "def get_evens(numbers: list) -> list:\n    return [n for n in numbers if n % 2 == 0]",
    "the quick brown fox jumps over the lazy dog",
    "SELECT * FROM users"
    
]

for code in safe_examples:
    result = clf.classify(code)
    first_line = code.split('\n')[0]
    print(f"{first_line}")
    print(f"  → vulnerable={result['vulnerable']} | vuln_score={result['vuln_score']}\n")

