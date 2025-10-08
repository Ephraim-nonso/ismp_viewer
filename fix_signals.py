#!/usr/bin/env python3
import re

with open('src/frontend/lib.rs', 'r') as f:
    content = f.read()

# Fix .set() calls on WriteSignal
content = re.sub(r'set_(\w+)\.set\(', r'set_\1(', content)

# Fix .get() calls on ReadSignal  
content = re.sub(r'(\w+)\.get\(\)', r'\1()', content)

with open('src/frontend/lib.rs', 'w') as f:
    f.write(content)

print("Fixed signal API calls!")

