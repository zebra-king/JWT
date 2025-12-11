# setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="jwt-security-audit",
    version="0.1.0",
    author="zebra-king",
    author_email="your-email@example.com",  # 可选的
    description="A professional JWT security vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zebra-king/Cryptography",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pyjwt>=2.0.0",
        "cryptography>=3.4",
        "click>=8.0",
        "rich>=10.0",
    ],
    entry_points={
        "console_scripts": [
            "jwt-audit=jwt_audit.cli:cli",  # 关键：创建命令行命令
        ],
    },
)