
from setuptools import setup, find_packages

setup(
    name="cyber_threat_characterization",
    version="0.1.0",
    description="Cyberattack Threat Characterization System",
    author="CSCI404",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "requests>=2.28.1",
        "python-nmap>=0.7.1",
        "colorama>=0.4.5",
        "tabulate>=0.9.0",
        "jsonschema>=4.17.3",
        "tqdm>=4.64.1",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "threat_analyzer=main:main",
        ],
    },
)