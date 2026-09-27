from setuptools import setup, find_packages

setup(
    name="touchque-authenticator",
    version="2.0.0",
    description="Official Python SDK for TouchQue Authenticator (2FA/MFA, passkeys, adaptive auth)",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="TouchQue",
    author_email="developer@touchque.com",
    url="https://touchque.com",
    project_urls={
        "Source": "https://github.com/Touchque/touchque-python",
    },
    # NOTE: the importable module stays `touchque` (i.e. `import touchque`)
    # even though the PyPI distribution name changed — matching the same
    # "package identity changes, internal naming stays" decision made for
    # the PHP SDK's PSR-4 namespace, to keep the rename's blast radius small.
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=[
        "requests>=2.25.1",
    ],
    extras_require={
        "dev": ["pytest>=7.0.0"],
        "flask": ["flask>=2.0"],
        "django": ["django>=3.2"],
        "fastapi": ["fastapi>=0.100", "anyio>=3.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: Django",
        "Framework :: Flask",
        "Framework :: FastAPI",
    ],
    python_requires=">=3.7",
)
