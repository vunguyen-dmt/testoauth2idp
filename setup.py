from setuptools import setup, find_packages

setup(
    name="testidp",
    version="0.1",
    packages=find_packages(),
    install_requires=["social-auth-core"],
)
