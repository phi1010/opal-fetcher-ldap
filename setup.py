from setuptools import setup, find_packages

def get_requirements(env=""):
    if env:
        env = "-{}".format(env)
    with open("requirements{}.txt".format(env)) as fp:
        return [x.strip() for x in fp.read().split("\n") if not x.startswith("#")]

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='opal-fetcher-ldap',
    version='1.0.0',
    author='Phillip Kuhrt',
    author_email="mail@phi1010.com",
    description="An OPAL fetch provider to bring authorization state from LDAP.",
    long_description_content_type="text/markdown",
    long_description=long_description,
    url="https://github.com/phi1010/opal-fetcher-ldap",
    packages=find_packages(),
    classifiers=[
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        #'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ],
    python_requires='>=3.7',
    install_requires=get_requirements(),
)