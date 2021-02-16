"""Setup file for packaging.
"""

import pathlib
import setuptools

here = pathlib.Path(__file__).parent

with open(f"{here}/README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="bogons",
    version="1.0.2",
    author="Darren O'Connor",
    author_email="nouser@bgpstuff.net",
    description="Python Libary for IP & ASN Bogons",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mellowdrifter/python-bogons",
    packages=setuptools.find_packages(),
    license="Apache Software License (http://www.apache.org/licenses/LICENSE-2.0)",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    install_requires=['ipaddress'],
    python_requires=">=3.6",
)
