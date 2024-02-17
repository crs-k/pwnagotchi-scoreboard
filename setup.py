from setuptools import setup, find_packages

# Read requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="Scoreboard",
    version="0.1",
    packages=find_packages(),
    author="Chris Kerins",
    description="A Pwnagotchi scoreboard application using a Raspberry Pi and a 3.5 inch e-Paper display.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="http://github.com/crs-k/pwnagotchi-scoreboard",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements,  # Use requirements read from requirements.txt
    python_requires=">=3.6",
)