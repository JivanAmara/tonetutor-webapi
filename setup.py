from setuptools import setup
import os

# allow setup.py to be run from any path
os.chdir(os.path.dirname(os.path.abspath(__file__)))

README = "Provides tonetutor-webapi models to allow cascading deletes."

setup(
    name="tonetutor-webapi",
    version="0.3.6",
    author="Jivan Amara",
    author_email="Development@JivanAmara.net",
    packages=['webapi', 'webapi.migrations'],
    description=README,
    long_description=README,
    classifiers=[
        'Intended Audience :: Developers',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
    ],
)
