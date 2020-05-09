# The author disclaims copyright to this source code. Please see the
# accompanying UNLICENSE file.

import distutils.cmd
import subprocess

import setuptools


class FormatCommand(distutils.cmd.Command):

    description = "Run autoflake and yapf on python source files"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run_isort(self):
        subprocess.check_call(["isort", "-rc", "-sl", "-y"])

    def run_yapf(self):
        subprocess.check_call(["yapf", "-i", "-r", "--style=google", "."])

    def run_autoflake(self):
        subprocess.check_call([
            "autoflake", "-i", "-r", "--remove-all-unused-imports",
            "--remove-duplicate-keys", "--remove-unused-variables", "."
        ])

    def run(self):
        self.run_isort()
        self.run_yapf()
        self.run_autoflake()


class LintCommand(distutils.cmd.Command):

    description = "Run autoflake and yapf on python source files"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run_autoflake(self):
        subprocess.check_call([
            "pylint",
            "http_proxy",
            "http_proxy_test",
            "setup.py",
        ])

    def run(self):
        self.run_pylint()


setuptools.setup(
    name="http_proxy",
    version="0.1",
    description="A feature-incomplete HTTP proxy, mainly for testing libtorrent",
    author="AllSeeingEyeTolledEweSew",
    author_email="allseeingeyetolledewesew@protonmail.com",
    url="http://github.com/AllSeeingEyeTolledEweSew/http_proxy",
    license="Unlicense",
    packages=setuptools.find_packages(),
    cmdclass={
        "format": FormatCommand,
        "lint": LintCommand,
    },
    test_suite="http_proxy_test",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: Public Domain",
        "Programming Language :: Python",
        "Topic :: System :: Networking",
        "Operating System :: OS Independent",
    ],
)
