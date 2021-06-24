import sys

from setuptools import setup


setup(
    author="Mozilla",
    author_email="conduit-team@mozilla.com",
    description="Pulsebot is a bot listening to pulse.mozilla.org for mercurial changes and notifying bugzilla accordingly.",
    include_package_data=True,
    install_requires=[
        "requests",
        "MozillaPulse"
    ],
    license="Mozilla Public License 2.0",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    name="Pulsebot",
    # Note: Please change the `updater.py::check_for_updates` method if the format
    # would be different than >=X.Y
    python_requires=">=2.7",
    url="https://github.com/mozilla-conduit/pulsebot",
    version="0.1",
    zip_safe=False,
)
