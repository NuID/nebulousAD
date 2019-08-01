from setuptools import setup, find_packages

DEPENDENCIES = open('requirements.txt', 'r').read().split('\n')
README = open('README.md', 'r').read()

setup(
    name='nebulousAD',
    version='1.0.0',
    description='Python library and CLI for Checking AD hashes.',
    long_description=README,
    long_description_content_type='text/markdown',
    author='Robert Paul',
    author_email='robert@nuid.io',
    url="http://github.com/NuID/nebulousAD/tree/master",
    packages=find_packages(),
    include_package_data=True,
    entry_points={'console_scripts': ['nebulousAD=nebulousAD.nebulousAD:main']},
    install_requires=DEPENDENCIES,
    keywords=['security', 'network', 'hacking'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)