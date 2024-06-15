#!/usr/bin/env python3
import setuptools

description = open('README.md', 'r').read()
setuptools.setup(
  name='lotordb',
  version='0.0.1',
  author='smurfd',
  author_email='smurfd@gmail.com',
  packages=['lotordb'],
  description='Database, sneaky like natures bandit',
  long_description=description,
  long_description_content_type='text/markdown',
  url='https://github.com/smurfd/lotordb',
  license='MIT',
  #python_requires='>=3.11',
  extras_require={
    'testing': [
      'pytest',
    ],
    'linting': [
      'ruff',
      'mypy',
      'pre-commit',
    ],
  },
)
