argon2pure
==========

Pure Python implementation of Argon2_ v1.3.

You probably want to use the argon2_cffi_ or pyargon2_ bindings instead.

Usage
-----

.. code:: python

    >>> import argon2pure
    >>> from binascii import hexlify
    >>> hexlify(argon2pure.argon2('password', 'randomsalt', time_cost=1, memory_cost=16, parallelism=2))
    '0163c5fa892819055eb07b8acb94fd2ff5273e689b34107daaaaceda648f1e1b'


Installation
------------

Run::

    pip install argon2pure

TODO
----

- Optimize.
- Cover corner-cases in tests.

.. _argon2: https://password-hashing.net/#argon2
.. _pyargon2: https://pypi.python.org/pypi/argon2
.. _argon2_cffi: https://pypi.python.org/pypi/argon2_cffi
