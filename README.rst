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
    '4d0e55fb28dd8408d40b103111d88081e5311706f4a35b842c463678d1fecc91'


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
