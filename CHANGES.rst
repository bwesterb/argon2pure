argon2pure Changelog
====================

1.4 (unreleased)
----------------

- Nothing changed yet.


1.3 (2016-12-27)
----------------

- Support ARGON2ID.
- Add ARGON2_TYPES constant.
- Python 3.6 support.


1.2.4 (2016-06-25)
------------------

- Close worker pool explicitly.  For CPython this makes no difference, but
  for a Python implementation without reference counting, like PyPy, this
  will drastically decrease memory usage.  (Eli Collins)


1.2.3 (2016-06-23)
------------------

- Add use_threads flag to use threads instead of processes.  (Eli Collins)


1.2.2 (2016-06-18)
------------------

- Add ARGON2_VERSIONS constant.  (Eli Collins)


1.2 (2016-06-17)
----------------

- Support and switch the default to Argon2 v1.3


1.1.1 (2016-06-17)
------------------

- Fix setup.py typo.  (Fixes #1)

Thanks to: Eli Collins


1.1 (2016-02-06)
----------------

Performance improvements.

- Faster XORing of blocks.
- Use multiple threads if possible.


1 (2016-01-21)
--------------

- Initial release.
