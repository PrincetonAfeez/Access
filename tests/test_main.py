"""Tests for the main module."""

from __future__ import annotations

import unittest

import cli


class MainModuleTests(unittest.TestCase):
    def test_main_reexports_cli_main(self) -> None:
        import main as main_module

        self.assertIs(main_module.main, cli.main)
        self.assertTrue(callable(main_module.main))


if __name__ == "__main__":
    unittest.main()
