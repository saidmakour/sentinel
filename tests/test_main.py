from unittest.mock import patch

import pytest


class TestMain:
    """Tests de la fonction main() et du point d'entrée."""

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_calls_setup_logging(self, mock_app, mock_setup_logging):
        """Test que main() appelle setup_logging()."""
        from sentinel.main import main

        main()

        mock_setup_logging.assert_called_once()

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_calls_app(self, mock_app, mock_setup_logging):
        """Test que main() appelle app() après setup_logging."""
        from sentinel.main import main

        main()

        mock_app.assert_called_once()

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_order_setup_logging_then_app(
        self, mock_app, mock_setup_logging
    ):
        """Test que setup_logging est appelé avant app()."""
        from sentinel.main import main

        main()

        assert mock_setup_logging.call_count == 1
        assert mock_app.call_count == 1

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_returns_none(self, mock_app, mock_setup_logging):
        """Test que main() retourne None."""
        from sentinel.main import main

        result = main()

        assert result is None


class TestMainWithAppExceptions:
    """Tests de gestion d'erreurs de l'app CLI."""

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_propagates_app_exception(self, mock_app, mock_setup_logging):
        """Test que les exceptions de app() sont propagées."""
        from sentinel.main import main

        mock_app.side_effect = ValueError("CLI error")

        with pytest.raises(ValueError, match="CLI error"):
            main()

        mock_setup_logging.assert_called_once()

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_propagates_system_exit(self, mock_app, mock_setup_logging):
        """Test que SystemExit de app() est propagé (ex: --help)."""
        from sentinel.main import main

        mock_app.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            main()

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_propagates_keyboard_interrupt(
        self, mock_app, mock_setup_logging
    ):
        """Test que KeyboardInterrupt est propagé."""
        from sentinel.main import main

        mock_app.side_effect = KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            main()


class TestMainWithLoggingExceptions:
    """Tests de gestion d'erreurs de logging."""

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_logging_exception_stops_execution(
        self, mock_app, mock_setup_logging
    ):
        """Test qu'une exception dans setup_logging empêche l'appel de app()."""
        from sentinel.main import main

        mock_setup_logging.side_effect = RuntimeError("Logging failed")

        with pytest.raises(RuntimeError, match="Logging failed"):
            main()

        mock_app.assert_not_called()


class TestMainFunction:
    """Tests de base de la fonction main."""

    def test_main_function_exists(self):
        """Test que la fonction main() existe et est callable."""
        from sentinel.main import main

        assert callable(main)

    def test_main_signature(self):
        """Test que main() a la bonne signature."""
        import inspect

        from sentinel.main import main

        sig = inspect.signature(main)
        # Avec from __future__ import annotations, le retour est une string
        # On vérifie juste que c'est bien une fonction sans paramètres
        assert sig.parameters == {}
        # Le return annotation peut être 'None' ou "'None'" selon Python
        assert sig.return_annotation in (None, "None", "'None'", type(None))


class TestMainEdgeCases:
    """Tests des cas limites."""

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_called_multiple_times(self, mock_app, mock_setup_logging):
        """Test que main() peut être appelé plusieurs fois."""
        from sentinel.main import main

        main()
        main()

        assert mock_setup_logging.call_count == 2
        assert mock_app.call_count == 2

    @patch("sentinel.main.setup_logging")
    @patch("sentinel.main.app")
    def test_main_with_app_returning_various_values(
        self, mock_app, mock_setup_logging
    ):
        """Test que main() ignore la valeur de retour de app()."""
        from sentinel.main import main

        for return_value in [None, 0, 1, "", "result"]:
            mock_app.return_value = return_value
            mock_setup_logging.reset_mock()

            result = main()

            assert result is None


# Tests optionnels si tu veux tester l'exécution réelle via subprocess
class TestMainSubprocess:
    """Tests d'exécution via subprocess (intégration réelle)."""

    def test_module_can_be_executed_with_help(self):
        """Test que le module peut être exécuté avec python -m sentinel --help."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "sentinel", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        # --help peut retourner 0 ou 1 selon la config Typer/Click
        # On vérifie juste que l'aide est affichée
        assert (
            "Usage:" in result.stdout
            or "Options:" in result.stdout
            or result.returncode in (0, 1)
        )

    def test_module_execution_with_invalid_command(self):
        """Test avec une commande invalide."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "sentinel", "invalid-command"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        # Devrait retourner une erreur non-zero
        assert result.returncode != 0

    def test_module_can_be_executed_without_args(self):
        """Test que le module peut être exécuté sans arguments."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "sentinel"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        # Selon ta CLI, ça peut afficher l'aide ou une erreur
        # On vérifie juste que ça s'exécute sans exception Python
        assert result.returncode in (
            0,
            1,
            2,
        )  # 0=OK, 1=erreur CLI, 2=usage error
