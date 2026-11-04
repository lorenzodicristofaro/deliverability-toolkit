import app


def test_import_app() -> None:
    assert app.__name__ == "app"
