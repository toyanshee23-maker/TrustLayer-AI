from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_streamlit_entrypoint_renders_without_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTLAYER_DB_PATH", str(tmp_path / "app-test.db"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=30).run()
    assert not app.exception
    assert any("TrustLayer AI" in item.value for item in app.title)
    assert len(app.metric) >= 4
