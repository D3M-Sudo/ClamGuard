import os
import tempfile
from src.core.path_validator import validate_path


def test_validate_path_sensitive_direct():
    valid, reason = validate_path("/etc/shadow")
    assert not valid
    assert "sensibile" in reason or "non leggibile" in reason


def test_validate_path_sensitive_proc():
    valid, reason = validate_path("/proc")
    assert not valid


def test_validate_path_sensitive_symlink():
    with tempfile.TemporaryDirectory() as tmpdir:
        symlink_path = os.path.join(tmpdir, "shadow_link")
        try:
            os.symlink("/etc/shadow", symlink_path)
            valid, reason = validate_path(symlink_path)
            assert not valid
            assert "sensibile" in reason or "non leggibile" in reason
        except OSError:
            pass


def test_validate_path_normal_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmp_name = tmpfile.name
    try:
        valid, reason = validate_path(tmp_name)
        assert valid
        assert reason is None
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def test_validate_path_traversal():
    valid, reason = validate_path("/tmp/../etc/passwd")
    assert not valid
    assert "traversal" in reason.lower()
