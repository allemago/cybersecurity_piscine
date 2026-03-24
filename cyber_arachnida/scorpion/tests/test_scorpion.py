from unittest.mock import patch
from src.cli import scorpion, validate_args


IMG_WITH_EXIF = "tests/img1.jpg"
IMG_WITH_DATE = "tests/img6.jpg"
IMG_NO_EXIF = "tests/img3.jpg"


def test_valid_image_produces_output(capsys):
    """Check that basic metadata (filename, format, size) is printed."""
    scorpion([IMG_WITH_EXIF])
    out = capsys.readouterr().out
    print(out)
    assert "img1.jpg" in out
    assert "Format:" in out
    assert "Size:" in out


def test_image_with_exif_shows_exif_data(capsys):
    """Check that EXIF data is detected and reported for an image that has it."""
    scorpion([IMG_WITH_EXIF])
    out = capsys.readouterr().out
    print(out)
    assert "EXIF data found" in out


def test_image_without_exif(capsys):
    """Check that missing EXIF data is reported clearly."""
    scorpion([IMG_NO_EXIF])
    out = capsys.readouterr().out
    print(out)
    assert "No EXIF data found" in out


def test_creation_date_is_displayed(capsys):
    """Check that the creation date is extracted and printed when available."""
    scorpion([IMG_WITH_DATE])
    out = capsys.readouterr().out
    print(out)
    assert "Creation date:" in out
    assert "2020" in out


def test_unsupported_extension_is_skipped(capsys):
    """Check that files with unsupported extensions are skipped gracefully."""
    scorpion(["tests/__init__.py"])
    out = capsys.readouterr().out
    print(out)
    assert "Skipping unsupported file type" in out


def test_multiple_files(capsys):
    """Check that multiple files are all processed in one call."""
    scorpion([IMG_WITH_EXIF, IMG_NO_EXIF])
    out = capsys.readouterr().out
    print(out)
    assert "img1.jpg" in out
    assert "img3.jpg" in out


def test_nonexistent_file_does_not_crash(capsys):
    """Check that a missing file prints an error without crashing."""
    scorpion(["tests/ghost.jpg"])
    out = capsys.readouterr().out
    print(out)
    assert "Error" in out


def test_validate_args_parses_files():
    """Check that CLI arguments are parsed into a list of file paths."""
    with patch("sys.argv", ["scorpion", "a.jpg", "b.jpg"]):
        args = validate_args()
    assert args.img_files == ["a.jpg", "b.jpg"]
