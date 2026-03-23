import os
import secrets
import subprocess

from ft_otp.cli import process_hex_file, process_key_file


class TestFullWorkflow:
    """Test the complete OTP generation workflow."""

    def setup_method(self):
        """Generate a fresh hex key file before each test."""
        self.key = secrets.token_hex(32)
        with open("key.txt", "w") as file:
            file.write(self.key)

    def teardown_method(self):
        """Clean up generated files after each test."""
        for file in ("key.txt", "ft_otp.key", "filekey.key"):
            if os.path.exists(file):
                os.remove(file)

    def test_store_key(self):
        """Storing a valid hex key should create ft_otp.key."""
        process_hex_file("key.txt")
        assert os.path.exists("ft_otp.key")

    def test_generate_otp(self):
        """Generated OTP should be a 6-digit string."""
        process_hex_file("key.txt")
        otp = process_key_file("ft_otp.key")
        assert len(otp) == 6
        assert otp.isdigit()

    def test_invalid_key_too_short(self):
        """A key shorter than 64 hex chars should raise ValueError."""
        with open("key.txt", "w") as file:
            file.write("ab" * 31)
        try:
            process_hex_file("key.txt")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_invalid_key_not_hex(self):
        """A non-hex key should raise ValueError."""
        with open("key.txt", "w") as file:
            file.write("z" * 64)
        try:
            process_hex_file("key.txt")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_missing_file(self):
        """A missing key file should raise FileNotFoundError."""
        try:
            process_key_file("nonexistent.key")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass

    def test_otp_matches_oathtool(self):
        """Generated OTP should match oathtool --totp output."""
        process_hex_file("key.txt")
        otp = process_key_file("ft_otp.key")
        result = subprocess.run(
            ["oathtool", "--totp", self.key],
            capture_output=True, text=True
        )
        assert result.returncode == 0, f"oathtool failed: {result.stderr}"
        assert otp == result.stdout.strip()
