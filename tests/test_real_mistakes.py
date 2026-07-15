import unittest
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from src.scanning import scan_directory, SecretCandidate
from src.refactoring import refactor_file, append_to_env, LANGUAGE_RULES

class TestRealMistakes(unittest.TestCase):

    def setUp(self):
        # Path to templates containing real human mistakes
        self.templates_dir = Path(__file__).parent / "real_mistakes"

    def test_real_mistakes_flow(self):
        with TemporaryDirectory() as tmp_dir:
            temp_path = Path(tmp_dir)
            
            # Copy all files from templates_dir to the temp directory
            for item in self.templates_dir.iterdir():
                if item.is_file():
                    shutil.copy(item, temp_path / item.name)
            
            # 1. Perform scanning of the temp directory
            candidates = list(scan_directory(temp_path, min_len=8, threshold=4.5))
            
            # Extract inner values of found candidates
            found_inner_values = [c.inner_value for c in candidates]
            
            # We expect these high-entropy secrets to be detected
            expected_secrets = [
                "postgresql://db_admin:admin_P@ssw0rd_987654321@prod-db.cluster.internal:5432/production",
                "redis://:Redis_Secret_Pass_99887766!_aBcDeFg_12345@redis.prod.internal:6379/0",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "pk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z",
                "sk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z",
                "jwt_signing_secret_key_1234567890_abcdefg_XYZ_!!!!"
            ]
            
            for secret in expected_secrets:
                with self.subTest(secret=secret):
                    self.assertIn(secret, found_inner_values)

            # 2. Simulate interactive resolution and refactoring
            env_file = temp_path / ".env"
            
            # Map each secret to a variable name
            secret_to_var = {
                "postgresql://db_admin:admin_P@ssw0rd_987654321@prod-db.cluster.internal:5432/production": "DATABASE_URL",
                "redis://:Redis_Secret_Pass_99887766!_aBcDeFg_12345@redis.prod.internal:6379/0": "REDIS_URL",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS_SECRET_KEY",
                "pk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z": "STRIPE_PUB_KEY",
                "sk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z": "STRIPE_SECRET_KEY",
                "jwt_signing_secret_key_1234567890_abcdefg_XYZ_!!!!": "JWT_SECRET_KEY"
            }
            
            for candidate in candidates:
                # If it's one of our expected secrets, refactor it
                if candidate.inner_value in secret_to_var:
                    var_name = secret_to_var[candidate.inner_value]
                    
                    # Write to .env
                    append_to_env(env_file, var_name, candidate.inner_value)
                    
                    # Refactor source file
                    refactored = refactor_file(candidate.file_path, candidate.match_text, var_name)
                    self.assertTrue(refactored, f"Failed to refactor {candidate.file_path.name} for {var_name}")
            
            # 3. Assertions on the generated .env file
            env_content = env_file.read_text(encoding='utf-8')
            for secret_val, var_name in secret_to_var.items():
                # Escape value just like refactoring.py does
                escaped_val = secret_val.replace('\\', '\\\\').replace('"', '\\"')
                self.assertIn(f'{var_name}="{escaped_val}"', env_content)
                
            # 4. Assertions on the refactored database.py file
            refactored_db = (temp_path / "database.py").read_text(encoding='utf-8')
            self.assertIn("import os\n", refactored_db)
            self.assertIn("DB_CONNECTION_STRING = os.environ.get('DATABASE_URL')", refactored_db)
            self.assertIn("REDIS_URL = os.environ.get('REDIS_URL')", refactored_db)
            
            # 5. Assertions on the refactored aws.js file
            refactored_aws = (temp_path / "aws.js").read_text(encoding='utf-8')
            self.assertIn("const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_KEY;", refactored_aws)
            
            # 6. Assertions on the refactored payment.tsx file
            refactored_payment = (temp_path / "payment.tsx").read_text(encoding='utf-8')
            self.assertIn("const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUB_KEY;", refactored_payment)
            self.assertIn("const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;", refactored_payment)
            
            # 7. Assertions on the refactored jwt.py file
            refactored_jwt = (temp_path / "jwt.py").read_text(encoding='utf-8')
            self.assertIn("import os\n", refactored_jwt)
            self.assertIn("JWT_SECRET = os.environ.get('JWT_SECRET_KEY')", refactored_jwt)

    def test_scan_only_mode(self):
        """Scan-only mode (default) should report findings without modifying files."""
        import subprocess
        import sys

        with TemporaryDirectory() as tmp_dir:
            temp_path = Path(tmp_dir)
            source_dir = temp_path / "project_src"
            source_dir.mkdir()

            # Write a file with a secret
            secret_val = "EZm1Mg5xKnU8xFclna83LWsjzJw8oTpaWfsgWls5zUQ="
            dummy_file = source_dir / "app.py"
            original_content = f'key = "{secret_val}"\n'
            dummy_file.write_text(original_content, encoding='utf-8')

            # Run WITHOUT -r (scan-only mode), no stdin needed
            cmd = [sys.executable, "-m", "src.main", str(source_dir)]
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input="")

            self.assertEqual(process.returncode, 0, f"Process failed: {stderr}")

            # The secret should be reported in output
            self.assertIn(secret_val, stdout)
            self.assertIn("CRITICAL", stdout)
            self.assertIn("SCAN-ONLY", stdout)

            # The file must NOT be modified
            self.assertEqual(dummy_file.read_text(encoding='utf-8'), original_content)

            # No .env file should be created
            self.assertFalse((source_dir / ".env").exists())

    def test_duplicate_cli_flag(self):
        import subprocess
        import sys
        
        with TemporaryDirectory() as tmp_dir:
            temp_path = Path(tmp_dir)
            source_dir = temp_path / "project_src"
            source_dir.mkdir()
            
            # Write a dummy python file with a secret
            dummy_file = source_dir / "app.py"
            secret_val = "EZm1Mg5xKnU8xFclna83LWsjzJw8oTpaWfsgWls5zUQ="
            dummy_file.write_text(f'key = "{secret_val}"\n', encoding='utf-8')
            
            # We run python3 -m src.main <source_dir> -r -d (refactor + duplicate)
            cmd = [sys.executable, "-m", "src.main", str(source_dir), "-r", "-d"]
            
            # Run the command with stdin piped
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Send inputs: 'y' to confirm, then 'MY_KEY' for variable name
            stdout, stderr = process.communicate(input="y\nMY_KEY\n")
            
            # Verify process exited successfully
            self.assertEqual(process.returncode, 0, f"Process failed with stderr: {stderr}")
            
            # 1. Verify the original file is untouched
            self.assertEqual(dummy_file.read_text(encoding='utf-8'), f'key = "{secret_val}"\n')
            
            # 2. Verify the duplicated folder exists
            duplicated_dir = temp_path / "project_src_env_guard_fixed"
            self.assertTrue(duplicated_dir.exists() and duplicated_dir.is_dir())
            
            # 3. Verify the files in the duplicated folder are refactored
            refactored_file = duplicated_dir / "app.py"
            self.assertTrue(refactored_file.exists())
            refactored_content = refactored_file.read_text(encoding='utf-8')
            self.assertIn("import os\n", refactored_content)
            self.assertIn("key = os.environ.get('MY_KEY')", refactored_content)
            self.assertNotIn(secret_val, refactored_content)
            
            # 4. Verify the .env file exists in the duplicated folder
            env_file = duplicated_dir / ".env"
            self.assertTrue(env_file.exists())
            self.assertIn('MY_KEY="EZm1Mg5xKnU8xFclna83LWsjzJw8oTpaWfsgWls5zUQ="', env_file.read_text(encoding='utf-8'))

if __name__ == '__main__':
    unittest.main()
