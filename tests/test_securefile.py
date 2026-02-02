#!/usr/bin/env python3
"""
Unit tests for SecureShare Pro - PKI-Based Secure File Sharing System
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from securefile import (
    CryptoEngine,
    KeyVault,
    SecureFileSharingSystem,
)


class TestCryptoEngine(unittest.TestCase):
    """Test cases for the CryptoEngine class."""
    
    def test_generate_key_pair(self):
        """Test RSA key pair generation."""
        private_key, public_key = CryptoEngine.generate_key_pair(key_size=2048)
        
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(private_key.key_size, 2048)
    
    def test_generate_ec_key_pair(self):
        """Test Elliptic Curve key pair generation."""
        private_key, public_key = CryptoEngine.generate_ec_key_pair()
        
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
    
    def test_create_self_signed_certificate(self):
        """Test self-signed certificate creation."""
        private_key, _ = CryptoEngine.generate_key_pair()
        certificate = CryptoEngine.create_self_signed_certificate(
            private_key,
            "Test User"
        )
        
        self.assertIsNotNone(certificate)
        self.assertEqual(certificate.subject.rfc4514_string().find("Test User") >= 0, True)
    
    def test_encrypt_decrypt_aes_gcm(self):
        """Test AES-GCM encryption and decryption."""
        data = b"This is a test message for encryption."
        key = os.urandom(32)  # 256-bit key
        
        ciphertext, iv, tag = CryptoEngine.encrypt_aes_gcm(data, key)
        decrypted = CryptoEngine.decrypt_aes_gcm(ciphertext, key, iv, tag)
        
        self.assertEqual(decrypted, data)
        self.assertNotEqual(ciphertext, data)
    
    def test_hybrid_encrypt_decrypt(self):
        """Test hybrid encryption (RSA + AES)."""
        # Generate key pair
        private_key, public_key = CryptoEngine.generate_key_pair()
        
        # Test data
        data = b"This is a secret message for hybrid encryption."
        
        # Encrypt
        encrypted_data = CryptoEngine.hybrid_encrypt(data, public_key)
        
        self.assertIn('ciphertext', encrypted_data)
        self.assertIn('encrypted_key', encrypted_data)
        self.assertIn('iv', encrypted_data)
        self.assertIn('tag', encrypted_data)
        self.assertEqual(encrypted_data['algorithm'], 'RSA-OAEP/AES-256-GCM')
        
        # Decrypt
        decrypted = CryptoEngine.hybrid_decrypt(encrypted_data, private_key)
        self.assertEqual(decrypted, data)
    
    def test_sign_and_verify_signature(self):
        """Test digital signature creation and verification."""
        private_key, public_key = CryptoEngine.generate_key_pair()
        data = b"This data needs to be signed."
        
        signature = CryptoEngine.sign_data(data, private_key)
        
        # Verify with correct public key
        result = CryptoEngine.verify_signature(data, signature, public_key)
        self.assertEqual(result, True)
        
        # Verify with wrong data (should fail)
        wrong_data = b"This is different data."
        result = CryptoEngine.verify_signature(wrong_data, signature, public_key)
        self.assertEqual(result, False)
    
    def test_derive_key_from_password(self):
        """Test key derivation from password using PBKDF2."""
        password = "secure_password_123"
        salt = os.urandom(16)
        
        key = CryptoEngine.derive_key_from_password(password, salt)
        
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)  # 256-bit key
        
        # Same password and salt should produce same key
        key2 = CryptoEngine.derive_key_from_password(password, salt)
        self.assertEqual(key, key2)
        
        # Different salt should produce different key
        different_salt = os.urandom(16)
        key3 = CryptoEngine.derive_key_from_password(password, different_salt)
        self.assertNotEqual(key, key3)


class TestKeyVault(unittest.TestCase):
    """Test cases for the KeyVault class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.vault = KeyVault(vault_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_vault_initialization(self):
        """Test KeyVault initialization."""
        self.assertTrue(self.vault.keys_file.exists())
        self.assertTrue(self.vault.certificates_file.exists())
        self.assertTrue(self.vault.shared_files_file.exists())
    
    def test_save_and_load_private_key(self):
        """Test saving and loading password-protected private key."""
        private_key, _ = CryptoEngine.generate_key_pair()
        password = "test_password_123"
        key_id = "test_key"
        
        # Save key
        result = self.vault.save_private_key(key_id, private_key, password)
        self.assertEqual(result, True)
        
        # Load key
        loaded_key = self.vault.load_private_key(key_id, password)
        self.assertIsNotNone(loaded_key)
        self.assertEqual(loaded_key.key_size, private_key.key_size)
        
        # Wrong password should fail
        wrong_password = self.vault.load_private_key(key_id, "wrong_password")
        self.assertIsNone(wrong_password)
    
    def test_save_and_load_certificate(self):
        """Test saving and loading certificates."""
        private_key, public_key = CryptoEngine.generate_key_pair()
        certificate = CryptoEngine.create_self_signed_certificate(
            private_key,
            "Test Certificate"
        )
        cert_id = "test_cert"
        
        # Save certificate
        self.vault.save_certificate(cert_id, certificate, public_key)
        
        # Load certificate
        cert_data = self.vault.get_certificate(cert_id)
        self.assertIsNotNone(cert_data)
        self.assertIn('certificate', cert_data)
        self.assertIn('subject', cert_data)
        
        # Load public key
        loaded_pub_key = self.vault.get_public_key(cert_id)
        self.assertIsNotNone(loaded_pub_key)
    
    def test_save_and_get_shared_file_metadata(self):
        """Test saving and retrieving shared file metadata."""
        file_id = "test_file_123"
        metadata = {
            'file_id': file_id,
            'filename': 'test.txt',
            'sender': 'alice',
            'recipient': 'bob',
            'encrypted_data': {'ciphertext': 'abc123'},
            'signature': 'sig456',
            'timestamp': '2024-01-01T00:00:00',
            'file_size': 1024,
            'original_hash': 'hash789'
        }
        
        # Save metadata
        self.vault.save_shared_file_metadata(file_id, metadata)
        
        # Get metadata
        retrieved = self.vault.get_shared_file_metadata(file_id)
        self.assertEqual(retrieved['file_id'], file_id)
        self.assertEqual(retrieved['filename'], 'test.txt')
        self.assertEqual(retrieved['sender'], 'alice')


class TestSecureFileSharingSystem(unittest.TestCase):
    """Test cases for the SecureFileSharingSystem class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.system = SecureFileSharingSystem()
        self.system.key_vault = KeyVault(vault_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_user_registration(self):
        """Test user registration."""
        result = self.system.register_user("test_user", "password123")
        self.assertEqual(result, True)
        self.assertEqual(self.system.current_user, "test_user")
        self.assertIsNotNone(self.system.user_private_key)
    
    def test_user_login_success(self):
        """Test successful user login."""
        # Register user first
        self.system.register_user("test_user", "password123")
        self.system.current_user = None
        self.system.user_private_key = None
        
        # Login
        result = self.system.login("test_user", "password123")
        self.assertEqual(result, True)
        self.assertEqual(self.system.current_user, "test_user")
    
    def test_user_login_failure(self):
        """Test failed user login."""
        # Try to login without registering
        result = self.system.login("nonexistent_user", "password123")
        self.assertEqual(result, False)
    
    def test_encrypt_and_sign_file(self):
        """Test file encryption and signing."""
        # Setup users
        sender = "sender_user"
        recipient = "recipient_user"
        
        self.system.register_user(sender, "sender_pass")
        self.system.register_user(recipient, "recipient_pass")
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content for encryption.")
            temp_file = f.name
        
        try:
            # Encrypt file
            self.system.user_private_key = None  # Reset state
            self.system.login(sender, "sender_pass")
            metadata = self.system.encrypt_and_sign_file(temp_file, recipient)
            
            self.assertIsNotNone(metadata)
            self.assertIn('file_id', metadata)
            self.assertIn('encrypted_data', metadata)
            self.assertIn('signature', metadata)
            # Verify metadata has expected fields
            self.assertIn('sender', metadata)
            self.assertEqual(metadata['recipient'], recipient)
        finally:
            os.unlink(temp_file)
    
    def test_decrypt_and_verify_file(self):
        """Test file decryption and verification."""
        # Setup users
        sender = "sender_user"
        recipient = "recipient_user"
        
        self.system.register_user(sender, "sender_pass")
        self.system.register_user(recipient, "recipient_pass")
        
        # Create test file
        test_content = b"Test file content for decryption."
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_file = f.name
        
        try:
            # Encrypt file as sender
            self.system.user_private_key = None  # Reset
            self.system.login(sender, "sender_pass")
            metadata = self.system.encrypt_and_sign_file(temp_file, recipient)
            
            # Decrypt as recipient
            self.system.user_private_key = None  # Reset
            self.system.login(recipient, "recipient_pass")
            
            output_file = tempfile.mktemp(suffix='.txt')
            success, message = self.system.decrypt_and_verify_file(
                metadata['file_id'],
                output_file
            )
            
            self.assertEqual(success, True)
            
            # Verify content
            with open(output_file, 'rb') as f:
                decrypted_content = f.read()
            self.assertEqual(decrypted_content, test_content)
            
            os.unlink(output_file)
        finally:
            os.unlink(temp_file)
    
    def test_get_user_files(self):
        """Test retrieving list of files for user."""
        # Setup users
        self.system.register_user("sender", "sender_pass")
        self.system.register_user("recipient", "recipient_pass")
        
        # Create and encrypt a file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content")
            temp_file = f.name
        
        try:
            self.system.user_private_key = None
            self.system.login("sender", "sender_pass")
            self.system.encrypt_and_sign_file(temp_file, "recipient")
            
            # Get files as recipient
            self.system.user_private_key = None
            self.system.login("recipient", "recipient_pass")
            files = self.system.get_user_files()
            
            self.assertGreater(len(files), 0)
            # Verify the returned file info has expected fields
            self.assertIn('sender', files[0])
            self.assertIn('filename', files[0])
        finally:
            os.unlink(temp_file)
    
    def test_get_available_users(self):
        """Test retrieving list of available users."""
        # Register users
        self.system.register_user("user1", "pass1")
        self.system.register_user("user2", "pass2")
        
        # Login as user1
        self.system.login("user1", "pass1")
        users = self.system.get_available_users()
        
        self.assertIn("user2", users)
        self.assertNotIn("user1", users)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.system = SecureFileSharingSystem()
        self.system.key_vault = KeyVault(vault_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_complete_encryption_workflow(self):
        """Test complete encryption and decryption workflow."""
        # Register sender and recipient
        self.system.register_user("alice", "alice_pass123")
        self.system.register_user("bob", "bob_pass123")
        
        # Create test file
        test_content = b"Confidential message from Alice to Bob."
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_file = f.name
        
        try:
            # Alice encrypts and sends to Bob
            self.system.login("alice", "alice_pass123")
            metadata = self.system.encrypt_and_sign_file(temp_file, "bob")
            
            self.assertIsNotNone(metadata)
            
            # Bob receives and decrypts
            self.system.login("bob", "bob_pass123")
            output_file = tempfile.mktemp(suffix='.txt')
            success, message = self.system.decrypt_and_verify_file(
                metadata['file_id'],
                output_file
            )
            
            self.assertEqual(success, True)
            
            # Verify decrypted content
            with open(output_file, 'rb') as f:
                decrypted = f.read()
            self.assertEqual(decrypted, test_content)
            
            os.unlink(output_file)
        finally:
            os.unlink(temp_file)
    
    def test_tamper_detection(self):
        """Test that tampered files are detected and rejected."""
        # Register sender and recipient
        self.system.register_user("alice", "alice_pass123")
        self.system.register_user("bob", "bob_pass123")
        
        # Create and encrypt file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content")
            temp_file = f.name
        
        try:
            self.system.login("alice", "alice_pass123")
            metadata = self.system.encrypt_and_sign_file(temp_file, "bob")
            
            # Tamper with metadata
            tampered_metadata = metadata.copy()
            tampered_metadata['encrypted_data']['ciphertext'] += "X"
            self.system.key_vault.save_shared_file_metadata(
                f"tampered_{metadata['file_id']}",
                tampered_metadata
            )
            
            # Try to decrypt tampered file
            self.system.login("bob", "bob_pass123")
            output_file = tempfile.mktemp(suffix='.txt')
            success, message = self.system.decrypt_and_verify_file(
                f"tampered_{metadata['file_id']}",
                output_file
            )
            
            self.assertEqual(success, False)
            self.assertIn("verification failed", message.lower())
            
            # Cleanup if file was created (shouldn't be in failure case)
            if os.path.exists(output_file):
                os.unlink(output_file)
        finally:
            os.unlink(temp_file)


if __name__ == "__main__":
    unittest.main()

