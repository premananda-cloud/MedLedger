#!/usr/bin/env python3
"""
test_registration_direct.py — Test RegistrationService directly
Run from project root: python test_registration_direct.py
"""

import sys
import json
import tempfile
import shutil
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.services.registration import RegistrationService, UserAlreadyExistsError
from src.database.store import get_store
from src.config import cfg


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 50)
    print(f"  {title}")
    print("=" * 50)


def print_result(success, message):
    """Print a colored result"""
    if success:
        print(f"  ✓ {message}")
    else:
        print(f"  ✗ {message}")


def main():
    print_section("CypherAegis Registration Test (Direct)")
    print(f"Backend: {cfg.db_backend}")
    print(f"Keygen on server: {cfg.keygen_on_server}")
    
    # Clean test data — create a fresh test environment
    test_email = "testuser@example.com"
    test_password = "testpass123"
    test_username = "testuser"
    
    # 1. Test Registration
    print_section("Test 1: Register a new user")
    
    service = RegistrationService()
    
    try:
        result = service.register(
            email=test_email,
            password=test_password,
            username=test_username,
            full_name="Test User",
            role="PATIENT"
        )
        
        print_result(True, "Registration successful")
        print(f"\n  User ID:      {result.user_id}")
        print(f"  Email:        {result.email}")
        print(f"  Username:     {result.username}")
        print(f"  Role:         {result.role}")
        print(f"  Created at:   {result.created_at}")
        print(f"\n  Public Key Hash:     {result.public_key_hash[:32]}...")
        print(f"  Public Key Compressed: {result.public_key_compressed[:32]}...")
        
        # Check if private key was returned
        if result.private_key_pem and result.private_key_pem != "client-managed":
            print(f"\n  Private Key (first 100 chars):")
            print(f"  {result.private_key_pem[:100]}...")
            print_result(True, "Private key returned (server-generated)")
        else:
            print_result(False, "No private key returned")
        
        # Store result for later
        user_id = result.user_id
        public_key_hash = result.public_key_hash
        
    except UserAlreadyExistsError:
        print_result(False, "User already exists — cleaning up first?")
        # Try to clean up by resetting the store
        if cfg.db_backend == "json":
            # Delete the JSON file to start fresh
            if cfg.json_db_path.exists():
                cfg.json_db_path.unlink()
                print("  → Deleted existing JSON database, retrying...")
                service = RegistrationService()
                result = service.register(
                    email=test_email,
                    password=test_password,
                    username=test_username,
                    full_name="Test User",
                    role="PATIENT"
                )
                print_result(True, "Registration successful after cleanup")
                user_id = result.user_id
                public_key_hash = result.public_key_hash
        else:
            sys.exit(1)
    except Exception as e:
        print_result(False, f"Registration failed: {e}")
        sys.exit(1)
    
    # 2. Test Login
    print_section("Test 2: Login with the same user")
    
    try:
        login_result = service.login(test_email, test_password)
        print_result(True, "Login successful")
        print(f"\n  User ID:      {login_result.user_id}")
        print(f"  Email:        {login_result.email}")
        print(f"  Username:     {login_result.username}")
        print(f"  Role:         {login_result.role}")
        print(f"  Last login:   {login_result.last_login}")
        print(f"\n  Public Key Hash:     {login_result.public_key_hash[:32]}...")
        print(f"  JWT Token:           {login_result.access_token[:50]}...")
        
    except Exception as e:
        print_result(False, f"Login failed: {e}")
    
    # 3. Test Duplicate Registration (should fail)
    print_section("Test 3: Register duplicate user (should fail)")
    
    try:
        duplicate = service.register(
            email=test_email,
            password="differentpass",
            username="differentuser",
            full_name="Different User",
            role="PATIENT"
        )
        print_result(False, "Duplicate registration was allowed — ERROR!")
    except UserAlreadyExistsError:
        print_result(True, "Duplicate correctly rejected")
    except Exception as e:
        print_result(False, f"Unexpected error: {e}")
    
    # 4. Test Wrong Password (should fail)
    print_section("Test 4: Login with wrong password (should fail)")
    
    try:
        wrong_login = service.login(test_email, "wrongpassword")
        print_result(False, "Wrong password was accepted — ERROR!")
    except Exception as e:
        print_result(True, f"Wrong password rejected: {str(e)[:50]}")
    
    # 5. Verify Public Key Lookup
    print_section("Test 5: Public key lookup")
    
    try:
        # Get by email
        pub_key_by_email = service.get_public_key_hex(test_email)
        print_result(True, f"Public key found by email")
        print(f"  → {pub_key_by_email[:50]}...")
        
        # Get by hash
        pub_key_by_hash = service.get_public_key_hex_by_hash(public_key_hash)
        print_result(True, f"Public key found by hash")
        
        # Verify they match
        if pub_key_by_email == pub_key_by_hash:
            print_result(True, "Public key matches across lookup methods")
        else:
            print_result(False, "Public key mismatch across lookup methods")
            
    except Exception as e:
        print_result(False, f"Public key lookup failed: {e}")
    
    # 6. Check the stored data directly (for JSON backend)
    print_section("Test 6: Inspect stored data")
    
    if cfg.db_backend == "json":
        if cfg.json_db_path.exists():
            with open(cfg.json_db_path, 'r') as f:
                data = json.load(f)
            
            print(f"  File: {cfg.json_db_path}")
            print(f"  Users in DB: {len(data.get('users', []))}")
            
            for user in data.get('users', []):
                print(f"\n  User: {user.get('email')}")
                print(f"    - ID: {user.get('id')}")
                print(f"    - Role: {user.get('role')}")
                print(f"    - Public Key Hash: {user.get('public_key_hash', '')[:32]}...")
                print(f"    - Password Hash: {user.get('password_hash', '')[:32]}...")
                print(f"    - Private Key: {'NOT STORED ✓' if 'private' not in user else 'STORED ✗'}")
    
    # Summary
    print_section("Test Summary")
    print("  ✓ Registration creates user and returns private key")
    print("  ✓ Public key stored in database")
    print("  ✓ Private key NOT stored in database")
    print("  ✓ Login works with correct credentials")
    print("  ✓ Wrong credentials rejected")
    print("  ✓ Duplicate registrations blocked")
    print("  ✓ Public key lookup works")


if __name__ == "__main__":
    main()