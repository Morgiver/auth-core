#!/usr/bin/env python3
"""Helper script to run all auth-core contract tests with PostgreSQL and MongoDB"""

import os
import sys
import subprocess

def run_tests_for_db(db_type, conn_string, adapter):
    """Run tests for a specific database type"""
    print(f"\n{'='*70}")
    print(f"Testing auth-core with {db_type.upper()} ({adapter})")
    print(f"{'='*70}\n")

    os.environ['TEST_DB_TYPE'] = db_type
    os.environ['TEST_DB_NAME'] = f'test_auth_{adapter}'
    os.environ['TEST_DB_CONNECTION_STRING'] = conn_string
    os.environ['TEST_ADAPTER'] = adapter

    result = subprocess.run([
        sys.executable,
        '-m', 'pytest',
        'tests/contracts/',
        '-v',
        '--tb=short',
        f'--adapter={adapter}'
    ])

    return result.returncode

# Run PostgreSQL tests
pg_result = run_tests_for_db(
    'postgresql',
    'postgresql://postgres:postgres@192.168.1.8:5432/test_auth_pg',
    'sqlalchemy'
)

# Run MongoDB tests
mongo_result = run_tests_for_db(
    'mongodb',
    'mongodb://admin:admin@192.168.1.8:27017/test_auth_mongo?authSource=admin',
    'mongodb'
)

# Exit with error if any tests failed
if pg_result != 0 or mongo_result != 0:
    print(f"\n{'='*70}")
    print(f"FAILED: PostgreSQL={pg_result}, MongoDB={mongo_result}")
    print(f"{'='*70}")
    sys.exit(1)
else:
    print(f"\n{'='*70}")
    print(f"ALL TESTS PASSED!")
    print(f"{'='*70}")
    sys.exit(0)
