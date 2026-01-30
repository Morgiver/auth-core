#!/usr/bin/env python3
"""
Database setup script for auth-core package.

This script creates the test database and all required tables/indexes
for both PostgreSQL and MongoDB adapters.

Usage:
    python setup_db.py --db-type postgresql --db-name test_auth_pg --host 192.168.1.8
    python setup_db.py --db-type mongodb --db-name test_auth_mongo --host 192.168.1.8
"""

import argparse
import sys
from pathlib import Path


def setup_postgresql(host: str, port: int, db_name: str, username: str, password: str):
    """Create PostgreSQL database and tables for auth-core"""
    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        print("Error: sqlalchemy not installed. Run: pip install sqlalchemy")
        sys.exit(1)

    # Step 1: Create database
    admin_url = f"postgresql://{username}:{password}@{host}:{port}/postgres"

    try:
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

        with engine.connect() as conn:
            # Drop database if exists
            conn.execute(text(f"DROP DATABASE IF EXISTS {db_name}"))
            print(f"  Dropped existing database '{db_name}' (if existed)")

            # Create database
            conn.execute(text(f"CREATE DATABASE {db_name}"))
            print(f"  Created database '{db_name}'")

        engine.dispose()

    except Exception as e:
        print(f"Error creating database: {e}")
        sys.exit(1)

    # Step 2: Create tables
    db_url = f"postgresql://{username}:{password}@{host}:{port}/{db_name}"

    try:
        # Import SQLAlchemy models
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from auth_core.adapters.repositories.sqlalchemy import Base

        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        print(f"  Created all tables (credentials, sessions, tokens, password_resets, oauth)")

        engine.dispose()

    except ImportError as e:
        print(f"Error importing models: {e}")
        print("Make sure auth-core is installed: pip install -e .")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating tables: {e}")
        sys.exit(1)

    print(f"PostgreSQL setup completed successfully for '{db_name}'")


def setup_mongodb(host: str, port: int, db_name: str, username: str, password: str):
    """Create MongoDB database and indexes for auth-core"""
    try:
        from pymongo import MongoClient
    except ImportError:
        print("Error: pymongo not installed. Run: pip install pymongo")
        sys.exit(1)

    try:
        # Connect to MongoDB
        client = MongoClient(f"mongodb://{username}:{password}@{host}:{port}/")

        # Drop database if exists
        client.drop_database(db_name)
        print(f"  Dropped existing database '{db_name}' (if existed)")

        # Get database reference
        db = client[db_name]

        # Credentials collection
        credentials_collection = db.credentials
        credentials_collection.create_index("user_id", unique=True)
        print(f"  Created unique index on credentials.user_id")

        credentials_collection.create_index("status")
        print(f"  Created index on credentials.status")

        # Sessions collection
        sessions_collection = db.sessions
        sessions_collection.create_index("session_id", unique=True)
        print(f"  Created unique index on sessions.session_id")

        sessions_collection.create_index("user_id")
        print(f"  Created index on sessions.user_id")

        sessions_collection.create_index("expires_at")
        print(f"  Created index on sessions.expires_at")

        sessions_collection.create_index([("user_id", 1), ("status", 1)])
        print(f"  Created compound index on sessions.user_id and status")

        # Tokens collection
        tokens_collection = db.tokens
        tokens_collection.create_index("token_hash", unique=True)
        print(f"  Created unique index on tokens.token_hash")

        tokens_collection.create_index("user_id")
        print(f"  Created index on tokens.user_id")

        tokens_collection.create_index("expires_at")
        print(f"  Created index on tokens.expires_at")

        # Password resets collection
        password_resets_collection = db.password_resets
        password_resets_collection.create_index("token_hash", unique=True)
        print(f"  Created unique index on password_resets.token_hash")

        password_resets_collection.create_index("user_id")
        print(f"  Created index on password_resets.user_id")

        password_resets_collection.create_index("expires_at")
        print(f"  Created index on password_resets.expires_at")

        # OAuth connections collection
        oauth_collection = db.oauth_connections
        oauth_collection.create_index([("provider", 1), ("provider_user_id", 1)], unique=True)
        print(f"  Created unique compound index on oauth_connections.provider and provider_user_id")

        oauth_collection.create_index("user_id")
        print(f"  Created index on oauth_connections.user_id")

        client.close()

    except Exception as e:
        print(f"Error setting up MongoDB: {e}")
        sys.exit(1)

    print(f"MongoDB setup completed successfully for '{db_name}'")


def main():
    parser = argparse.ArgumentParser(
        description='Setup test database for auth-core',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--db-type',
        required=True,
        choices=['postgresql', 'mongodb'],
        help='Database type'
    )

    parser.add_argument(
        '--db-name',
        required=True,
        help='Database name (should start with test_)'
    )

    parser.add_argument(
        '--host',
        required=True,
        help='Database host'
    )

    parser.add_argument(
        '--port',
        type=int,
        help='Database port (default: 5432 for PostgreSQL, 27017 for MongoDB)'
    )

    parser.add_argument(
        '--username',
        default='postgres',
        help='Database username (default: postgres)'
    )

    parser.add_argument(
        '--password',
        default='postgres',
        help='Database password (default: postgres)'
    )

    args = parser.parse_args()

    # Validate database name starts with test_
    if not args.db_name.startswith('test_'):
        print("Error: Database name must start with 'test_' to avoid accidental data loss")
        sys.exit(1)

    # Set default port based on database type
    if args.port is None:
        args.port = 5432 if args.db_type == 'postgresql' else 27017

    print(f"Setting up {args.db_type} database '{args.db_name}' on {args.host}:{args.port}")

    if args.db_type == 'postgresql':
        setup_postgresql(args.host, args.port, args.db_name, args.username, args.password)
    elif args.db_type == 'mongodb':
        setup_mongodb(args.host, args.port, args.db_name, args.username, args.password)


if __name__ == '__main__':
    main()
