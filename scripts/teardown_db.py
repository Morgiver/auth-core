#!/usr/bin/env python3
"""
Database teardown script for auth-core package.

This script drops the test database completely.

Usage:
    python teardown_db.py --db-type postgresql --db-name test_auth_pg --host 192.168.1.8
    python teardown_db.py --db-type mongodb --db-name test_auth_mongo --host 192.168.1.8
"""

import argparse
import sys


def teardown_postgresql(host: str, port: int, db_name: str, username: str, password: str):
    """Drop PostgreSQL database"""
    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        print("Error: sqlalchemy not installed. Run: pip install sqlalchemy")
        sys.exit(1)

    admin_url = f"postgresql://{username}:{password}@{host}:{port}/postgres"

    try:
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

        with engine.connect() as conn:
            # Terminate existing connections to the database
            conn.execute(text(f"""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{db_name}'
                AND pid <> pg_backend_pid()
            """))

            # Drop database
            conn.execute(text(f"DROP DATABASE IF EXISTS {db_name}"))
            print(f"  Dropped database '{db_name}'")

        engine.dispose()

    except Exception as e:
        print(f"Error dropping database: {e}")
        sys.exit(1)

    print(f"PostgreSQL teardown completed for '{db_name}'")


def teardown_mongodb(host: str, port: int, db_name: str, username: str, password: str):
    """Drop MongoDB database"""
    try:
        from pymongo import MongoClient
    except ImportError:
        print("Error: pymongo not installed. Run: pip install pymongo")
        sys.exit(1)

    try:
        # Connect to MongoDB
        client = MongoClient(f"mongodb://{username}:{password}@{host}:{port}/")

        # Drop database
        client.drop_database(db_name)
        print(f"  Dropped database '{db_name}'")

        client.close()

    except Exception as e:
        print(f"Error dropping MongoDB database: {e}")
        sys.exit(1)

    print(f"MongoDB teardown completed for '{db_name}'")


def main():
    parser = argparse.ArgumentParser(
        description='Teardown test database for auth-core',
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

    print(f"Tearing down {args.db_type} database '{args.db_name}' on {args.host}:{args.port}")

    if args.db_type == 'postgresql':
        teardown_postgresql(args.host, args.port, args.db_name, args.username, args.password)
    elif args.db_type == 'mongodb':
        teardown_mongodb(args.host, args.port, args.db_name, args.username, args.password)


if __name__ == '__main__':
    main()
