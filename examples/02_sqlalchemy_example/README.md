# SQLAlchemy Example

This example demonstrates how to use auth-core with SQLAlchemy for database persistence.

## Features Demonstrated

- Setting up SQLAlchemy with SQLite/PostgreSQL/MySQL
- Creating database tables using Alembic migrations (optional)
- Using SQLAlchemy repositories for persistence
- Complete authentication flow with database
- Password management with database storage
- Token generation and verification with database

## Requirements

```bash
pip install auth-core[sqlalchemy,argon2,jwt]
```

## Running the Example

### With SQLite (Default)

```bash
python main.py
```

This creates a `auth_demo.db` file in the current directory.

### With PostgreSQL

Modify the connection string in `main.py`:

```python
engine = create_engine("postgresql://user:password@localhost/auth_db")
```

### With MySQL

```python
engine = create_engine("mysql+pymysql://user:password@localhost/auth_db")
```

## Database Schema

The example creates the following tables:

- `auth_credentials` - User credentials (passwords, MFA)
- `auth_tokens` - Access and refresh tokens
- `auth_sessions` - User sessions
- `auth_password_resets` - Password reset requests
- `auth_oauth_accounts` - OAuth account links

## Inspecting the Database

### SQLite

```bash
sqlite3 auth_demo.db

# View tables
.tables

# View credentials
SELECT * FROM auth_credentials;

# View tokens
SELECT * FROM auth_tokens;
```

### PostgreSQL

```bash
psql -U user -d auth_db

# View credentials
SELECT * FROM auth_credentials;
```

## Production Considerations

1. **Connection Pooling**: Use connection pooling for production
2. **Migrations**: Use Alembic for database migrations
3. **Indexes**: Ensure proper indexes are created (already done in models)
4. **Secrets**: Store secret keys in environment variables
5. **Transactions**: Handle transactions properly in your application

## Using with Flask

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from auth_core.adapters.repositories.sqlalchemy import (
    Base,
    SQLAlchemyCredentialRepository,
)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://...'
db = SQLAlchemy(app)

# Use the existing Base from auth-core
Base.metadata.create_all(db.engine)

# Create repositories
credential_repo = SQLAlchemyCredentialRepository(db.session)
```

## Using with FastAPI

```python
from fastapi import FastAPI, Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from auth_core.adapters.repositories.sqlalchemy import (
    Base,
    SQLAlchemyCredentialRepository,
)

DATABASE_URL = "postgresql://user:password@localhost/auth_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user_data: dict, db: Session = Depends(get_db)):
    repo = SQLAlchemyCredentialRepository(db)
    auth_service = AuthService(credential_repo=repo, ...)
    return auth_service.register(...)
```
