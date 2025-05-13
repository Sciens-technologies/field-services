# Field Service - FastAPI Application

This is a modular FastAPI application for managing a field service system with users, work orders, authentication, and more.

---

## 🚀 Features

- Modular architecture
- SQLAlchemy models and CRUD operations
- Pydantic schemas
- JWT authentication and security
- Email utilities
- Environment-based config management
- Alembic migrations
- Pytest-based testing

---

## 🧰 Requirements

- Python 3.8+
- `virtualenv` (recommended)
- PostgreSQL (or any supported database)

---

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
-- one time
git clone https://github.com/Sciens-technologies/field-services.git
cd field-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

-- start server
uvicorn main:app --reload

