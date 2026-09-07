"""
Conexión a la base de datos.

Usa PostgreSQL en produccion (Render), vía la variable de entorno DATABASE_URL.
Si esa variable no está configurada (por ejemplo corriendo en tu PC), usa
SQLite local como antes, para no tener que instalar nada extra para probar.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./bcra_app.db")

# Render entrega la URL con el prefijo "postgres://", pero SQLAlchemy 2.x
# necesita "postgresql://" (mismo motor, solo cambia el nombre del prefijo).
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# El argumento check_same_thread solo aplica a SQLite; con Postgres no hace falta.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency de FastAPI: abre una sesión de DB por request y la cierra al terminar."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()