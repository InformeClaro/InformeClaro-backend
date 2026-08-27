"""
Autenticación: hash de contraseña (bcrypt) y tokens de sesión (JWT).

Instalar dependencias nuevas:
    pip install "passlib[bcrypt]" "python-jose[cryptography]" --break-system-packages
"""
import os
import secrets as secrets_module
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db
from models import Usuario


def _cargar_o_generar_secret_key() -> str:
    """
    Prioridad: variable de entorno SECRET_KEY > archivo local .secret_key > generar una nueva.

    Esto evita usar una clave adivinable (como un valor fijo en el código) sin
    obligarte a configurar nada para probar en tu PC. Para producción, configurá
    SECRET_KEY como variable de entorno real del servidor - así ni siquiera queda
    guardada en un archivo.
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    archivo = Path(__file__).parent / ".secret_key"
    if archivo.exists():
        return archivo.read_text().strip()

    nueva_key = secrets_module.token_hex(32)
    archivo.write_text(nueva_key)
    print(
        "\n[AVISO] No se encontro la variable de entorno SECRET_KEY.\n"
        f"Se genero una clave nueva y se guardo en {archivo.name} para uso local.\n"
        "No subas ese archivo a ningun repositorio (agregalo a .gitignore).\n"
        "Para produccion, configura SECRET_KEY como variable de entorno del servidor.\n"
    )
    return nueva_key


SECRET_KEY = _cargar_o_generar_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # el token dura 7 días

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# auto_error=False para poder tener rutas donde el login es opcional (ej: /situacion)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verificar_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def crear_token(usuario_id: int) -> str:
    expira = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(usuario_id), "exp": expira}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _decodificar_token(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        return None


def get_usuario_actual(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> Usuario:
    """Dependency que EXIGE estar logueado. Usar en rutas como /reclamo."""
    credenciales_invalidas = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado o token inválido",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credenciales_invalidas
    usuario_id = _decodificar_token(token)
    if usuario_id is None:
        raise credenciales_invalidas
    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if usuario is None or not usuario.activo:
        raise credenciales_invalidas
    return usuario


def get_usuario_opcional(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> Optional[Usuario]:
    """Dependency que NO exige login. Devuelve el usuario si mandó un token válido, o None. Usar en /situacion."""
    if not token:
        return None
    usuario_id = _decodificar_token(token)
    if usuario_id is None:
        return None
    return db.query(Usuario).filter(Usuario.id == usuario_id).first()
