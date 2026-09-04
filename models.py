"""
Modelo de datos - App Central de Deudores BCRA

Asume FastAPI + SQLAlchemy + Pydantic (stack más común para este tipo de proyecto).
Si estás usando otra cosa (SQLModel, Django, etc.) avisame y lo adapto.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Numeric
from sqlalchemy.orm import relationship
from pydantic import BaseModel, EmailStr, Field

from database import Base


# ---------------------------------------------------------------------------
# TABLA: usuarios
# ---------------------------------------------------------------------------
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)

    # Login
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)  # nunca guardar la contraseña en texto plano (usar bcrypt)
    email_verificado = Column(Boolean, default=False)

    # Datos personales (necesarios para armar la carta de reclamo formal)
    nombre = Column(String(100), nullable=True)
    apellido = Column(String(100), nullable=True)
    dni = Column(String(20), nullable=True)
    cuit_cuil = Column(String(20), nullable=True)  # el CUIT/CUIL de la persona (para autocompletar consultas)
    domicilio = Column(String(255), nullable=True)
    localidad = Column(String(100), nullable=True)
    provincia = Column(String(100), nullable=True)
    telefono = Column(String(30), nullable=True)

    # Metadata
    fecha_creacion = Column(DateTime, default=datetime.utcnow)
    fecha_ultimo_login = Column(DateTime, nullable=True)
    activo = Column(Boolean, default=True)

    reclamos = relationship("Reclamo", back_populates="usuario")
    consultas = relationship("ConsultaBCRA", back_populates="usuario")


# ---------------------------------------------------------------------------
# TABLA: reclamos (lo que se genera cuando el usuario aprieta "Iniciar reclamo")
# ---------------------------------------------------------------------------
class Reclamo(Base):
    __tablename__ = "reclamos"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)

    entidad = Column(String(255), nullable=False)          # ej: "BANCO DE GALICIA Y BUENOS AIRES S.A."
    cuit_cuil_consultado = Column(String(20), nullable=False)
    periodo_deuda = Column(String(10), nullable=False)      # ej: "06/2026"
    situacion = Column(Integer, nullable=False)              # 1 a 6
    monto = Column(Numeric(14, 2), nullable=True)

    estado = Column(String(30), default="pendiente")  # pendiente | generado | enviado | resuelto | rechazado
    archivo_pdf_path = Column(String(500), nullable=True)   # ruta al PDF de la carta generada
    documentacion_adjunta = Column(Boolean, default=False)  # si el usuario adjunto su propio comprobante
    plazo_respuesta_dias = Column(Integer, default=5)       # dias habiles que menciona la carta (art. 16, Ley 25.326)

    fecha_deteccion = Column(DateTime, default=datetime.utcnow)  # cuándo detectamos que estaba caducada
    fecha_envio = Column(DateTime, nullable=True)
    fecha_resolucion = Column(DateTime, nullable=True)

    usuario = relationship("Usuario", back_populates="reclamos")


# ---------------------------------------------------------------------------
# TABLA: consultas_bcra (historial de consultas, con o sin usuario logueado)
# ---------------------------------------------------------------------------
class ConsultaBCRA(Base):
    __tablename__ = "consultas_bcra"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)  # nullable: se puede consultar sin cuenta

    cuit_cuil_consultado = Column(String(20), nullable=False)
    fecha_consulta = Column(DateTime, default=datetime.utcnow)
    peor_situacion = Column(Integer, nullable=True)
    cantidad_aptas_reclamo = Column(Integer, default=0)

    usuario = relationship("Usuario", back_populates="consultas")


# ---------------------------------------------------------------------------
# ESQUEMAS Pydantic (para las rutas de la API - request/response)
# ---------------------------------------------------------------------------
class UsuarioRegistro(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, description="Mínimo 8 caracteres")


class UsuarioLogin(BaseModel):
    email: EmailStr
    password: str


class UsuarioPerfilUpdate(BaseModel):
    nombre: str | None = None
    apellido: str | None = None
    dni: str | None = None
    cuit_cuil: str | None = None
    domicilio: str | None = None
    localidad: str | None = None
    provincia: str | None = None
    telefono: str | None = None


class UsuarioOut(BaseModel):
    id: int
    email: str
    nombre: str | None
    apellido: str | None
    dni: str | None
    cuit_cuil: str | None
    domicilio: str | None
    localidad: str | None
    provincia: str | None
    telefono: str | None
    email_verificado: bool

    class Config:
        from_attributes = True


class ReclamoOut(BaseModel):
    id: int
    numero: str  # formato RC-{anio}-{id:06d}, se arma al leer, no se guarda en la db
    entidad: str
    cuit_cuil_consultado: str
    periodo_deuda: str
    situacion: int
    estado: str
    documentacion_adjunta: bool
    plazo_respuesta_dias: int
    fecha_deteccion: datetime
    fecha_envio: datetime | None
    fecha_resolucion: datetime | None

    class Config:
        from_attributes = True


ESTADOS_RECLAMO_VALIDOS = {"pendiente", "generado", "enviado", "resuelto", "rechazado"}


class ReclamoUpdate(BaseModel):
    """Todos los campos son opcionales: se manda solo lo que cambia (ej. al confirmar el envio)."""
    estado: str | None = Field(default=None, description=f"Uno de: {', '.join(sorted(ESTADOS_RECLAMO_VALIDOS))}")
    documentacion_adjunta: bool | None = None
