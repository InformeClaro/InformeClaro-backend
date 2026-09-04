"""
API propia para la app de consulta BCRA + deteccion de deudas caducadas.
Consume la API publica de Central de Deudores del BCRA y agrega la logica
de negocio: dias de mora, caducidad segun Ley 25.326 art. 26, y generacion
de nota de reclamo (habeas data).

Correr local:
    pip install fastapi uvicorn requests sqlalchemy "passlib[bcrypt]" "python-jose[cryptography]" slowapi --break-system-packages
    uvicorn main:app --reload
"""
from datetime import date, datetime
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape as _xml_escape
import os
import re

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, field_validator
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import (
    Usuario,
    Reclamo as ReclamoDB,
    ConsultaBCRA,
    UsuarioRegistro,
    UsuarioLogin,
    UsuarioOut,
    UsuarioPerfilUpdate,
    ReclamoOut,
    ReclamoUpdate,
    ESTADOS_RECLAMO_VALIDOS,
)
from auth import (
    hash_password,
    verificar_password,
    crear_token,
    get_usuario_actual,
    get_usuario_opcional,
)

app = FastAPI(title="API Consulta BCRA - Central de Deudores", version="1.1.0")

# Limite de pedidos por IP, para frenar ataques de fuerza bruta contra /auth/login
# y spam de cuentas en /auth/registro. No afecta el uso normal de la app.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Crea las tablas en la base si todavía no existen (usuarios, reclamos, consultas_bcra).
Base.metadata.create_all(bind=engine)

# Permite que el frontend (web o app) consuma esta API sin que el navegador lo bloquee.
# Los origenes permitidos se toman de la variable de entorno CORS_ORIGINS (separados
# por coma). Si no se configura, se usan defaults comunes para probar en local (ej.
# la extension Live Server de VS Code, que sirve en el puerto 5500). Si abris el demo
# HTML directamente como archivo (file://) el navegador manda Origin "null" y estos
# origenes no lo cubren - conviene servirlo con un servidor local en uno de estos puertos.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5500,http://127.0.0.1:5500"
    ).split(",") if o.strip()],
    allow_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

BCRA_BASE_URL = "https://api.bcra.gob.ar/centraldedeudores/v1.0/Deudas"

# Plazo maximo (en anios) que la ley permite mantener info negativa vigente
# desde la fecha de mora (Ley 25.326, art. 26 inc. 4)
PLAZO_CADUCIDAD_ANIOS = 5

SITUACIONES = {
    1: {"nombre": "Situacion normal", "riesgo": "bajo"},
    2: {"nombre": "Riesgo bajo (seguimiento especial)", "riesgo": "medio-bajo"},
    3: {"nombre": "Riesgo medio", "riesgo": "medio"},
    4: {"nombre": "Riesgo alto", "riesgo": "alto"},
    5: {"nombre": "Irrecuperable", "riesgo": "muy alto"},
    6: {"nombre": "Irrecuperable por disposicion tecnica", "riesgo": "muy alto"},
}


def _normalizar_cuit(cuit: str) -> str:
    """Valida y normaliza CUIT/CUIL/CDI de 11 digitos (algoritmo oficial de modulo 11)."""
    limpio = re.sub(r"[-\s]", "", cuit or "")
    if not limpio.isdigit() or len(limpio) != 11:
        raise HTTPException(status_code=422, detail="CUIT/CUIL inválido: debe contener 11 dígitos")
    factores = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
    total = sum(int(d) * f for d, f in zip(limpio[:10], factores))
    resto = 11 - (total % 11)
    digito = 0 if resto == 11 else 9 if resto == 10 else resto
    if digito != int(limpio[-1]):
        raise HTTPException(status_code=422, detail="CUIT/CUIL inválido: no pasa la validación")
    return limpio


# ---------- Modelos de respuesta ----------

class EntidadDeuda(BaseModel):
    entidad: str
    situacion: int
    situacion_nombre: str
    riesgo: str
    monto_pesos: float
    dias_atraso: int
    periodo_inicio_mora: Optional[str]
    dias_desde_mora: Optional[int]
    posible_situacion_a_revisar: bool  # antes "caducada": ver nota en _calcular_caducidad
    es_estimacion: bool                 # antes "caducidad_estimada"
    motivo_a_revisar: Optional[str]     # antes "motivo_caducidad"


class PosibleCesion(BaseModel):
    entidad_anterior: str
    entidad_nueva: str
    periodo_corte: str
    motivo: str


class SituacionResponse(BaseModel):
    cuit: str
    denominacion: Optional[str]
    tiene_deudas: bool
    periodo_consultado: Optional[str]
    peor_situacion: Optional[int]
    entidades: list[EntidadDeuda]
    posibles_cesiones: list[PosibleCesion] = []


class ReclamoRequest(BaseModel):
    cuit: str
    entidad: str
    periodo_deuda: str = ""
    situacion: int = 0
    # Estos tres ahora son opcionales: si el usuario ya completo su perfil
    # (ver /auth/perfil), se usan esos datos y no hace falta reenviarlos.
    nombre_completo: Optional[str] = None
    domicilio: Optional[str] = None
    email: Optional[str] = None
    documentacion_adjunta: bool = False  # si el usuario dice haber adjuntado su comprobante

    @field_validator("cuit")
    @classmethod
    def validar_cuit(cls, value: str) -> str:
        return _normalizar_cuit(value)


# ---------- Logica de negocio ----------

def _periodo_a_fecha(periodo: str) -> Optional[date]:
    """Convierte un periodo 'YYYYMM' o 'YYYY-MM' en la fecha del primer dia de ese mes."""
    if not periodo:
        return None
    limpio = periodo.replace("-", "")
    if len(limpio) != 6 or not limpio.isdigit():
        return None
    anio, mes = int(limpio[:4]), int(limpio[4:6])
    try:
        return date(anio, mes, 1)
    except ValueError:
        return None


def _calcular_caducidad(entidad_nombre: str, situacion_actual: int, periodos_historicos: list) -> dict:
    """
    Estima desde cuando una entidad viene informando mora (situacion >= 2)
    de forma ininterrumpida, recorriendo el historico de periodos hacia atras,
    y si esa racha ya superaria el plazo habitual de permanencia (5 anios,
    segun el criterio del art. 26 inc. 4 de la Ley 25.326).

    IMPORTANTE: esto es una ESTIMACION propia de la app, no un dictamen legal.
    El calculo no puede detectar reconocimientos de deuda, pagos parciales,
    interrupciones del plazo, ni cesiones de la deuda a otra entidad (eso queda
    para una version futura). Por eso el resultado siempre se devuelve como
    "posible situacion a revisar", nunca como un hecho consumado tipo
    "la deuda esta caducada" - esa distincion hay que mantenerla tambien en
    cualquier lugar donde se muestre este dato en el frontend.

    periodos_historicos debe venir ordenado del mas reciente al mas antiguo.

    Si la racha de mora llega hasta el limite de los datos devueltos por el
    BCRA, no podemos confirmar si la mora empezo antes de esa fecha: se marca
    'es_estimacion' porque el dato real podria ser mas antiguo (piso, no techo).
    """
    if situacion_actual < 2:
        return {
            "periodo_inicio": None, "dias_desde_mora": None,
            "posible_situacion_a_revisar": False, "es_estimacion": False, "motivo": None,
        }

    periodo_inicio = None
    llego_al_borde = True
    for periodo in periodos_historicos:
        entidad_data = next(
            (e for e in periodo.get("entidades", []) if e.get("entidad") == entidad_nombre),
            None,
        )
        if entidad_data and entidad_data.get("situacion", 1) >= 2:
            periodo_inicio = periodo.get("periodo")
        else:
            llego_al_borde = False
            break

    if not periodo_inicio:
        return {
            "periodo_inicio": None, "dias_desde_mora": None,
            "posible_situacion_a_revisar": False, "es_estimacion": False,
            "motivo": "No hay suficiente historico para estimar la fecha de inicio de la mora.",
        }

    fecha_inicio = _periodo_a_fecha(periodo_inicio)
    if not fecha_inicio:
        return {
            "periodo_inicio": periodo_inicio, "dias_desde_mora": None,
            "posible_situacion_a_revisar": False, "es_estimacion": False, "motivo": None,
        }

    dias = (date.today() - fecha_inicio).days
    anios = dias / 365.25
    a_revisar = anios >= PLAZO_CADUCIDAD_ANIOS

    motivo = None
    if a_revisar:
        motivo = (
            f"Detectamos que esta entidad podria estar informando mora ininterrumpida "
            f"desde {periodo_inicio}, lo que superaria los {PLAZO_CADUCIDAD_ANIOS} anios "
            "que suele considerarse como plazo de permanencia (art. 26 inc. 4, Ley 25.326). "
            "Esto es una estimacion nuestra a partir del historico disponible, no una "
            "confirmacion: te recomendamos verificarlo antes de reclamar."
        )
    elif llego_al_borde:
        motivo = (
            "La mora ya venia informandose desde el periodo mas antiguo que devolvio "
            "el BCRA; podria ser mas vieja de lo que alcanzamos a confirmar con este historico."
        )

    return {
        "periodo_inicio": periodo_inicio,
        "dias_desde_mora": dias,
        "posible_situacion_a_revisar": a_revisar,
        # es_estimacion = no tenemos certeza total: o esta muy cerca del limite,
        # o la racha llega al borde de los datos disponibles
        "es_estimacion": llego_al_borde or (a_revisar and anios < PLAZO_CADUCIDAD_ANIOS + 0.5),
        "motivo": motivo,
    }


def _consultar_bcra(cuit: str) -> dict:
    cuit = _normalizar_cuit(cuit)
    url = f"{BCRA_BASE_URL}/{cuit}"
    try:
        resp = requests.get(url, timeout=15)
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"No se pudo consultar el BCRA: {e}")

    if resp.status_code == 404:
        return {"sin_deudas": True}
    if resp.status_code != 200:
        print(f"[DEBUG] BCRA respondio {resp.status_code} para {url}: {resp.text[:300]}")
        raise HTTPException(status_code=502, detail="El BCRA devolvio un error inesperado")

    return resp.json()


def _consultar_bcra_historico(cuit: str) -> list:
    """Trae el historico de periodos. Si falla, devuelve lista vacia (no rompe la consulta principal)."""
    cuit = _normalizar_cuit(cuit)
    url = f"{BCRA_BASE_URL}/Historicas/{cuit}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        resultados = resp.json().get("results", {})
        return resultados.get("periodos", [])
    except requests.exceptions.RequestException:
        return []


def _detectar_posibles_cesiones(periodos_historicos: list) -> list:
    """
    Heuristica para detectar posibles cesiones de deuda entre entidades
    (ej. Banco X -> Fideicomiso X), a partir del historico de hasta 24
    periodos que devuelve el BCRA.

    Idea: si una entidad deja de informar mora (situacion >= 2) en un
    periodo, y en ese mismo periodo o el siguiente aparece una entidad
    nueva informando mora por un monto similar, podria tratarse de la
    misma deuda cedida a otra entidad.

    IMPORTANTE: esto es solo una alerta a revisar, no una confirmacion.
    Puede haber falsos positivos (dos deudas distintas que cambian de
    estado en el mismo periodo por coincidencia) y falsos negativos (una
    cesion con un monto que cambio bastante, por ejemplo por intereses).
    No se usa todavia para extender el calculo de dias_desde_mora en
    _calcular_caducidad - eso implicaria "fusionar" el historico de dos
    entidades distintas, y conviene hacerlo recien cuando el usuario (o el
    equipo) haya podido validar esta heuristica con casos reales.
    """
    if not periodos_historicos:
        return []

    # ordenar del periodo mas antiguo al mas reciente para recorrerlo cronologicamente
    periodos_ordenados = sorted(periodos_historicos, key=lambda p: p.get("periodo", "") or "")

    entidades_por_periodo = []
    for p in periodos_ordenados:
        activas = {
            e.get("entidad"): (e.get("monto", 0) or 0)
            for e in p.get("entidades", [])
            if e.get("situacion", 1) >= 2 and e.get("entidad")
        }
        entidades_por_periodo.append((p.get("periodo"), activas))

    TOLERANCIA_MONTO = 0.2  # 20% - los intereses/gastos pueden mover el monto un poco

    alertas = []
    vistas = set()  # evita duplicar la misma alerta si se repite en mas de un corte
    for i in range(len(entidades_por_periodo) - 1):
        periodo_actual, activas_actual = entidades_por_periodo[i]
        periodo_siguiente, activas_siguiente = entidades_por_periodo[i + 1]

        desaparecidas = set(activas_actual) - set(activas_siguiente)
        aparecidas = set(activas_siguiente) - set(activas_actual)

        for entidad_vieja in desaparecidas:
            monto_viejo = activas_actual[entidad_vieja]
            if monto_viejo <= 0:
                continue
            for entidad_nueva in aparecidas:
                monto_nuevo = activas_siguiente[entidad_nueva]
                diferencia = abs(monto_nuevo - monto_viejo) / monto_viejo
                clave = (entidad_vieja, entidad_nueva)
                if diferencia <= TOLERANCIA_MONTO and clave not in vistas:
                    vistas.add(clave)
                    alertas.append(PosibleCesion(
                        entidad_anterior=entidad_vieja,
                        entidad_nueva=entidad_nueva,
                        periodo_corte=periodo_siguiente,
                        motivo=(
                            f"'{entidad_vieja}' dejo de informar en {periodo_actual} y "
                            f"'{entidad_nueva}' empezo a informar un monto similar a partir "
                            f"de {periodo_siguiente}. Podria tratarse de una cesion de la "
                            "misma deuda, pero tambien podria ser una coincidencia entre "
                            "dos deudas distintas: conviene verificarlo antes de asumir "
                            "continuidad."
                        ),
                    ))

    return alertas


# ---------- Endpoints ----------

@app.get("/situacion/{cuit}", response_model=SituacionResponse)
@limiter.limit("10/minute")
def obtener_situacion(
    request: Request,
    cuit: str,
    db: Session = Depends(get_db),
    usuario: Optional[Usuario] = Depends(get_usuario_opcional),
):
    """
    Consulta la situacion crediticia de un CUIT/CUIL/CDI y devuelve,
    por cada entidad, si hay una posible situacion a revisar segun el
    historico disponible (no es una confirmacion legal, ver
    _calcular_caducidad). Tambien devuelve alertas de posibles cesiones
    de deuda entre entidades (ver _detectar_posibles_cesiones).

    No requiere estar logueado (baja friccion para la primera consulta).
    Si el usuario esta logueado, la consulta queda guardada en su historial.
    """
    cuit = _normalizar_cuit(cuit)
    data = _consultar_bcra(cuit)

    if data.get("sin_deudas"):
        _guardar_consulta(db, usuario, cuit, peor_situacion=None, aptas_reclamo=0)
        return SituacionResponse(
            cuit=cuit, denominacion=None, tiene_deudas=False, periodo_consultado=None,
            peor_situacion=None, entidades=[]
        )

    resultados = data.get("results")
    denominacion = (resultados or {}).get("denominacion")
    periodos = (resultados or {}).get("periodos", [])
    if not periodos:
        _guardar_consulta(db, usuario, cuit, peor_situacion=None, aptas_reclamo=0)
        return SituacionResponse(
            cuit=cuit, denominacion=denominacion, tiene_deudas=False, periodo_consultado=None,
            peor_situacion=None, entidades=[]
        )

    ultimo_periodo = periodos[0]
    entidades_raw = ultimo_periodo.get("entidades", [])

    # El historico se usa para reconstruir desde cuando viene la mora,
    # porque fechaSit1 no es confiable para esto (ver nota en _calcular_caducidad)
    periodos_historicos = _consultar_bcra_historico(cuit)

    entidades = []
    peor_situacion = 1
    for e in entidades_raw:
        situacion = e.get("situacion", 1)
        peor_situacion = max(peor_situacion, situacion)
        info_sit = SITUACIONES.get(situacion, SITUACIONES[1])
        caducidad = _calcular_caducidad(e.get("entidad", ""), situacion, periodos_historicos)

        entidades.append(EntidadDeuda(
            entidad=e.get("entidad", ""),
            situacion=situacion,
            situacion_nombre=info_sit["nombre"],
            riesgo=info_sit["riesgo"],
            monto_pesos=(e.get("monto", 0) or 0) * 1000,
            dias_atraso=e.get("diasAtrasoPago", 0) or 0,
            periodo_inicio_mora=caducidad["periodo_inicio"],
            dias_desde_mora=caducidad["dias_desde_mora"],
            posible_situacion_a_revisar=caducidad["posible_situacion_a_revisar"],
            es_estimacion=caducidad["es_estimacion"],
            motivo_a_revisar=caducidad["motivo"],
        ))

    aptas_reclamo = sum(1 for e in entidades if e.posible_situacion_a_revisar)
    _guardar_consulta(db, usuario, cuit, peor_situacion=peor_situacion, aptas_reclamo=aptas_reclamo)

    posibles_cesiones = _detectar_posibles_cesiones(periodos_historicos)

    return SituacionResponse(
        cuit=cuit,
        denominacion=denominacion,
        tiene_deudas=True,
        periodo_consultado=ultimo_periodo.get("periodo"),
        peor_situacion=peor_situacion,
        entidades=entidades,
        posibles_cesiones=posibles_cesiones,
    )


def _guardar_consulta(
    db: Session, usuario: Optional[Usuario], cuit: str, peor_situacion: Optional[int], aptas_reclamo: int
) -> None:
    """Registra la consulta en el historial. usuario_id queda null si no hay login."""
    registro = ConsultaBCRA(
        usuario_id=usuario.id if usuario else None,
        cuit_cuil_consultado=cuit,
        peor_situacion=peor_situacion,
        cantidad_aptas_reclamo=aptas_reclamo,
    )
    db.add(registro)
    db.commit()


# ---------- Autenticacion ----------

@app.post("/auth/registro", response_model=UsuarioOut)
@limiter.limit("5/minute")
def registrar_usuario(request: Request, datos: UsuarioRegistro, db: Session = Depends(get_db)):
    existente = db.query(Usuario).filter(Usuario.email == datos.email).first()
    if existente:
        raise HTTPException(status_code=400, detail="Ya existe una cuenta con ese email")

    nuevo = Usuario(email=datos.email, password_hash=hash_password(datos.password))
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo


@app.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm espera "username" y "password" (estandar de FastAPI);
    # el frontend debe mandar el email en el campo "username".
    usuario = db.query(Usuario).filter(Usuario.email == form.username).first()
    if not usuario or not verificar_password(form.password, usuario.password_hash):
        raise HTTPException(status_code=401, detail="Email o contrasena incorrectos")

    usuario.fecha_ultimo_login = datetime.utcnow()
    db.commit()

    token = crear_token(usuario.id)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UsuarioOut)
def mi_perfil(usuario: Usuario = Depends(get_usuario_actual)):
    return usuario


@app.put("/auth/perfil", response_model=UsuarioOut)
def actualizar_perfil(
    datos: UsuarioPerfilUpdate,
    usuario: Usuario = Depends(get_usuario_actual),
    db: Session = Depends(get_db),
):
    """Completa nombre, DNI, domicilio, etc. - se usan despues para prellenar la carta de reclamo."""
    for campo, valor in datos.model_dump(exclude_unset=True).items():
        setattr(usuario, campo, valor)
    db.commit()
    db.refresh(usuario)
    return usuario


@app.post("/reclamo")
def generar_reclamo(
    req: ReclamoRequest,
    usuario: Usuario = Depends(get_usuario_actual),
    db: Session = Depends(get_db),
):
    """
    Genera el texto de una nota de reclamo (habeas data / art. 16 Ley 25.326)
    lista para que el usuario presente ante la entidad informante o ante el BCRA.
    No reemplaza asesoramiento legal en casos complejos o disputados.

    Requiere estar logueado: es el punto del flujo donde tiene sentido pedir
    cuenta, porque a partir de aca guardamos datos personales y el estado del tramite.
    """
    if req.situacion < 1 or req.situacion > 6:
        raise HTTPException(status_code=422, detail="Situación BCRA inválida")
    if not req.entidad.strip():
        raise HTTPException(status_code=422, detail="La entidad es obligatoria")

    # Si el usuario ya completo su perfil, usamos esos datos como base;
    # lo que venga en el request (req) los pisa si el usuario lo especifico distinto.
    nombre_completo = req.nombre_completo or f"{usuario.nombre or ''} {usuario.apellido or ''}".strip()
    domicilio = req.domicilio or usuario.domicilio
    email = req.email or usuario.email

    fecha_hoy = date.today().strftime("%d/%m/%Y")
    texto = f"""
Sr./Sra. Responsable de Datos Personales
{req.entidad}

De mi consideracion:

Quien suscribe, {nombre_completo}, CUIT/CUIL N° {req.cuit}, en ejercicio
del derecho conferido por el art. 43 de la Constitucion Nacional y los
arts. 16 y 26 de la Ley 25.326 de Proteccion de Datos Personales, vengo por
la presente a SOLICITAR que se revise la vigencia de los datos personales
informados por esa entidad a la Central de Deudores del Sistema Financiero
del BCRA y/o a bases de datos de informes comerciales, dado que, segun mi
propio analisis del historico disponible, esta informacion podria haber
superado el plazo maximo de permanencia previsto en el art. 26 inc. 4 de
la ley citada. Agradecere confirmar la situacion y, de corresponder,
proceder a la rectificacion y/o supresion del dato.

Se recuerda que, conforme el art. 16 de la Ley 25.326, esa entidad cuenta
con un plazo de CINCO (5) DIAS HABILES para responder a este pedido.

Quedo a la espera de una respuesta dentro del plazo legal.

Saludo atentamente,
{nombre_completo}
{f"Domicilio: {domicilio}" if domicilio else ""}
{f"Email: {email}" if email else ""}
Fecha: {fecha_hoy}

---
Nota generada con asistencia de esta aplicacion a partir de un analisis
automatizado del historico informado por el BCRA. No constituye asesoramiento
legal ni un dictamen sobre su caso particular; se recomienda revisar los datos
antes de presentar este reclamo.
""".strip()

    registro = ReclamoDB(
        usuario_id=usuario.id,
        entidad=req.entidad,
        cuit_cuil_consultado=req.cuit,
        periodo_deuda=req.periodo_deuda,
        situacion=req.situacion,
        estado="generado",
        documentacion_adjunta=req.documentacion_adjunta,
        plazo_respuesta_dias=5,  # art. 16, Ley 25.326
    )
    db.add(registro)
    db.commit()
    db.refresh(registro)

    registro.archivo_pdf_path = _generar_pdf_reclamo(texto, registro.id)
    db.commit()

    return {"texto_reclamo": texto, "reclamo_id": registro.id}


def _generar_pdf_reclamo(texto: str, reclamo_id: int) -> str:
    """
    Convierte el texto de la carta de reclamo en un PDF prolijo, listo para
    adjuntar o presentar en persona. Se guarda en ./reclamos_pdf/reclamo_{id}.pdf
    (carpeta local - en produccion conviene moverla a almacenamiento persistente,
    ej. un bucket, en vez del disco del servidor).
    """
    carpeta = Path(__file__).parent / "reclamos_pdf"
    carpeta.mkdir(exist_ok=True)
    ruta = carpeta / f"reclamo_{reclamo_id}.pdf"

    doc = SimpleDocTemplate(
        str(ruta), pagesize=letter,
        topMargin=56, bottomMargin=56, leftMargin=56, rightMargin=56,
    )
    styles = getSampleStyleSheet()
    estilo = styles["Normal"]
    estilo.fontName = "Helvetica"
    estilo.fontSize = 10.5
    estilo.leading = 15

    story = []
    for parrafo in texto.split("\n\n"):
        # Escapamos el texto (por si tiene &, <, > sueltos) antes de convertir
        # los saltos de linea en <br/>, que reportlab si interpreta.
        html = _xml_escape(parrafo).replace("\n", "<br/>")
        story.append(Paragraph(html, estilo))
        story.append(Spacer(1, 10))

    doc.build(story)
    return str(ruta)


def _numero_reclamo(registro: ReclamoDB) -> str:
    """Numero 'lindo' para mostrarle al usuario, armado a partir del id real y el anio de deteccion."""
    anio = (registro.fecha_deteccion or datetime.utcnow()).year
    return f"RC-{anio}-{registro.id:06d}"


def _reclamo_a_out(registro: ReclamoDB) -> ReclamoOut:
    return ReclamoOut(
        id=registro.id,
        numero=_numero_reclamo(registro),
        entidad=registro.entidad,
        cuit_cuil_consultado=registro.cuit_cuil_consultado,
        periodo_deuda=registro.periodo_deuda,
        situacion=registro.situacion,
        estado=registro.estado,
        documentacion_adjunta=registro.documentacion_adjunta,
        plazo_respuesta_dias=registro.plazo_respuesta_dias,
        fecha_deteccion=registro.fecha_deteccion,
        fecha_envio=registro.fecha_envio,
        fecha_resolucion=registro.fecha_resolucion,
    )


@app.get("/reclamos", response_model=list[ReclamoOut])
def listar_reclamos(
    usuario: Usuario = Depends(get_usuario_actual),
    db: Session = Depends(get_db),
):
    """Lista los reclamos del usuario logueado, del mas reciente al mas viejo. Para la pantalla de seguimiento."""
    registros = (
        db.query(ReclamoDB)
        .filter(ReclamoDB.usuario_id == usuario.id)
        .order_by(ReclamoDB.fecha_deteccion.desc())
        .all()
    )
    return [_reclamo_a_out(r) for r in registros]


@app.get("/reclamos/{reclamo_id}", response_model=ReclamoOut)
def obtener_reclamo(
    reclamo_id: int,
    usuario: Usuario = Depends(get_usuario_actual),
    db: Session = Depends(get_db),
):
    registro = db.query(ReclamoDB).filter(
        ReclamoDB.id == reclamo_id, ReclamoDB.usuario_id == usuario.id
    ).first()
    if not registro:
        raise HTTPException(status_code=404, detail="Reclamo no encontrado")
    return _reclamo_a_out(registro)


@app.get("/reclamos/{reclamo_id}/pdf")
def descargar_reclamo_pdf(
    reclamo_id: int,
    usuario: Usuario = Depends(get_usuario_actual),
    db: Session = Depends(get_db),
):
    """Descarga el PDF de la carta de reclamo generada. Solo el dueño del reclamo puede pedirlo."""
    registro = db.query(ReclamoDB).filter(
        ReclamoDB.id == reclamo_id, ReclamoDB.usuario_id == usuario.id
    ).first()
    if not registro:
        raise HTTPException(status_code=404, detail="Reclamo no encontrado")
    if not registro.archivo_pdf_path or not Path(registro.archivo_pdf_path).exists():
        raise HTTPException(status_code=404, detail="El PDF de este reclamo todavía no está disponible")
    return FileResponse(
        registro.archivo_pdf_path,
        media_type="application/pdf",
        filename=f"{_numero_reclamo(registro)}.pdf",
    )


@app.patch("/reclamos/{reclamo_id}", response_model=ReclamoOut)
def actualizar_reclamo(
    reclamo_id: int,
    datos: ReclamoUpdate,
    usuario: Usuario = Depends(get_usuario_actual),
    db: Session = Depends(get_db),
):
    """
    Actualiza el estado de un reclamo propio (ej: cuando el usuario confirma
    que ya lo envio desde su correo, o cuando llega una respuesta).
    No permite tocar reclamos de otro usuario.
    """
    registro = db.query(ReclamoDB).filter(
        ReclamoDB.id == reclamo_id, ReclamoDB.usuario_id == usuario.id
    ).first()
    if not registro:
        raise HTTPException(status_code=404, detail="Reclamo no encontrado")

    if datos.estado is not None:
        if datos.estado not in ESTADOS_RECLAMO_VALIDOS:
            raise HTTPException(
                status_code=400,
                detail=f"Estado invalido. Debe ser uno de: {', '.join(sorted(ESTADOS_RECLAMO_VALIDOS))}",
            )
        registro.estado = datos.estado
        if datos.estado == "enviado" and registro.fecha_envio is None:
            registro.fecha_envio = datetime.utcnow()
        if datos.estado == "resuelto" and registro.fecha_resolucion is None:
            registro.fecha_resolucion = datetime.utcnow()

    if datos.documentacion_adjunta is not None:
        registro.documentacion_adjunta = datos.documentacion_adjunta

    db.commit()
    db.refresh(registro)
    return _reclamo_a_out(registro)


@app.get("/health")
def health():
    return {"status": "ok"}
