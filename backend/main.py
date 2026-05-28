# ==============================================================================
# PanaderIA App — Backend FastAPI
# Sistema Integral de Producción para Panaderías y Pastelerías
# Versión 1.0 — Mayo 2026
# ==============================================================================

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import hashlib
import jwt
import datetime
import os
import json

# ── Configuración ──────────────────────────────────────────────────────────────
SECRET_KEY = "panaderia-app-secret-2026"
ALGORITHM  = "HS256"
DB_PATH    = os.path.join(os.path.dirname(__file__), "panaderia.db")

app = FastAPI(title="PanaderIA App", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ── Base de Datos ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    stmts = [
        "CREATE TABLE IF NOT EXISTS sedes (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT NOT NULL UNIQUE, activo INTEGER DEFAULT 1)",
        "CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, rol TEXT NOT NULL DEFAULT 'sede', sede_id INTEGER, activo INTEGER DEFAULT 1)",
        "CREATE TABLE IF NOT EXISTS materias_primas (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT NOT NULL UNIQUE, unidad TEXT DEFAULT 'g', activo INTEGER DEFAULT 1)",
        "CREATE TABLE IF NOT EXISTS bodega_movimientos (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, tipo TEXT NOT NULL, materia_id INTEGER NOT NULL, cantidad REAL NOT NULL, valor_total REAL DEFAULT 0, responsable TEXT, sede_id INTEGER, orden_id TEXT, bodega_categoria TEXT DEFAULT 'MATERIAS_PRIMAS')",
        "CREATE TABLE IF NOT EXISTS recetas (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT NOT NULL UNIQUE, activo INTEGER DEFAULT 1)",
        "CREATE TABLE IF NOT EXISTS receta_ingredientes (id INTEGER PRIMARY KEY AUTOINCREMENT, receta_id INTEGER NOT NULL, materia_id INTEGER NOT NULL, gramos_base REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS ordenes_produccion (id TEXT PRIMARY KEY, fecha TEXT NOT NULL, receta_id INTEGER NOT NULL, estado TEXT DEFAULT 'pendiente', responsable TEXT, masa_total REAL DEFAULT 0, unidades_prog INTEGER DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS ordenes_sedes (id INTEGER PRIMARY KEY AUTOINCREMENT, orden_id TEXT NOT NULL, sede_id INTEGER, sede_nombre TEXT, peso_g REAL NOT NULL, cantidad INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS produccion_terminada (id INTEGER PRIMARY KEY AUTOINCREMENT, orden_id TEXT, fecha_cierre TEXT NOT NULL, receta_nombre TEXT, unidades_prog INTEGER, unidades_real INTEGER, masa_sobrante REAL DEFAULT 0, merma_g REAL DEFAULT 0, estado_balance TEXT)",
        "CREATE TABLE IF NOT EXISTS configuracion (clave TEXT PRIMARY KEY, valor TEXT)",
        # ── NUEVAS tablas para relleno y decoración ───────────────────────────
        """CREATE TABLE IF NOT EXISTS receta_rellenos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            receta_id   INTEGER NOT NULL,
            materia_id  INTEGER NOT NULL,
            gramos_por_unidad REAL NOT NULL,
            FOREIGN KEY (receta_id) REFERENCES recetas(id),
            FOREIGN KEY (materia_id) REFERENCES materias_primas(id)
        )""",
        """CREATE TABLE IF NOT EXISTS receta_decoraciones (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            receta_id   INTEGER NOT NULL,
            materia_id  INTEGER NOT NULL,
            gramos_por_unidad REAL NOT NULL,
            FOREIGN KEY (receta_id) REFERENCES recetas(id),
            FOREIGN KEY (materia_id) REFERENCES materias_primas(id)
        )""",
    ]
    for stmt in stmts:
        c.execute(stmt)

    # ── Datos iniciales ────────────────────────────────────────────────────────
    # Sedes por defecto
    sedes_default = ["SEDE PRINCIPAL", "PASO ANCHO", "ROOSEVELT", "JARDÍN", "CAÑAS", "CALLE 13"]
    for s in sedes_default:
        c.execute("INSERT OR IGNORE INTO sedes (nombre) VALUES (?)", (s,))

    # Usuario administrador por defecto
    pwd_hash = hashlib.sha256("admin123".encode()).hexdigest()
    c.execute("""
        INSERT OR IGNORE INTO usuarios (nombre, email, password, rol, sede_id)
        VALUES ('Administrador', 'admin@panaderia.com', ?, 'admin', 1)
    """, (pwd_hash,))

    # Configuración por defecto
    config_default = {
        "empresa_nombre": "Natas Panadería",
        "empresa_logo":   "",
        "color_primario": "#f59e0b",
        "color_secundario": "#1a1a2e",
        "moneda": "COP",
        "version": "1.0.0"
    }
    for k, v in config_default.items():
        c.execute("INSERT OR IGNORE INTO configuracion (clave, valor) VALUES (?, ?)", (k, v))

    # Migración no-destructiva: agregar bodega_categoria si no existe
    try:
        c.execute("ALTER TABLE bodega_movimientos ADD COLUMN bodega_categoria TEXT DEFAULT 'MATERIAS_PRIMAS'")
    except Exception:
        pass  # columna ya existe

    conn.commit()
    conn.close()

# ── Auth ───────────────────────────────────────────────────────────────────────
def crear_token(user_id: int, rol: str, sede_id: Optional[int] = None) -> str:
    payload = {
        "sub": user_id,
        "rol": rol,
        "sede_id": sede_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def solo_admin(token: dict = Depends(verificar_token)):
    if token.get("rol") != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores")
    return token

# ── Modelos Pydantic ───────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

class MovimientoRequest(BaseModel):
    fecha: str
    tipo: str          # ENTRADA | SALIDA
    materia_nombre: str
    cantidad: float
    valor_total: Optional[float] = 0
    responsable: Optional[str] = ""
    sede_nombre: Optional[str] = ""
    bodega_categoria: Optional[str] = "MATERIAS_PRIMAS"  # MATERIAS_PRIMAS | EMPAQUE | CAFETERIA | FRIOS | PUNTO_VENTA

class RecetaIngrediente(BaseModel):
    materia_nombre: str
    gramos_base: float

class RecetaRequest(BaseModel):
    nombre: str
    ingredientes: List[RecetaIngrediente]

class OrdenSedeDetalle(BaseModel):
    sede_nombre: str
    peso_g: float
    cantidad: int

class OrdenRequest(BaseModel):
    receta_nombre: str
    responsable: str
    sedes: List[OrdenSedeDetalle]

class CierreOrdenRequest(BaseModel):
    unidades_real: int
    masa_sobrante: float
    responsable: str

class ConfigRequest(BaseModel):
    clave: str
    valor: str

class RellenoDecoItem(BaseModel):
    materia_nombre: str
    gramos_por_unidad: float

class RellenoDecoRequest(BaseModel):
    items: List[RellenoDecoItem]

class SimularConExtrasRequest(BaseModel):
    peso_g: float
    cantidad: int
    rellenos: Optional[List[RellenoDecoItem]] = []
    decoraciones: Optional[List[RellenoDecoItem]] = []
    descontar_inventario: Optional[bool] = False
    responsable: Optional[str] = "sistema"

# ── Helpers ────────────────────────────────────────────────────────────────────
def get_o_crear_materia(conn, nombre: str) -> int:
    nombre = nombre.strip().lower()
    row = conn.execute("SELECT id FROM materias_primas WHERE nombre = ?", (nombre,)).fetchone()
    if row:
        return row["id"]
    conn.execute("INSERT INTO materias_primas (nombre) VALUES (?)", (nombre,))
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]

def calcular_kardex(conn, categoria: str = None) -> dict:
    """Retorna saldos y costo promedio ponderado por materia prima, opcionalmente filtrado por categoría."""
    if categoria:
        movs = conn.execute("""
            SELECT mp.nombre, bm.tipo, bm.cantidad, bm.valor_total
            FROM bodega_movimientos bm
            JOIN materias_primas mp ON mp.id = bm.materia_id
            WHERE bm.bodega_categoria = ?
            ORDER BY bm.id
        """, (categoria,)).fetchall()
    else:
        movs = conn.execute("""
            SELECT mp.nombre, bm.tipo, bm.cantidad, bm.valor_total
            FROM bodega_movimientos bm
            JOIN materias_primas mp ON mp.id = bm.materia_id
            ORDER BY bm.id
        """).fetchall()

    kardex = {}
    for m in movs:
        nombre = m["nombre"]
        if nombre not in kardex:
            kardex[nombre] = {"cantidad": 0.0, "valor_total": 0.0, "cpp": 0.0}
        k = kardex[nombre]
        if m["tipo"] == "ENTRADA":
            k["cantidad"]    += m["cantidad"]
            k["valor_total"] += m["valor_total"]
            if k["cantidad"] > 0:
                k["cpp"] = k["valor_total"] / k["cantidad"]
        elif m["tipo"] == "SALIDA":
            dinero_salida     = m["cantidad"] * k["cpp"]
            k["cantidad"]    -= m["cantidad"]
            k["valor_total"] -= dinero_salida
    return kardex

def import_uuid():
    import uuid
    return str(uuid.uuid4())[:5]

# ==============================================================================
# ENDPOINTS
# ==============================================================================

# ── Auth ───────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
    user = db.execute(
        "SELECT * FROM usuarios WHERE email = ? AND password = ? AND activo = 1",
        (req.email, pwd_hash)
    ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    token = crear_token(user["id"], user["rol"], user["sede_id"])
    sede_nombre = ""
    if user["sede_id"]:
        s = db.execute("SELECT nombre FROM sedes WHERE id = ?", (user["sede_id"],)).fetchone()
        if s:
            sede_nombre = s["nombre"]
    return {
        "token": token,
        "usuario": {
            "id": user["id"],
            "nombre": user["nombre"],
            "rol": user["rol"],
            "sede_nombre": sede_nombre
        }
    }

# ── Sedes ──────────────────────────────────────────────────────────────────────
@app.get("/api/sedes")
def listar_sedes(db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    rows = db.execute("SELECT * FROM sedes WHERE activo = 1 ORDER BY id").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/sedes")
def crear_sede(body: dict, db: sqlite3.Connection = Depends(get_db), token=Depends(solo_admin)):
    nombre = body.get("nombre", "").strip().upper()
    if not nombre:
        raise HTTPException(400, "Nombre requerido")
    try:
        db.execute("INSERT INTO sedes (nombre) VALUES (?)", (nombre,))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "La sede ya existe")
    return {"ok": True, "nombre": nombre}

# ── Bodega ─────────────────────────────────────────────────────────────────────
@app.get("/api/bodega/saldos")
def saldos_bodega(
    categoria: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    kardex = calcular_kardex(db, categoria)
    resultado = []
    for nombre, k in kardex.items():
        resultado.append({
            "materia": nombre,
            "saldo_g": round(k["cantidad"], 2),
            "costo_promedio": round(k["cpp"], 4),
            "valor_inventario": round(k["cantidad"] * k["cpp"], 2)
        })
    resultado.sort(key=lambda x: x["materia"])
    return resultado

@app.get("/api/bodega/movimientos")
def movimientos_bodega(
    fecha: Optional[str] = None,
    sede: Optional[str] = None,
    categoria: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    query = """
        SELECT bm.id, bm.fecha, bm.tipo, mp.nombre as materia, bm.cantidad,
               bm.valor_total, bm.responsable, s.nombre as sede, bm.bodega_categoria
        FROM bodega_movimientos bm
        JOIN materias_primas mp ON mp.id = bm.materia_id
        LEFT JOIN sedes s ON s.id = bm.sede_id
        WHERE 1=1
    """
    params = []
    if fecha:
        query += " AND bm.fecha = ?"
        params.append(fecha)
    if sede:
        query += " AND s.nombre = ?"
        params.append(sede)
    if categoria:
        query += " AND bm.bodega_categoria = ?"
        params.append(categoria)
    query += " ORDER BY bm.id DESC LIMIT 500"
    rows = db.execute(query, params).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/bodega/movimiento")
def registrar_movimiento(req: MovimientoRequest, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    materia_id = get_o_crear_materia(db, req.materia_nombre)
    sede_id = None
    if req.sede_nombre:
        s = db.execute("SELECT id FROM sedes WHERE nombre = ?", (req.sede_nombre.strip().upper(),)).fetchone()
        if s:
            sede_id = s["id"]
    categoria = (req.bodega_categoria or "MATERIAS_PRIMAS").upper()
    db.execute("""
        INSERT INTO bodega_movimientos (fecha, tipo, materia_id, cantidad, valor_total, responsable, sede_id, bodega_categoria)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (req.fecha, req.tipo.upper(), materia_id, req.cantidad, req.valor_total or 0, req.responsable, sede_id, categoria))
    db.commit()
    return {"ok": True}

# ── Recetas ────────────────────────────────────────────────────────────────────
@app.get("/api/recetas")
def listar_recetas(db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    recetas = db.execute("SELECT * FROM recetas WHERE activo = 1 ORDER BY nombre").fetchall()
    result = []
    for r in recetas:
        ings = db.execute("""
            SELECT mp.nombre, ri.gramos_base
            FROM receta_ingredientes ri
            JOIN materias_primas mp ON mp.id = ri.materia_id
            WHERE ri.receta_id = ?
        """, (r["id"],)).fetchall()
        rellenos = db.execute("""
            SELECT rr.id, mp.nombre, rr.gramos_por_unidad
            FROM receta_rellenos rr
            JOIN materias_primas mp ON mp.id = rr.materia_id
            WHERE rr.receta_id = ?
        """, (r["id"],)).fetchall()
        decoraciones = db.execute("""
            SELECT rd.id, mp.nombre, rd.gramos_por_unidad
            FROM receta_decoraciones rd
            JOIN materias_primas mp ON mp.id = rd.materia_id
            WHERE rd.receta_id = ?
        """, (r["id"],)).fetchall()
        result.append({
            **dict(r),
            "ingredientes": [dict(i) for i in ings],
            "peso_total_g": sum(i["gramos_base"] for i in ings),
            "rellenos": [dict(x) for x in rellenos],
            "decoraciones": [dict(x) for x in decoraciones],
        })
    return result

@app.post("/api/recetas")
def crear_receta(req: RecetaRequest, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    nombre = req.nombre.strip().upper()
    try:
        db.execute("INSERT INTO recetas (nombre) VALUES (?)", (nombre,))
        receta_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        raise HTTPException(400, f"La receta '{nombre}' ya existe")
    for ing in req.ingredientes:
        mat_id = get_o_crear_materia(db, ing.materia_nombre)
        db.execute(
            "INSERT INTO receta_ingredientes (receta_id, materia_id, gramos_base) VALUES (?,?,?)",
            (receta_id, mat_id, ing.gramos_base)
        )
    db.commit()
    return {"ok": True, "receta_id": receta_id}

# ── Rellenos por Receta ────────────────────────────────────────────────────────
@app.get("/api/recetas/{nombre}/rellenos")
def listar_rellenos(nombre: str, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    receta = db.execute("SELECT id FROM recetas WHERE nombre = ?", (nombre.upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")
    rows = db.execute("""
        SELECT rr.id, mp.nombre as materia, rr.gramos_por_unidad
        FROM receta_rellenos rr
        JOIN materias_primas mp ON mp.id = rr.materia_id
        WHERE rr.receta_id = ?
        ORDER BY rr.id
    """, (receta["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/recetas/{nombre}/rellenos")
def agregar_rellenos(nombre: str, req: RellenoDecoRequest, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    receta = db.execute("SELECT id FROM recetas WHERE nombre = ?", (nombre.upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")
    for item in req.items:
        mat_id = get_o_crear_materia(db, item.materia_nombre)
        db.execute(
            "INSERT INTO receta_rellenos (receta_id, materia_id, gramos_por_unidad) VALUES (?,?,?)",
            (receta["id"], mat_id, item.gramos_por_unidad)
        )
    db.commit()
    return {"ok": True, "insertados": len(req.items)}

@app.delete("/api/recetas/{nombre}/rellenos/{relleno_id}")
def eliminar_relleno(nombre: str, relleno_id: int, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    receta = db.execute("SELECT id FROM recetas WHERE nombre = ?", (nombre.upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")
    db.execute("DELETE FROM receta_rellenos WHERE id = ? AND receta_id = ?", (relleno_id, receta["id"]))
    db.commit()
    return {"ok": True}

# ── Decoraciones por Receta ────────────────────────────────────────────────────
@app.get("/api/recetas/{nombre}/decoraciones")
def listar_decoraciones(nombre: str, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    receta = db.execute("SELECT id FROM recetas WHERE nombre = ?", (nombre.upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")
    rows = db.execute("""
        SELECT rd.id, mp.nombre as materia, rd.gramos_por_unidad
        FROM receta_decoraciones rd
        JOIN materias_primas mp ON mp.id = rd.materia_id
        WHERE rd.receta_id = ?
        ORDER BY rd.id
    """, (receta["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/recetas/{nombre}/decoraciones")
def agregar_decoraciones(nombre: str, req: RellenoDecoRequest, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    receta = db.execute("SELECT id FROM recetas WHERE nombre = ?", (nombre.upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")
    for item in req.items:
        mat_id = get_o_crear_materia(db, item.materia_nombre)
        db.execute(
            "INSERT INTO receta_decoraciones (receta_id, materia_id, gramos_por_unidad) VALUES (?,?,?)",
            (receta["id"], mat_id, item.gramos_por_unidad)
        )
    db.commit()
    return {"ok": True, "insertados": len(req.items)}

@app.delete("/api/recetas/{nombre}/decoraciones/{deco_id}")
def eliminar_decoracion(nombre: str, deco_id: int, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    receta = db.execute("SELECT id FROM recetas WHERE nombre = ?", (nombre.upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")
    db.execute("DELETE FROM receta_decoraciones WHERE id = ? AND receta_id = ?", (deco_id, receta["id"]))
    db.commit()
    return {"ok": True}

# ── Simulador extendido con Relleno + Decoración ───────────────────────────────
@app.post("/api/recetas/{nombre}/simular-completo")
def simular_completo(
    nombre: str,
    req: SimularConExtrasRequest,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    nombre = nombre.upper()
    receta = db.execute("SELECT * FROM recetas WHERE nombre = ?", (nombre,)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")

    ings = db.execute("""
        SELECT mp.nombre, ri.gramos_base
        FROM receta_ingredientes ri
        JOIN materias_primas mp ON mp.id = ri.materia_id
        WHERE ri.receta_id = ?
    """, (receta["id"],)).fetchall()

    peso_total_receta = sum(i["gramos_base"] for i in ings)
    masa_neta = req.peso_g * req.cantidad
    masa_con_averia = masa_neta * 1.05

    kardex = calcular_kardex(db)
    viable = True
    detalle_masa = []

    for ing in ings:
        pct = ing["gramos_base"] / peso_total_receta
        necesario = masa_con_averia * pct
        saldo = kardex.get(ing["nombre"], {}).get("cantidad", 0)
        ok = saldo >= necesario or ing["nombre"] == "agua"
        if not ok:
            viable = False
        costo_u = kardex.get(ing["nombre"], {}).get("cpp", 0.0)
        detalle_masa.append({
            "materia": ing["nombre"],
            "necesario_g": round(necesario, 1),
            "saldo_g": round(saldo, 1),
            "ok": ok,
            "faltante_g": round(max(0, necesario - saldo), 1),
            "costo_total": round(necesario * costo_u, 0)
        })

    costo_masa_total = sum(d["costo_total"] for d in detalle_masa)
    costo_masa_unidad = costo_masa_total / req.cantidad if req.cantidad > 0 else 0

    # Usar rellenos del request; si vacío, cargar predefinidos de la receta
    rellenos_usar = req.rellenos or []
    if not rellenos_usar:
        rows = db.execute("""
            SELECT mp.nombre, rr.gramos_por_unidad
            FROM receta_rellenos rr JOIN materias_primas mp ON mp.id = rr.materia_id
            WHERE rr.receta_id = ?
        """, (receta["id"],)).fetchall()
        rellenos_usar = [{"materia_nombre": r["nombre"], "gramos_por_unidad": r["gramos_por_unidad"]} for r in rows]

    decoraciones_usar = req.decoraciones or []
    if not decoraciones_usar:
        rows = db.execute("""
            SELECT mp.nombre, rd.gramos_por_unidad
            FROM receta_decoraciones rd JOIN materias_primas mp ON mp.id = rd.materia_id
            WHERE rd.receta_id = ?
        """, (receta["id"],)).fetchall()
        decoraciones_usar = [{"materia_nombre": r["nombre"], "gramos_por_unidad": r["gramos_por_unidad"]} for r in rows]

    def verificar_extras(lista_extras):
        resultado = []
        for item in lista_extras:
            mat = item["materia_nombre"] if isinstance(item, dict) else item.materia_nombre
            gxu = item["gramos_por_unidad"] if isinstance(item, dict) else item.gramos_por_unidad
            total_g = gxu * req.cantidad
            saldo = kardex.get(mat.lower(), {}).get("cantidad", 0)
            cpp_item = kardex.get(mat.lower(), {}).get("cpp", 0.0)
            ok = saldo >= total_g
            if not ok:
                nonlocal viable
                viable = False
            resultado.append({
                "materia": mat,
                "gramos_por_unidad": gxu,
                "total_g": round(total_g, 1),
                "saldo_g": round(saldo, 1),
                "ok": ok,
                "faltante_g": round(max(0, total_g - saldo), 1),
                "costo_total": round(total_g * cpp_item, 0)
            })
        return resultado

    detalle_relleno = verificar_extras(rellenos_usar)
    detalle_deco = verificar_extras(decoraciones_usar)

    costo_relleno_unidad = sum(d["costo_total"] for d in detalle_relleno) / req.cantidad if req.cantidad > 0 else 0
    costo_deco_unidad = sum(d["costo_total"] for d in detalle_deco) / req.cantidad if req.cantidad > 0 else 0
    costo_total_unidad = costo_masa_unidad + costo_relleno_unidad + costo_deco_unidad

    # Descontar inventario si se solicitó
    descuentos_aplicados = []
    if req.descontar_inventario and (detalle_relleno or detalle_deco):
        fecha_hoy = datetime.datetime.now().strftime("%d/%m/%Y")
        for item in detalle_relleno + detalle_deco:
            mat_id = get_o_crear_materia(db, item["materia"])
            db.execute("""
                INSERT INTO bodega_movimientos (fecha, tipo, materia_id, cantidad, valor_total, responsable)
                VALUES (?, 'SALIDA', ?, ?, 0, ?)
            """, (fecha_hoy, mat_id, item["total_g"], req.responsable))
            descuentos_aplicados.append({"materia": item["materia"], "descontado_g": item["total_g"]})
        db.commit()

    return {
        "receta": nombre,
        "unidades": req.cantidad,
        "peso_g": req.peso_g,
        "masa_con_averia_g": round(masa_con_averia, 1),
        "viable": viable,
        "masa": {
            "ingredientes": detalle_masa,
            "costo_total": round(costo_masa_total, 0),
            "costo_por_unidad": round(costo_masa_unidad, 0)
        },
        "relleno": {
            "ingredientes": detalle_relleno,
            "costo_total": round(sum(d["costo_total"] for d in detalle_relleno), 0),
            "costo_por_unidad": round(costo_relleno_unidad, 0)
        },
        "decoracion": {
            "ingredientes": detalle_deco,
            "costo_total": round(sum(d["costo_total"] for d in detalle_deco), 0),
            "costo_por_unidad": round(costo_deco_unidad, 0)
        },
        "costo_total_por_unidad": round(costo_total_unidad, 0),
        "descuentos_aplicados": descuentos_aplicados
    }

@app.get("/api/recetas/{nombre}/simular")
def simular_pedido(
    nombre: str,
    peso_g: float = 500,
    cantidad: int = 10,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    nombre = nombre.upper()
    receta = db.execute("SELECT * FROM recetas WHERE nombre = ?", (nombre,)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{nombre}' no encontrada")

    ings = db.execute("""
        SELECT mp.nombre, ri.gramos_base
        FROM receta_ingredientes ri
        JOIN materias_primas mp ON mp.id = ri.materia_id
        WHERE ri.receta_id = ?
    """, (receta["id"],)).fetchall()

    peso_total_receta = sum(i["gramos_base"] for i in ings)
    masa_neta = peso_g * cantidad
    masa_total = masa_neta * 1.05

    kardex = calcular_kardex(db)
    resultado = []
    viable = True

    for ing in ings:
        pct = ing["gramos_base"] / peso_total_receta
        necesario = masa_total * pct
        saldo = kardex.get(ing["nombre"], {}).get("cantidad", 0)
        ok = saldo >= necesario or ing["nombre"] == "agua"
        if not ok:
            viable = False
        resultado.append({
            "materia": ing["nombre"],
            "necesario_g": round(necesario, 1),
            "saldo_bodega_g": round(saldo, 1),
            "ok": ok,
            "faltante_g": round(max(0, necesario - saldo), 1)
        })

    return {
        "receta": nombre,
        "unidades": cantidad,
        "peso_g": peso_g,
        "masa_neta_g": masa_neta,
        "masa_con_averia_g": masa_total,
        "viable": viable,
        "ingredientes": resultado
    }

# ── Órdenes de Producción ──────────────────────────────────────────────────────
@app.post("/api/ordenes")
def crear_orden(req: OrdenRequest, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    import uuid
    receta = db.execute("SELECT * FROM recetas WHERE nombre = ?", (req.receta_nombre.strip().upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, f"Receta '{req.receta_nombre}' no encontrada")

    ings = db.execute("""
        SELECT mp.nombre, ri.gramos_base
        FROM receta_ingredientes ri
        JOIN materias_primas mp ON mp.id = ri.materia_id
        WHERE ri.receta_id = ?
    """, (receta["id"],)).fetchall()

    peso_total_receta = sum(i["gramos_base"] for i in ings)

    # Consolidar masa total
    masa_total_neta = sum(s.peso_g * s.cantidad for s in req.sedes)
    masa_con_averia = masa_total_neta * 1.05
    total_unidades  = sum(s.cantidad for s in req.sedes)

    orden_id = str(uuid.uuid4())[:5].upper()
    fecha_hoy = datetime.datetime.now().strftime("%d/%m/%Y")

    db.execute("""
        INSERT INTO ordenes_produccion (id, fecha, receta_id, estado, responsable, masa_total, unidades_prog)
        VALUES (?, ?, ?, 'pendiente', ?, ?, ?)
    """, (orden_id, fecha_hoy, receta["id"], req.responsable, round(masa_con_averia, 1), total_unidades))

    for s in req.sedes:
        sede_id = None
        sede_row = db.execute("SELECT id FROM sedes WHERE nombre = ?", (s.sede_nombre.strip().upper(),)).fetchone()
        if sede_row:
            sede_id = sede_row["id"]
        db.execute("""
            INSERT INTO ordenes_sedes (orden_id, sede_id, sede_nombre, peso_g, cantidad)
            VALUES (?, ?, ?, ?, ?)
        """, (orden_id, sede_id, s.sede_nombre.strip().upper(), s.peso_g, s.cantidad))

    # Descontar de bodega
    kardex = calcular_kardex(db)
    for ing in ings:
        pct = ing["gramos_base"] / peso_total_receta
        gramos_descontar = masa_con_averia * pct
        mat_id = get_o_crear_materia(db, ing["nombre"])
        db.execute("""
            INSERT INTO bodega_movimientos (fecha, tipo, materia_id, cantidad, valor_total, responsable, orden_id)
            VALUES (?, 'SALIDA', ?, ?, 0, ?, ?)
        """, (fecha_hoy, mat_id, round(gramos_descontar, 2), req.responsable, orden_id))

    db.commit()
    return {"ok": True, "orden_id": orden_id, "masa_total_g": round(masa_con_averia, 1), "unidades": total_unidades}

@app.get("/api/ordenes")
def listar_ordenes(estado: Optional[str] = None, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    q = """
        SELECT op.id, op.fecha, r.nombre as receta, op.estado,
               op.responsable, op.masa_total, op.unidades_prog
        FROM ordenes_produccion op
        JOIN recetas r ON r.id = op.receta_id
        WHERE 1=1
    """
    params = []
    if estado:
        q += " AND op.estado = ?"
        params.append(estado)
    q += " ORDER BY op.fecha DESC LIMIT 100"
    rows = db.execute(q, params).fetchall()
    result = []
    for r in rows:
        sedes = db.execute(
            "SELECT sede_nombre, peso_g, cantidad FROM ordenes_sedes WHERE orden_id = ?",
            (r["id"],)
        ).fetchall()
        result.append({**dict(r), "sedes": [dict(s) for s in sedes]})
    return result

@app.put("/api/ordenes/{orden_id}/cerrar")
def cerrar_orden(orden_id: str, req: CierreOrdenRequest, db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    orden = db.execute("SELECT * FROM ordenes_produccion WHERE id = ?", (orden_id,)).fetchone()
    if not orden:
        raise HTTPException(404, "Orden no encontrada")
    if orden["estado"] == "cerrada":
        raise HTTPException(400, "La orden ya está cerrada")

    receta_row = db.execute("SELECT nombre FROM recetas WHERE id = ?", (orden["receta_id"],)).fetchone()
    receta_nombre = receta_row["nombre"] if receta_row else ""

    masa_real_panes = req.unidades_real * (orden["masa_total"] / orden["unidades_prog"]) if orden["unidades_prog"] > 0 else 0
    merma = orden["masa_total"] - (masa_real_panes + req.masa_sobrante)
    estado_balance = "PROCESO CUADRADO"
    if merma > 0:
        estado_balance = f"MERMA INVISIBLE: {merma:.1f}g"
    elif merma < 0:
        estado_balance = f"EXCESO: {abs(merma):.1f}g"

    fecha_cierre = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    db.execute("""
        INSERT INTO produccion_terminada
        (orden_id, fecha_cierre, receta_nombre, unidades_prog, unidades_real, masa_sobrante, merma_g, estado_balance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (orden_id, fecha_cierre, receta_nombre, orden["unidades_prog"], req.unidades_real,
          req.masa_sobrante, round(merma, 1), estado_balance))

    db.execute("UPDATE ordenes_produccion SET estado = 'cerrada' WHERE id = ?", (orden_id,))
    db.commit()
    return {"ok": True, "merma_g": round(merma, 1), "estado_balance": estado_balance}

# ── Reportes ───────────────────────────────────────────────────────────────────
@app.get("/api/reportes/productos-terminados")
def tabla_productos_terminados(
    peso_g: float = 200,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    """
    Tabla de productos terminados: por cada receta muestra masa, relleno y decoración
    con sus costos, escalado al peso comercial de presentación indicado.
    """
    kardex = calcular_kardex(db)

    recetas = db.execute("SELECT * FROM recetas WHERE activo = 1 ORDER BY nombre").fetchall()
    resultado = []

    for receta in recetas:
        # ── Masa base ──────────────────────────────────────────────────────────
        ings = db.execute("""
            SELECT mp.nombre, ri.gramos_base
            FROM receta_ingredientes ri
            JOIN materias_primas mp ON mp.id = ri.materia_id
            WHERE ri.receta_id = ?
        """, (receta["id"],)).fetchall()

        peso_lote = sum(i["gramos_base"] for i in ings)
        if peso_lote == 0:
            continue

        costo_lote = sum(
            i["gramos_base"] * kardex.get(i["nombre"], {}).get("cpp", 0.0)
            for i in ings
        )
        cpp_masa = costo_lote / peso_lote
        costo_masa_presentacion = round(cpp_masa * peso_g, 0)

        # ── Rellenos ───────────────────────────────────────────────────────────
        rellenos = db.execute("""
            SELECT mp.nombre, rr.gramos_por_unidad
            FROM receta_rellenos rr
            JOIN materias_primas mp ON mp.id = rr.materia_id
            WHERE rr.receta_id = ?
            ORDER BY rr.id
        """, (receta["id"],)).fetchall()

        rellenos_detalle = []
        costo_relleno_total = 0.0
        for r in rellenos:
            cpp_r = kardex.get(r["nombre"], {}).get("cpp", 0.0)
            costo_r = round(r["gramos_por_unidad"] * cpp_r, 0)
            costo_relleno_total += costo_r
            rellenos_detalle.append({
                "ingrediente": r["nombre"],
                "gramos": r["gramos_por_unidad"],
                "costo": costo_r
            })

        # ── Decoraciones ───────────────────────────────────────────────────────
        decoraciones = db.execute("""
            SELECT mp.nombre, rd.gramos_por_unidad
            FROM receta_decoraciones rd
            JOIN materias_primas mp ON mp.id = rd.materia_id
            WHERE rd.receta_id = ?
            ORDER BY rd.id
        """, (receta["id"],)).fetchall()

        decos_detalle = []
        costo_deco_total = 0.0
        for d in decoraciones:
            cpp_d = kardex.get(d["nombre"], {}).get("cpp", 0.0)
            costo_d = round(d["gramos_por_unidad"] * cpp_d, 0)
            costo_deco_total += costo_d
            decos_detalle.append({
                "ingrediente": d["nombre"],
                "gramos": d["gramos_por_unidad"],
                "costo": costo_d
            })

        costo_total = round(costo_masa_presentacion + costo_relleno_total + costo_deco_total, 0)

        resultado.append({
            "receta": receta["nombre"],
            "peso_masa_g": peso_g,
            "costo_masa": costo_masa_presentacion,
            "rellenos": rellenos_detalle,
            "costo_relleno_total": round(costo_relleno_total, 0),
            "decoraciones": decos_detalle,
            "costo_deco_total": round(costo_deco_total, 0),
            "costo_total_unidad": costo_total
        })

    return resultado

@app.get("/api/reportes/produccion")
def reporte_produccion(
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    q = "SELECT * FROM produccion_terminada WHERE 1=1"
    params = []
    if fecha_desde:
        q += " AND fecha_cierre >= ?"
        params.append(fecha_desde)
    if fecha_hasta:
        q += " AND fecha_cierre <= ?"
        params.append(fecha_hasta + " 23:59")
    q += " ORDER BY fecha_cierre DESC"
    rows = db.execute(q, params).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/reportes/consumo-estimado")
def consumo_estimado(
    receta_nombre: str,
    dias: int = 7,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    """Estima el consumo de materias primas basado en el promedio histórico de producción."""
    receta = db.execute("SELECT * FROM recetas WHERE nombre = ?", (receta_nombre.strip().upper(),)).fetchone()
    if not receta:
        raise HTTPException(404, "Receta no encontrada")

    # Promedio de unidades producidas por día en últimas 30 producciones
    hist = db.execute("""
        SELECT AVG(unidades_real) as avg_real
        FROM produccion_terminada
        WHERE receta_nombre = ?
        ORDER BY fecha_cierre DESC
        LIMIT 30
    """, (receta_nombre.strip().upper(),)).fetchone()

    promedio_diario = hist["avg_real"] or 100  # default 100 si no hay historial

    ings = db.execute("""
        SELECT mp.nombre, ri.gramos_base
        FROM receta_ingredientes ri
        JOIN materias_primas mp ON mp.id = ri.materia_id
        WHERE ri.receta_id = ?
    """, (receta["id"],)).fetchall()

    peso_total_receta = sum(i["gramos_base"] for i in ings)
    kardex = calcular_kardex(db)

    resultado = []
    for ing in ings:
        pct = ing["gramos_base"] / peso_total_receta
        masa_diaria_estimada = promedio_diario * (peso_total_receta / len(ings))  # aprox
        consumo_periodo = masa_diaria_estimada * pct * dias
        saldo = kardex.get(ing["nombre"], {}).get("cantidad", 0)
        dias_restantes = (saldo / (consumo_periodo / dias)) if consumo_periodo > 0 else 999
        resultado.append({
            "materia": ing["nombre"],
            "consumo_estimado_g": round(consumo_periodo, 1),
            "saldo_actual_g": round(saldo, 1),
            "dias_restantes": round(dias_restantes, 1),
            "alerta": dias_restantes < 3
        })

    return {
        "receta": receta_nombre.upper(),
        "dias_proyectados": dias,
        "promedio_diario_unidades": round(promedio_diario, 0),
        "materias": resultado
    }

@app.get("/api/reportes/despachos-sede")
def despachos_por_sede(
    fecha: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    q = """
        SELECT os.sede_nombre, r.nombre as receta,
               SUM(os.cantidad) as total_unidades,
               SUM(os.peso_g * os.cantidad) as masa_total_g,
               op.fecha
        FROM ordenes_sedes os
        JOIN ordenes_produccion op ON op.id = os.orden_id
        JOIN recetas r ON r.id = op.receta_id
        WHERE 1=1
    """
    params = []
    if fecha:
        q += " AND op.fecha = ?"
        params.append(fecha)
    q += " GROUP BY os.sede_nombre, r.nombre, op.fecha ORDER BY op.fecha DESC, os.sede_nombre"
    rows = db.execute(q, params).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/reportes/dashboard-kpis")
def dashboard_kpis(db: sqlite3.Connection = Depends(get_db), token=Depends(verificar_token)):
    hoy = datetime.datetime.now().strftime("%d/%m/%Y")

    # KPIs principales
    ordenes_pendientes = db.execute(
        "SELECT COUNT(*) as n FROM ordenes_produccion WHERE estado = 'pendiente'"
    ).fetchone()["n"]

    produccion_hoy = db.execute(
        "SELECT SUM(unidades_real) as n FROM produccion_terminada WHERE fecha_cierre LIKE ?",
        (datetime.datetime.now().strftime("%Y-%m-%d") + "%",)
    ).fetchone()["n"] or 0

    # hoy en formato dd/mm/yyyy para coincidir con los CSV migrados
    entradas_hoy = db.execute(
        "SELECT SUM(cantidad) as n FROM bodega_movimientos WHERE tipo='ENTRADA' AND fecha=?", (hoy,)
    ).fetchone()["n"] or 0
    # También buscar en formato yyyy-mm-dd para movimientos nuevos ingresados desde la app
    hoy_iso = datetime.datetime.now().strftime("%Y-%m-%d")
    entradas_hoy_iso = db.execute(
        "SELECT SUM(cantidad) as n FROM bodega_movimientos WHERE tipo='ENTRADA' AND fecha=?", (hoy_iso,)
    ).fetchone()["n"] or 0
    entradas_hoy = entradas_hoy + entradas_hoy_iso

    kardex = calcular_kardex(db)
    valor_inventario = sum(k["cantidad"] * k["cpp"] for k in kardex.values())
    materias_con_saldo = sum(1 for k in kardex.values() if k["cantidad"] > 0)

    # Producción últimos 7 días (fecha_cierre en formato "yyyy-mm-dd HH:MM")
    prod_semana = db.execute("""
        SELECT DATE(fecha_cierre) as dia, SUM(unidades_real) as total
        FROM produccion_terminada
        GROUP BY DATE(fecha_cierre)
        ORDER BY dia DESC
        LIMIT 7
    """).fetchall()
    prod_semana = list(reversed([dict(r) for r in prod_semana]))

    # Top materias por consumo (todos los registros de tipo SALIDA)
    # Nota: fechas migradas de CSV están en formato dd/mm/yyyy — no filtrar por date() de SQLite
    top_consumo = db.execute("""
        SELECT mp.nombre, SUM(bm.cantidad) as total_g
        FROM bodega_movimientos bm
        JOIN materias_primas mp ON mp.id = bm.materia_id
        WHERE bm.tipo = 'SALIDA'
        GROUP BY mp.nombre
        ORDER BY total_g DESC
        LIMIT 6
    """).fetchall()

    # Despachos por sede hoy
    despachos_hoy = db.execute("""
        SELECT os.sede_nombre, SUM(os.cantidad) as unidades
        FROM ordenes_sedes os
        JOIN ordenes_produccion op ON op.id = os.orden_id
        WHERE op.fecha = ?
        GROUP BY os.sede_nombre
        ORDER BY unidades DESC
    """, (hoy,)).fetchall()

    return {
        "ordenes_pendientes": ordenes_pendientes,
        "produccion_hoy": int(produccion_hoy),
        "entradas_hoy_g": int(entradas_hoy),
        "valor_inventario": round(valor_inventario, 0),
        "materias_activas": materias_con_saldo,
        "saldos_bodega": [
            {"materia": k, "saldo_g": round(v["cantidad"], 0)}
            for k, v in kardex.items() if v["cantidad"] > 0
        ][:8],
        "produccion_semana": [dict(r) for r in prod_semana],
        "top_consumo": [dict(r) for r in top_consumo],
        "despachos_hoy": [dict(r) for r in despachos_hoy]
    }

# ── Pareto 80/20 ──────────────────────────────────────────────────────────────
@app.get("/api/reportes/pareto")
def reporte_pareto(
    tipo: Optional[str] = "consumo",  # consumo | inventario | merma
    categoria: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db),
    token=Depends(verificar_token)
):
    """
    Análisis Pareto 80/20.
    tipo=consumo    → materias más consumidas (SALIDA)
    tipo=inventario → materias con mayor valor en bodega
    tipo=merma      → recetas con mayor merma histórica
    """
    if tipo == "consumo":
        q = """
            SELECT mp.nombre as item, SUM(bm.cantidad) as valor
            FROM bodega_movimientos bm
            JOIN materias_primas mp ON mp.id = bm.materia_id
            WHERE bm.tipo = 'SALIDA'
        """
        params = []
        if categoria:
            q += " AND bm.bodega_categoria = ?"
            params.append(categoria)
        q += " GROUP BY mp.nombre ORDER BY valor DESC"
        rows = db.execute(q, params).fetchall()
        unidad = "g"

    elif tipo == "inventario":
        kardex = calcular_kardex(db, categoria)
        rows_data = [
            {"item": k, "valor": round(v["cantidad"] * v["cpp"], 0)}
            for k, v in kardex.items() if v["cantidad"] > 0
        ]
        rows_data.sort(key=lambda x: x["valor"], reverse=True)
        rows = rows_data
        unidad = "COP"

    elif tipo == "merma":
        rows = db.execute("""
            SELECT receta_nombre as item, SUM(merma_g) as valor
            FROM produccion_terminada
            WHERE merma_g > 0
            GROUP BY receta_nombre
            ORDER BY valor DESC
        """).fetchall()
        unidad = "g"
    else:
        raise HTTPException(400, "tipo debe ser: consumo, inventario o merma")

    # Calcular acumulado y % para la curva Pareto
    items = [dict(r) for r in rows] if not isinstance(rows[0] if rows else {}, dict) else rows
    total = sum(i["valor"] for i in items) if items else 1
    acumulado = 0
    resultado = []
    for i in items:
        acumulado += i["valor"]
        pct = round(i["valor"] / total * 100, 2)
        pct_acum = round(acumulado / total * 100, 2)
        resultado.append({
            "item": i["item"],
            "valor": round(i["valor"], 1),
            "porcentaje": pct,
            "porcentaje_acumulado": pct