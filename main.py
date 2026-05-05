import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
import datetime

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY", "cheie-dev-de-inlocuit")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
TOKEN_EXPIRE_MINUTES = int(os.environ.get("EXPIRARE_TOKEN_MINUTE", "30"))
DATABASE_PATH = os.environ.get("DATABASE_PATH", "sarcini.db")

DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="autentificare")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500", "null"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UtilizatorDB(Base):
    __tablename__ = "utilizatori"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    parola_hash = Column(String)

class SarcinaDB(Base):
    __tablename__ = "sarcini"
    id = Column(Integer, primary_key=True, index=True)
    titlu = Column(String)
    descriere = Column(String, default="")
    finalizata = Column(Boolean, default=False)
    utilizator_id = Column(Integer, ForeignKey("utilizatori.id"))

Base.metadata.create_all(bind=engine)

class InregistrareSchema(BaseModel):
    email: str
    parola: str

class SarcinaCreare(BaseModel):
    titlu: str
    descriere: Optional[str] = ""

class SarcinaActualizare(BaseModel):
    titlu: str
    descriere: Optional[str] = ""

class SarcinaRaspuns(BaseModel):
    id: int
    titlu: str
    descriere: str
    finalizata: bool
    class Config:
        from_attributes = True

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_parola(parola: str):
    return pwd_context.hash(parola)

def verifica_parola(parola: str, hash: str):
    return pwd_context.verify(parola, hash)

def creeaza_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_utilizator_curent(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Token invalid")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalid")
    utilizator = db.query(UtilizatorDB).filter(UtilizatorDB.email == email).first()
    if utilizator is None:
        raise HTTPException(status_code=401, detail="Utilizator negasit")
    return utilizator

@app.post("/inregistrare", status_code=201)
def inregistrare(date: InregistrareSchema, db: Session = Depends(get_db)):
    existent = db.query(UtilizatorDB).filter(UtilizatorDB.email == date.email).first()
    if existent:
        raise HTTPException(status_code=400, detail="Email deja inregistrat")
    utilizator = UtilizatorDB(email=date.email, parola_hash=hash_parola(date.parola))
    db.add(utilizator)
    db.commit()
    return {"mesaj": "Cont creat cu succes"}

@app.post("/autentificare")
def autentificare(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    utilizator = db.query(UtilizatorDB).filter(UtilizatorDB.email == form.username).first()
    if not utilizator or not verifica_parola(form.password, utilizator.parola_hash):
        raise HTTPException(status_code=401, detail="Email sau parola incorecte")
    token = creeaza_token({"sub": utilizator.email})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/sarcini", response_model=list[SarcinaRaspuns])
def get_sarcini(doar_nefinalizate: bool = False, utilizator=Depends(get_utilizator_curent), db: Session = Depends(get_db)):
    query = db.query(SarcinaDB).filter(SarcinaDB.utilizator_id == utilizator.id)
    if doar_nefinalizate:
        query = query.filter(SarcinaDB.finalizata == False)
    return query.all()

@app.post("/sarcini", response_model=SarcinaRaspuns, status_code=201)
def creeaza_sarcina(sarcina: SarcinaCreare, utilizator=Depends(get_utilizator_curent), db: Session = Depends(get_db)):
    s = SarcinaDB(titlu=sarcina.titlu, descriere=sarcina.descriere or "", utilizator_id=utilizator.id)
    db.add(s)
    db.commit()
    db.refresh(s)
    return s

@app.put("/sarcini/{id}", response_model=SarcinaRaspuns)
def actualizeaza_sarcina(id: int, date: SarcinaActualizare, utilizator=Depends(get_utilizator_curent), db: Session = Depends(get_db)):
    s = db.query(SarcinaDB).filter(SarcinaDB.id == id, SarcinaDB.utilizator_id == utilizator.id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Sarcina negasita")
    s.titlu = date.titlu
    s.descriere = date.descriere or ""
    db.commit()
    db.refresh(s)
    return s

@app.patch("/sarcini/{id}/finaliza", response_model=SarcinaRaspuns)
def finalizeaza_sarcina(id: int, utilizator=Depends(get_utilizator_curent), db: Session = Depends(get_db)):
    s = db.query(SarcinaDB).filter(SarcinaDB.id == id, SarcinaDB.utilizator_id == utilizator.id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Sarcina negasita")
    s.finalizata = True
    db.commit()
    db.refresh(s)
    return s

@app.delete("/sarcini/{id}", status_code=204)
def sterge_sarcina(id: int, utilizator=Depends(get_utilizator_curent), db: Session = Depends(get_db)):
    s = db.query(SarcinaDB).filter(SarcinaDB.id == id, SarcinaDB.utilizator_id == utilizator.id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Sarcina negasita")
    db.delete(s)
    db.commit()

# ULTIMUL rand - dupa toate endpoint-urile
app.mount("/", StaticFiles(directory="static", html=True), name="static")
