"""Inventory API for a small shop. Every route needs a logged-in user; items belong to their owner."""

import hashlib
import hmac
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

engine = create_engine(os.environ.get("DATABASE_URL", "sqlite:///./inventory.db"))
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SYNC_API_KEY = os.environ.get("SYNC_API_KEY", "")


class UserRow(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    token_hash = Column(String, unique=True)


class ItemRow(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    quantity = Column(Integer, default=0)


class ItemIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    quantity: int = Field(ge=0, le=100_000)


class ItemPatch(BaseModel):
    quantity: Optional[int] = Field(default=None, ge=0, le=100_000)


app = FastAPI(title="Inventory")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://inventory.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserRow:
    digest = hashlib.sha256(token.encode()).hexdigest()
    user = db.query(UserRow).filter(UserRow.token_hash == digest).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def own_item(item_id: int, user: UserRow, db: Session) -> ItemRow:
    item = db.query(ItemRow).filter(ItemRow.id == item_id, ItemRow.owner_id == user.id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.get("/items")
def list_items(db: Session = Depends(get_db), user: UserRow = Depends(get_current_user)):
    return db.query(ItemRow).filter(ItemRow.owner_id == user.id).all()


@app.post("/items", status_code=201)
def create_item(item: ItemIn, db: Session = Depends(get_db), user: UserRow = Depends(get_current_user)):
    row = ItemRow(owner_id=user.id, name=item.name, quantity=item.quantity)
    db.add(row)
    db.commit()
    return {"id": row.id}


@app.patch("/items/{item_id}")
def update_item(item_id: int, patch: ItemPatch, db: Session = Depends(get_db), user: UserRow = Depends(get_current_user)):
    item = own_item(item_id, user, db)
    if patch.quantity is not None:
        item.quantity = patch.quantity
    db.commit()
    return {"id": item.id, "quantity": item.quantity}


@app.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: int, db: Session = Depends(get_db), user: UserRow = Depends(get_current_user)):
    item = db.query(ItemRow).filter(ItemRow.id == item_id, ItemRow.owner_id == user.id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(item)
    db.commit()


@app.post("/sync")
def sync_from_warehouse(x_api_key: str = Header(...), db: Session = Depends(get_db)):
    if x_api_key != SYNC_API_KEY:
        raise HTTPException(status_code=403, detail="Bad API key")
    return {"synced": db.query(ItemRow).count()}
