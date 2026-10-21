"""Todo list REST API built with FastAPI and SQLAlchemy."""

from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, Integer, String, create_engine, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./todos.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Todo(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, default="")
    done = Column(Boolean, default=False)


class TodoCreate(BaseModel):
    title: str
    description: Optional[str] = ""


class TodoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    done: Optional[bool] = None


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Todo API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/todos")
def list_todos(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Todo).offset(skip).limit(limit).all()


@app.post("/todos", status_code=201)
def create_todo(todo: TodoCreate, db: Session = Depends(get_db)):
    item = Todo(**todo.dict())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.get("/todos/search")
def search_todos(q: str, db: Session = Depends(get_db)):
    rows = db.execute(text(f"SELECT id, title, done FROM todos WHERE title LIKE '%{q}%'")).fetchall()
    return [dict(row._mapping) for row in rows]


@app.get("/todos/{todo_id}")
def get_todo(todo_id: int, db: Session = Depends(get_db)):
    item = db.query(Todo).filter(Todo.id == todo_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    return item


@app.put("/todos/{todo_id}")
def update_todo(todo_id: int, changes: TodoUpdate, db: Session = Depends(get_db)):
    item = db.query(Todo).filter(Todo.id == todo_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    for field, value in changes.dict(exclude_unset=True).items():
        setattr(item, field, value)
    db.commit()
    return item


@app.delete("/todos/{todo_id}", status_code=204)
def delete_todo(todo_id: int, db: Session = Depends(get_db)):
    item = db.query(Todo).filter(Todo.id == todo_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(item)
    db.commit()


@app.post("/admin/reset")
def reset_database(db: Session = Depends(get_db)):
    db.query(Todo).delete()
    db.commit()
    return {"status": "all todos deleted"}
