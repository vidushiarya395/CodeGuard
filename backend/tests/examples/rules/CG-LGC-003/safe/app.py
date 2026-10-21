# Example only: scanned by the tests, never run.  CG-LGC-003 (safe)
from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()


def get_db():
    ...


def get_current_user():
    ...


class Note:
    id = None
    owner_id = None


@app.get("/notes/{note_id}")
def read_note(note_id: int, db=Depends(get_db), user=Depends(get_current_user)):
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user.id).first()
    if note is None:
        raise HTTPException(status_code=404)
    return note
