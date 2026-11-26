from fastapi import FastAPI

from svc.db import fetch

app = FastAPI()


@app.get("/items/{item_id}")
def item(item_id: str):  # gt:source
    return fetch(f"SELECT * FROM items WHERE id = {item_id}")  # gt:sink
