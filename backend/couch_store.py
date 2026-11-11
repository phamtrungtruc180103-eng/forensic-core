from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import Any


class CouchStore:
    def __init__(self) -> None:
        self.base_url = os.getenv("COUCHDB_URL", "http://localhost:5984").rstrip("/")
        self.database = os.getenv("COUCHDB_DATABASE", "forensic_core")
        self.username = os.getenv("COUCHDB_USER", "").strip()
        self.password = os.getenv("COUCHDB_PASSWORD", "")
        self.auth_header = ""
        if self.username and self.password:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.auth_header = f"Basic {token}"

    def _request(self, method: str, path: str, payload: Any | None = None) -> Any:
        if not self.auth_header:
            raise RuntimeError("COUCHDB_USER and COUCHDB_PASSWORD must be configured")
        body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(f"{self.base_url}/{path.lstrip('/')}", data=body, method=method)
        request.add_header("Authorization", self.auth_header)
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "PUT" and path == self.database:
                raise
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"CouchDB {method} {path} failed ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"CouchDB unavailable at {self.base_url}: {exc.reason}") from exc

    def ensure_database(self) -> None:
        try:
            self._request("PUT", self.database)
        except RuntimeError as exc:
            if "(412)" in str(exc):
                return
            raise

    def documents(self, collection: str) -> list[dict[str, Any]]:
        result = self._request("GET", f"{self.database}/_all_docs?include_docs=true")
        return [row["doc"] for row in result.get("rows", []) if row.get("doc", {}).get("collection") == collection]

    def get(self, collection: str, document_id: str) -> dict[str, Any] | None:
        try:
            return self._request("GET", f"{self.database}/{collection}:{document_id}")
        except RuntimeError as exc:
            if "(404)" in str(exc):
                return None
            raise

    def put(self, collection: str, document_id: str, value: dict[str, Any]) -> dict[str, Any]:
        document = {"_id": f"{collection}:{document_id}", "collection": collection, **value}
        existing = self.get(collection, document_id)
        if existing and "_rev" in existing:
            document["_rev"] = existing["_rev"]
        return self._request("PUT", f"{self.database}/{collection}:{document_id}", document)

    def delete(self, collection: str, document_id: str, revision: str) -> None:
        self._request("DELETE", f"{self.database}/{collection}:{document_id}?rev={revision}")

    def replace_collection(self, collection: str, values: list[dict[str, Any]], id_field: str) -> None:
        existing = self.documents(collection)
        for item in values:
            self.put(collection, str(item[id_field]), item)
        desired = {str(item[id_field]) for item in values}
        for item in existing:
            if "_id" in item and ":" in item:
                item_id = item["_id"].split(":", 1)[1]
                if item_id not in desired:
                    self._request("DELETE", f"{self.database}/{item['_id']}?rev={item['_rev']}")

    def next_id(self, collection: str, prefix: str) -> str:
        return f"{prefix}{len(self.documents(collection)) + 1:03d}"


store = CouchStore()
