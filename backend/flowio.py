"""Getting flow definitions into the scanner: normalising the JSON shapes people export, and reading
flows out of a Power Platform solution .zip. Nothing is written to disk and nothing is executed."""
import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile

MAX_ENTRIES = 5000
MAX_TOTAL_BYTES = 200 * 1024 * 1024   # uncompressed, whole archive
MAX_ENTRY_BYTES = 25 * 1024 * 1024    # one flow / customizations.xml


def locate_definition(content: dict) -> dict:
    """Return the workflow definition object inside any supported export shape (the live object, not a copy)."""
    if isinstance(content.get("resources"), list):          # Logic Apps / ARM template export
        for res in content["resources"]:
            if isinstance(res, dict) and isinstance(res.get("properties"), dict) and isinstance(res["properties"].get("definition"), dict):
                return res["properties"]["definition"]
        raise ValueError("Template has no workflow resource with a definition")
    if isinstance(content.get("properties"), dict) and isinstance(content["properties"].get("definition"), dict):
        return content["properties"]["definition"]
    if isinstance(content.get("definition"), dict):
        return content["definition"]
    if "triggers" in content or "actions" in content:
        return content
    raise ValueError("No flow definition found (expected properties.definition, definition, or triggers/actions)")


def normalize(filename: str, content: dict) -> dict:
    """Accept a full flow resource, {definition: ...}, a bare definition or a Logic Apps template."""
    base = filename.rsplit(".", 1)[0]
    if isinstance(content.get("resources"), list):
        for res in content["resources"]:
            if isinstance(res, dict) and isinstance(res.get("properties"), dict) and "definition" in res["properties"]:
                name = res.get("displayName") or base
                return {"name": base, "properties": {"displayName": name, "definition": res["properties"]["definition"]}}
        raise ValueError("Template has no workflow resource with a definition")
    if isinstance(content.get("properties"), dict) and "definition" in content["properties"]:
        flow = content
        flow.setdefault("name", base)
        flow["properties"].setdefault("displayName", base)
    elif "definition" in content:
        flow = {"name": base, "properties": {"displayName": base, "definition": content["definition"]}}
    elif "triggers" in content or "actions" in content:
        flow = {"name": base, "properties": {"displayName": base, "definition": content}}
    else:
        raise ValueError("No flow definition found (expected properties.definition, definition, or triggers/actions)")
    return flow


def _workflow_meta(xml_bytes: bytes) -> dict[str, dict]:
    """Map '/Workflows/x.json' (lower case, no leading slash) to {name, state} from customizations.xml."""
    if len(xml_bytes) > MAX_ENTRY_BYTES or b"<!DOCTYPE" in xml_bytes[:4096].upper() or b"<!ENTITY" in xml_bytes.upper():
        return {}
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return {}
    out: dict[str, dict] = {}
    for wf in root.iter("Workflow"):
        path = (wf.findtext("JsonFileName") or "").strip().lstrip("/").lower()
        if path:
            state = (wf.findtext("StateCode") or "").strip()
            out[path] = {"name": wf.get("Name"), "state": {"1": "Started", "0": "Stopped"}.get(state)}
    return out


RPA_EXTS = (".xaml", ".bot", ".atmx", ".bprelease", ".bpobject", ".bpprocess")


def _unique(name: str, used: set) -> str:
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    out, n = name, 1
    while out.lower() in used:
        n += 1
        out = f"{stem} ({n})" + (f".{ext}" if ext else "")
    used.add(out.lower())
    return out


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w .()\-]+", "_", name).strip(" .")[:80] or "flow"


def extract_solution(data: bytes) -> dict:
    """Read cloud flows out of a solution zip. Returns {"flows": [{filename, content}], "skipped": [{file, reason}]}."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("This is not a valid .zip file.")
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise ValueError(f"Archive has {len(infos)} entries; the limit is {MAX_ENTRIES}.")
    if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
        raise ValueError("Archive is too large once unpacked.")

    meta: dict[str, dict] = {}
    for i in infos:
        if i.filename.lower() == "customizations.xml" and i.file_size <= MAX_ENTRY_BYTES:
            meta = _workflow_meta(zf.read(i))

    flows, skipped, used = [], [], set()
    for i in infos:
        low = i.filename.lower()
        if not (low.startswith("workflows/") and low.endswith(".json")) or i.is_dir():
            continue
        if i.file_size > MAX_ENTRY_BYTES:
            skipped.append({"file": i.filename, "reason": "file is too large"})
            continue
        try:
            doc = json.loads(zf.read(i).decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            skipped.append({"file": i.filename, "reason": "not valid JSON"})
            continue
        props = doc.get("properties") if isinstance(doc, dict) else None
        if not (isinstance(props, dict) and isinstance(props.get("definition"), dict)):
            skipped.append({"file": i.filename, "reason": "no flow definition (not a cloud flow)"})
            continue
        m = meta.get(low, {})
        base = i.filename.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        props.setdefault("displayName", m.get("name") or base)
        if m.get("state"):
            props.setdefault("state", m["state"])
        doc.setdefault("name", base)
        fname, n = _safe_name(props["displayName"]), 1
        while fname.lower() in used:
            n += 1
            fname = f"{_safe_name(props['displayName'])} ({n})"
        used.add(fname.lower())
        flows.append({"filename": fname + ".json", "content": doc})
    # RPA projects and packages (UiPath .xaml and project.json, Automation Anywhere, Blue Prism)
    from rpascan import kind_of as rpa_kind   # imported here: rpascan itself imports this module's neighbours
    used_files = {f["filename"].lower() for f in flows}
    for i in infos:
        base = i.filename.rsplit("/", 1)[-1]
        if i.is_dir() or i.file_size > MAX_ENTRY_BYTES or not base:
            continue
        if base.lower().endswith(RPA_EXTS):
            try:
                text = zf.read(i).decode("utf-8-sig")
            except UnicodeDecodeError:
                skipped.append({"file": i.filename, "reason": "not text"})
                continue
            flows.append({"filename": _unique(base, used_files), "content": {"format": "rpa-file", "name": base, "text": text}})
        elif base.lower() == "project.json":
            try:
                doc = json.loads(zf.read(i).decode("utf-8-sig"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(doc, dict) and rpa_kind(doc) == "uipath-project":
                flows.append({"filename": _unique("project.json", used_files), "content": doc})
    return {"flows": flows, "skipped": skipped}
