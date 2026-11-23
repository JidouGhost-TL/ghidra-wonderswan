# SPDX-License-Identifier: MIT OR Apache-2.0
"""Inventory the fresh Ghidra 12.1.3 indexed project used by the GUI rehearsal."""
from dataclasses import dataclass
import hashlib
import re
import stat
import struct
from xml.etree import ElementTree


class IndexedStorageError(RuntimeError):
    pass


def check(condition, reason):
    if not condition:
        raise IndexedStorageError(reason)


def safe_entry(path, directory=False):
    info = path.lstat()
    check(not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT,
          "saved_storage_boundary")
    if directory:
        check(stat.S_ISDIR(info.st_mode), "saved_storage_boundary")
    else:
        check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "saved_storage_boundary")
    return info


def metadata_bytes(path):
    info = safe_entry(path)
    check(info.st_size <= 8192, "saved_storage_metadata")
    return path.read_bytes()


def index_items(path, fixtures):
    lines = metadata_bytes(path).decode("utf-8").splitlines()
    check(len(lines) == len(fixtures) + 4 and lines[:2] == ["VERSION=1", "/"], "saved_storage_index")
    next_id = re.fullmatch(r"NEXT-ID:([0-9a-f]{1,16})", lines[-2])
    # The pinned writer resets MD5 for each line and writes the empty digest footer.
    check(next_id and lines[-1] == "MD5:d41d8cd98f00b204e9800998ecf8427e", "saved_storage_index")
    items = {}
    for line in lines[2:-2]:
        entry = re.fullmatch(r"  ([0-9a-f]{8,16}):([^:]+):([0-9a-f]{1,32})", line)
        check(entry, "saved_storage_index")
        storage, name, file_id = entry.groups()
        check(storage not in items and int(storage, 16) < int(next_id[1], 16), "saved_storage_index")
        items[storage] = (name, file_id)
    check({name for name, _ in items.values()} == set(fixtures) and
          len({file_id for _, file_id in items.values()}) == len(fixtures), "saved_storage_index")
    return items


def property_states(path, reason):
    data = metadata_bytes(path).decode("utf-8")
    check("<!" not in data, reason)
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        raise IndexedStorageError(reason) from error
    check(root.tag == "FILE_INFO" and len(root) == 1 and root[0].tag == "BASIC_INFO", reason)
    states = {}
    for field in root[0]:
        key = field.get("NAME")
        check(field.tag == "STATE" and key and key not in states, reason)
        states[key] = (field.get("TYPE"), field.get("VALUE"))
    return states


def verify_item(path, name, file_id):
    states = property_states(path, "saved_storage_item")
    expected = {"NAME": ("string", name), "FILE_ID": ("string", file_id), "PARENT": ("string", "/"),
                "CONTENT_TYPE": ("string", "Program"), "FILE_TYPE": ("int", "0"),
                "READ_ONLY": ("boolean", "true")}
    check(all(states.get(key) == value for key, value in expected.items()), "saved_storage_item")


def buffer_digest(path):
    length = safe_entry(path).st_size
    with path.open("rb") as stream:
        header = stream.read(24)
        check(len(header) == 24, "saved_storage_buffer")
        magic, _, version, block_size = struct.unpack(">QQII", header)
        check(magic == 0x2f30312c34292c2a and version == 1 and block_size >= 128 and
              length >= 2 * block_size and length % block_size == 0, "saved_storage_buffer")
        # DBParms occupies buffer zero, immediately after the LocalBufferFile header block.
        stream.seek(block_size)
        data = stream.read(23)
        check(len(data) == 23, "saved_storage_buffer")
        flags, index, node, size, version, _, database_id = struct.unpack(">BIBIBIQ", data)
        check((flags, index, node, version) == (0, 0, 9, 1) and 13 <= size <= block_size - 10 and
              (size - 1) % 4 == 0 and database_id != 0, "saved_storage_buffer")
        stream.seek(0)
        return database_id, hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass(frozen=True)
class SavedPrograms:
    items: dict
    files: dict


def saved_programs(projects, project, fixtures):
    safe_entry(projects, directory=True)
    marker, repository = projects / f"{project}.gpr", projects / f"{project}.rep"
    check({path.name for path in projects.iterdir()} == {marker.name, repository.name}, "saved_storage_layout")
    safe_entry(marker)
    safe_entry(repository, directory=True)
    settings = property_states(repository / "project.prp", "saved_storage_project")
    owner = settings.get("OWNER", (None, None))
    check(owner[0] == "string" and owner[1] and not settings.keys() & {"SERVER", "REPOSITORY_NAME", "PORT_NUMBER"},
          "saved_storage_project")
    store = repository / "idata"
    safe_entry(store, directory=True)
    index = store / "~index.dat"
    items = index_items(index, fixtures)
    buckets = {}
    for storage in items:
        buckets.setdefault(storage[-3:-1], set()).update((f"{storage}.prp", f"~{storage}.db"))
    for path in store.iterdir():
        if path.name in buckets:
            safe_entry(path, directory=True)
            check({entry.name for entry in path.iterdir()} == buckets[path.name], "saved_storage_layout")
        else:
            check(path.name in {"~index.dat", "~index.bak", "~journal.bak"}, "saved_storage_layout")
            safe_entry(path)

    files, database_owners = {}, {}
    for storage, (name, file_id) in items.items():
        bucket = store / storage[-3:-1]
        verify_item(bucket / f"{storage}.prp", name, file_id)
        database = bucket / f"~{storage}.db"
        safe_entry(database, directory=True)
        generations = list(database.iterdir())
        check(generations, "saved_storage_buffer")
        database_ids = set()
        for path in generations:
            version = re.fullmatch(r"db\.([1-9][0-9]{0,9})\.gbf", path.name)
            check(version and int(version[1]) <= 0x7fffffff, "saved_storage_buffer")
            database_id, digest = buffer_digest(path)
            check(database_owners.setdefault(database_id, storage) == storage, "saved_storage_buffer")
            database_ids.add(database_id)
            files[path.relative_to(projects)] = digest
        check(len(database_ids) == 1, "saved_storage_buffer")
    return SavedPrograms(items, files)
