"""Deterministic global/scoped identity registry, alias clustering, and path mapper."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import threading
from typing import Iterable
from urllib.parse import urlparse

from .config import (
    ENGINEERING_STOPWORDS,
    PRESERVED_PATH_SEGMENTS,
    SAFE_CAD_VENDORS,
    SAFE_DOMAINS,
    is_safe_engineering_token,
    split_compound_extension,
)
from .matching import TokenMatcher, replace_tokens

ENTITY_TYPES = (
    "ORG",
    "PERSON",
    "USERNAME",
    "ACCOUNT",
    "DOMAIN",
    "EMAIL",
    "HOST",
    "URL",
    "PROJECT",
    "PART_ID",
    "ADDRESS",
    "PHONE",
    "PATH",
)

GLOBAL_SCOPE = "__global__"

# Precompiled universal PII regexes for uncatalogued occurrences during transform
RE_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
RE_URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})([^\s\"'<>)\]]*)")
RE_UNC_PATH = re.compile(r"(\\\\[A-Za-z0-9._-]+(?:\\[^\\/:*?\"<>|\r\n]+)+)")
RE_WIN_USER_PATH = re.compile(
    r"([A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*)",
    re.IGNORECASE,
)
RE_WIN_DRIVE_PATH = re.compile(
    r"([A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]*)"
)
RE_UNIX_HOME_PATH = re.compile(r"(/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s\"'<>|]+)*)")
RE_DOMAIN_USER = re.compile(
    r"(?<![A-Za-z0-9\\])([A-Za-z][A-Za-z0-9_-]{1,20})\\([A-Za-z][A-Za-z0-9._-]{1,32})(?![A-Za-z0-9\\])"
)
RE_PHONE = re.compile(
    r"(?<!\d)(\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,6})(?!\d)"
)
RE_PSEUDONYM = re.compile(
    r"(?:org-?|prj-|part-|usr|acct|engineer |host-)(?:\d{4,}|f[0-9a-f]{11})(?:\.example\.invalid)?$",
    re.IGNORECASE,
)
PART_FILENAME_SUFFIXES = frozenset({
    ".step", ".stp", ".iges", ".igs", ".sldprt", ".sldasm", ".slddrw", ".stl",
    ".ipt", ".iam", ".idw", ".dxf", ".dwg", ".catpart", ".catproduct", ".pdf",
})


def _norm_key(raw: str) -> str:
    return re.sub(r"\s+", " ", raw.strip()).lower()


def _clean_slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s.strip())
    return s.strip("-") or "item"


def _part_filename_suffix(value: str) -> str:
    _, suffix = split_compound_extension(value)
    return suffix if suffix.lower() in PART_FILENAME_SUFFIXES else ""


@dataclass
class IdentityEntry:
    entity_id: str
    entity_type: str
    pseudonym: str
    short_code: str
    scopes: set[str] = field(default_factory=set)
    variants: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "pseudonym": self.pseudonym,
            "short_code": self.short_code,
            "scopes": sorted(self.scopes),
            "variants": sorted(self.variants),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IdentityEntry":
        return cls(
            entity_id=d["entity_id"],
            entity_type=d["entity_type"],
            pseudonym=d["pseudonym"],
            short_code=d["short_code"],
            scopes=set(d.get("scopes", [])),
            variants=set(d.get("variants", [])),
        )


class IdentityRegistry:
    """Thread/process-serializable deterministic pseudonym registry."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.counters: dict[str, int] = {t: 0 for t in ENTITY_TYPES}
        self.entities: dict[str, IdentityEntry] = {}  # entity_id -> IdentityEntry
        self.variant_to_id: dict[str, str] = {}  # norm_variant -> entity_id
        self.raw_to_id: dict[str, str] = {}  # exact lower raw -> entity_id
        self.path_map: dict[str, str] = {}  # input_rel_path -> output_rel_path
        self.dir_basename_map: dict[str, dict[str, str]] = {}  # scope_or_dir -> {old_base_lower: new_base}
        self.global_basename_map: dict[str, str] = {}  # unambiguous old_base_lower -> new_base
        self.omitted_defects: list[dict[str, str]] = []
        self._frozen = False
        self._identity_matchers: dict[str, TokenMatcher] = {}
        self._scoped_entries: dict[str, list[IdentityEntry]] = {}
        self._filename_matchers: dict[str, TokenMatcher] = {}

    @staticmethod
    def scope_for_rel_path(rel_path: str) -> str:
        """Compute project scope key for a corpus-relative path."""
        parts = rel_path.replace("\\", "/").strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "sources":
            return "/".join(parts[:3])
        if len(parts) >= 2 and parts[0] == "archives":
            stem = parts[1].split("__")[0] if "__" in parts[1] else parts[1]
            return f"archives/{stem}"
        return parts[0] if parts else GLOBAL_SCOPE

    def _next_id(self, entity_type: str) -> tuple[str, str, str]:
        self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
        n = self.counters[entity_type]
        return self._format_id(entity_type, f"{n:04d}")

    @staticmethod
    def _format_id(entity_type: str, n: str) -> tuple[str, str, str]:
        eid = f"{entity_type}-{n}"
        if entity_type == "ORG":
            return eid, f"ORG-{n}", f"ORG{n}"
        if entity_type == "PERSON":
            return eid, f"Engineer {n}", f"eng{n}"
        if entity_type == "USERNAME":
            return eid, f"usr{n}", f"usr{n}"
        if entity_type == "ACCOUNT":
            return eid, f"acct{n}", f"acct{n}"
        if entity_type == "DOMAIN":
            return eid, f"org{n}.example.invalid", f"org{n}"
        if entity_type == "EMAIL":
            return eid, f"usr{n}@example.invalid", f"usr{n}"
        if entity_type == "HOST":
            return eid, f"host-{n}", f"host{n}"
        if entity_type == "URL":
            return eid, f"https://org{n}.example.invalid/ref-{n}", f"ref{n}"
        if entity_type == "PROJECT":
            return eid, f"PRJ-{n}", f"PRJ{n}"
        if entity_type == "PART_ID":
            return eid, f"PART-{n}", f"PRT{n}"
        if entity_type == "ADDRESS":
            return eid, f"100 Industrial Way, Suite {n}", f"ADDR{n}"
        if entity_type == "PHONE":
            return eid, f"+1-555-010-{n}", f"TEL{n}"
        if entity_type == "PATH":
            return eid, f"C:\\workspace\\prj-{n}", f"PTH{n}"
        return eid, f"ID-{n}", f"ID{n}"

    def _should_ignore_raw(self, raw: str, entity_type: str) -> bool:
        s = raw.strip()
        if len(s) < 2:
            return True
        low = s.lower()
        if RE_PSEUDONYM.fullmatch(s) or ".example.invalid" in low or low.endswith("@example.invalid"):
            return True
        if entity_type == "DOMAIN":
            if low in SAFE_DOMAINS or any(low.endswith("." + sd) for sd in SAFE_DOMAINS):
                return True
            if low.endswith(".example.invalid"):
                return True
        if entity_type == "URL":
            try:
                host = (urlparse(s).hostname or "").lower()
                if not host or host in SAFE_DOMAINS or any(host.endswith("." + sd) for sd in SAFE_DOMAINS):
                    return True
            except Exception:
                return True
        if entity_type not in {"EMAIL", "URL", "DOMAIN", "ADDRESS", "PHONE", "PATH"}:
            if is_safe_engineering_token(s):
                return True
            if re.fullmatch(r"\d{1,3}", s):
                return True
        return False

    def register(
        self,
        raw: str,
        entity_type: str,
        scope: str = GLOBAL_SCOPE,
        *,
        is_global: bool | None = None,
        link_to_id: str | None = None,
    ) -> str | None:
        """Register an identifying value and return its pseudonym (or None if ignored)."""
        if not raw or not isinstance(raw, str):
            return None
        cleaned = re.sub(r"\s+", " ", raw.strip())
        if self._should_ignore_raw(cleaned, entity_type):
            return None
        if self._frozen:
            return self._resolve_frozen_identity(cleaned, entity_type, scope)

        # Decompose structured compound identities first so components stay linked!
        if entity_type == "EMAIL" and "@" in cleaned:
            local, dom = cleaned.rsplit("@", 1)
            dom_pseudo = self.register(dom, "DOMAIN", scope, is_global=True)
            usr_pseudo = self.register(local, "USERNAME", scope, is_global=(len(local) >= 4))
            if dom_pseudo and usr_pseudo:
                key = _norm_key(cleaned)
                with self._lock:
                    if key in self.variant_to_id:
                        ent = self.entities[self.variant_to_id[key]]
                        ent.scopes.add(GLOBAL_SCOPE)
                        return ent.pseudonym
                    self.counters["EMAIL"] += 1
                    n = self.counters["EMAIL"]
                    eid = f"EMAIL-{n:04d}"
                    pseudo = f"{usr_pseudo}@{dom_pseudo}"
                    ent = IdentityEntry(eid, "EMAIL", pseudo, f"usr{n:04d}", {GLOBAL_SCOPE, scope}, {cleaned})
                    self.entities[eid] = ent
                    self.variant_to_id[key] = eid
                    self.raw_to_id[cleaned.lower()] = eid
                    return pseudo

        if entity_type == "URL":
            try:
                p = urlparse(cleaned)
                host = (p.hostname or "").lower()
                if host and not self._should_ignore_raw(host, "DOMAIN"):
                    dom_pseudo = self.register(host, "DOMAIN", scope, is_global=True)
                    key = _norm_key(cleaned)
                    with self._lock:
                        if key in self.variant_to_id:
                            return self.entities[self.variant_to_id[key]].pseudonym
                        self.counters["URL"] += 1
                        n = self.counters["URL"]
                        eid = f"URL-{n:04d}"
                        scheme = p.scheme or "https"
                        pseudo = f"{scheme}://{dom_pseudo}/ref-{n:04d}"
                        ent = IdentityEntry(eid, "URL", pseudo, f"ref{n:04d}", {GLOBAL_SCOPE, scope}, {cleaned})
                        self.entities[eid] = ent
                        self.variant_to_id[key] = eid
                        self.raw_to_id[cleaned.lower()] = eid
                        return pseudo
            except Exception:
                pass

        m_du = RE_DOMAIN_USER.fullmatch(cleaned)
        if m_du:
            org_raw, usr_raw = m_du.group(1), m_du.group(2)
            org_p = self.register(org_raw, "ORG", scope, is_global=(len(org_raw) >= 4)) or "ORG-0000"
            usr_p = self.register(usr_raw, "USERNAME", scope, is_global=(len(usr_raw) >= 4)) or "usr0000"
            key = _norm_key(cleaned)
            with self._lock:
                if key in self.variant_to_id:
                    return self.entities[self.variant_to_id[key]].pseudonym
                self.counters["ACCOUNT"] += 1
                n = self.counters["ACCOUNT"]
                eid = f"ACCOUNT-{n:04d}"
                pseudo = f"{org_p}\\{usr_p}"
                ent = IdentityEntry(eid, "ACCOUNT", pseudo, f"acct{n:04d}", {GLOBAL_SCOPE, scope}, {cleaned})
                self.entities[eid] = ent
                self.variant_to_id[key] = eid
                self.raw_to_id[cleaned.lower()] = eid
                return pseudo

        if entity_type == "DOMAIN" and "." in cleaned:
            labels = cleaned.lower().split(".")
            # Check if first label is a host prefix of an already known parent domain
            if len(labels) >= 3 and len(labels[0]) >= 2:
                parent_dom = ".".join(labels[1:])
                if parent_dom not in {"co.uk", "com.au", "ac.uk", "org.uk"} and len(labels[1]) >= 3:
                    parent_p = self.register(parent_dom, "DOMAIN", scope, is_global=True)
                    host_p = self.register(labels[0], "HOST", scope, is_global=False)
                    if parent_p and host_p:
                        key = _norm_key(cleaned)
                        with self._lock:
                            if key in self.variant_to_id:
                                return self.entities[self.variant_to_id[key]].pseudonym
                            self.counters["DOMAIN"] += 1
                            n = self.counters["DOMAIN"]
                            eid = f"DOMAIN-{n:04d}"
                            pseudo = f"{host_p}.{parent_p}"
                            ent = IdentityEntry(eid, "DOMAIN", pseudo, host_p, {GLOBAL_SCOPE, scope}, {cleaned})
                            self.entities[eid] = ent
                            self.variant_to_id[key] = eid
                            self.raw_to_id[cleaned.lower()] = eid
                            return pseudo

        # Determine whether token is safe for global scope or must stay scoped
        if is_global is None:
            if entity_type in {"EMAIL", "URL", "DOMAIN", "ADDRESS", "PHONE", "ACCOUNT"}:
                is_global = True
            elif entity_type in {"PERSON", "ORG", "PROJECT"}:
                # Full multi-word names or unambiguous >=5 char handles can be global;
                # short acronyms (<=4 chars) or single common words stay project-scoped.
                has_space_or_sep = bool(re.search(r"[\s._-]", cleaned))
                is_global = (len(cleaned) >= 5 and (has_space_or_sep or not re.fullmatch(r"[A-Za-z]+", cleaned) or len(cleaned) >= 6))
            elif entity_type == "USERNAME":
                is_global = len(cleaned) >= 5
            elif entity_type == "PART_ID":
                is_global = bool(re.fullmatch(r"[A-Za-z]{2,8}[-_]\d{3,}[A-Za-z0-9-]*", cleaned))
            else:
                is_global = len(cleaned) >= 6

        key = _norm_key(cleaned)
        target_scope = GLOBAL_SCOPE if is_global else scope

        with self._lock:
            existing_id = self.variant_to_id.get(key)
            if existing_id:
                ent = self.entities[existing_id]
                if cleaned not in ent.variants or target_scope not in ent.scopes or scope not in ent.scopes:
                    ent.variants.add(cleaned)
                    ent.scopes.update((target_scope, scope))
                    self._invalidate_cache()
                return ent.pseudonym

            if link_to_id and link_to_id in self.entities:
                ent = self.entities[link_to_id]
                ent.variants.add(cleaned)
                ent.scopes.add(target_scope)
                ent.scopes.add(scope)
                self.variant_to_id[key] = link_to_id
                self.raw_to_id[cleaned.lower()] = link_to_id
                self._invalidate_cache()
                return ent.pseudonym

            eid, pseudo, short_code = self._next_id(entity_type)
            ent = IdentityEntry(
                entity_id=eid,
                entity_type=entity_type,
                pseudonym=pseudo,
                short_code=short_code,
                scopes={target_scope, scope},
                variants={cleaned},
            )
            self.entities[eid] = ent
            self.variant_to_id[key] = eid
            self.raw_to_id[cleaned.lower()] = eid

            # Register normalized domain root as an ORG alias if meaningful
            if entity_type == "DOMAIN" and "." in cleaned:
                root_lbl = cleaned.split(".")[0]
                if len(root_lbl) >= 4 and not is_safe_engineering_token(root_lbl):
                    if _norm_key(root_lbl) not in self.variant_to_id:
                        self.register(root_lbl, "ORG", scope, is_global=True)

            # Link salient constituent words (>=4 chars, non-stopword) of multi-word ORG names within scope
            if entity_type == "ORG" and " " in cleaned:
                for tok in re.findall(r"[A-Za-z][A-Za-z0-9-]{3,}", cleaned):
                    if not is_safe_engineering_token(tok) and _norm_key(tok) not in self.variant_to_id:
                        self.register(tok, "ORG", scope, is_global=False, link_to_id=eid)

            self._invalidate_cache()
            return pseudo

    def freeze(self) -> None:
        """Keep discovered names immutable and resolve new explicit IDs deterministically."""
        if self._frozen:
            return
        self._frozen = True
        self._invalidate_cache()
        for entry in self.entities.values():
            scopes = (GLOBAL_SCOPE,) if GLOBAL_SCOPE in entry.scopes else entry.scopes
            for scope in scopes:
                self._scoped_entries.setdefault(scope, []).append(entry)

    def _resolve_frozen_identity(self, raw: str, entity_type: str, scope: str) -> str:
        key = _norm_key(raw)
        if eid := self.variant_to_id.get(key):
            return self.entities[eid].pseudonym

        suffix = "f" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:11]
        _, pseudonym, _ = self._format_id(entity_type, suffix)
        if entity_type == "EMAIL" and "@" in raw:
            local, domain = raw.rsplit("@", 1)
            person = self.register(local, "USERNAME", scope)
            host = self.register(domain, "DOMAIN", scope)
            if person and host:
                return f"{person}@{host}"
        if entity_type == "URL":
            url = urlparse(raw)
            if url.hostname and (host := self.register(url.hostname, "DOMAIN", scope)):
                return f"{url.scheme}://{host}/ref-{suffix}"
        if entity_type == "ACCOUNT" and (account := RE_DOMAIN_USER.fullmatch(raw)):
            org = self.register(account[1], "ORG", scope)
            user = self.register(account[2], "USERNAME", scope)
            if org and user:
                return f"{org}\\{user}"
        return pseudonym

    def register_path(self, raw_path: str, scope: str = GLOBAL_SCOPE, *, discover: bool = False) -> str:
        """De-identify a local/UNC Windows or Unix path while keeping CAD filename tail."""
        if not raw_path:
            return raw_path
        sep = "\\" if "\\" in raw_path else "/"
        is_unc = raw_path.startswith("\\\\")
        drive = ""
        rest = raw_path
        if is_unc:
            rest = raw_path[2:]
        elif re.match(r"^[A-Za-z]:[\\/]", raw_path):
            drive = raw_path[:2].upper()
            rest = raw_path[3:]
        elif raw_path.startswith("/"):
            drive = ""
            rest = raw_path[1:]

        segs = [s for s in re.split(r"[\\/]+", rest) if s]
        is_dir_path = raw_path.endswith(("\\", "/"))
        out_segs: list[str] = []
        for idx, seg in enumerate(segs):
            if is_unc and idx == 0:
                p = self.register(seg, "DOMAIN" if "." in seg else "HOST", scope, is_global=True)
                out_segs.append(p or "host-0000")
                continue
            if idx == len(segs) - 1 and not is_dir_path:
                # Filename segment: check basename map or scrub tokens
                mapped = seg if discover else self.resolve_filename(seg, scope)
                out_segs.append(mapped)
                continue
            low = seg.lower()
            if low in PRESERVED_PATH_SEGMENTS or low in ENGINEERING_STOPWORDS:
                out_segs.append(seg)
            elif low in {"users", "home", "austausch", "documents and settings", "appdata", "local", "roaming", "temp", "tmp", "desktop", "documents", "documentos", "downloads", "onedrive", "dropbox"}:
                out_segs.append(seg)
            elif idx > 0 and segs[idx - 1].lower() in {"users", "home"}:
                p = self.register(seg, "USERNAME", scope, is_global=(len(seg) >= 4))
                out_segs.append(p or "usr0000")
            else:
                # Replace any known tokens inside folder name, or map identifying folder name
                scrubbed = seg if discover else self.replace_text(seg, scope, context="path_seg")
                if scrubbed == seg and not is_safe_engineering_token(seg) and re.search(r"[A-Za-z]{3,}", seg):
                    p = self.register(seg, "PROJECT", scope, is_global=False)
                    scrubbed = p or seg
                out_segs.append(scrubbed)

        if is_unc:
            res = "\\\\" + "\\".join(out_segs)
        elif drive:
            res = f"{drive}{sep}" + sep.join(out_segs)
        elif raw_path.startswith("/"):
            res = "/" + "/".join(out_segs)
        else:
            res = sep.join(out_segs)
        if is_dir_path and not res.endswith(sep):
            res += sep
        return res

    def _invalidate_cache(self) -> None:
        self._identity_matchers.clear()

    def _identity_matcher(self, scope: str) -> TokenMatcher:
        with self._lock:
            if scope not in self._identity_matchers:
                entries = self._scoped_entries.get(scope, ()) if self._frozen else (
                    entry for entry in self.entities.values()
                    if (scope in entry.scopes and (scope == GLOBAL_SCOPE or GLOBAL_SCOPE not in entry.scopes))
                )
                tokens = {
                    v: entry.pseudonym + (_part_filename_suffix(v) if entry.entity_type == "PART_ID" else "")
                    for entry in entries for v in entry.variants
                    if len(v) >= 3 or (len(v) >= 2 and entry.entity_type in {"EMAIL", "DOMAIN", "ACCOUNT"})
                }
                self._identity_matchers[scope] = TokenMatcher(tokens)
            return self._identity_matchers[scope]

    def replace_text(self, text: str, scope: str = GLOBAL_SCOPE, *, context: str = "general") -> str:
        """Replace all registered identifiers and uncatalogued PII patterns consistently."""
        if not text:
            return text
        out = text

        # 1. Explicit structural PII patterns (UNC paths, Windows user paths, emails, URLs, DOMAIN\user)
        def _sub_unc(m: re.Match[str]) -> str:
            return self.register_path(m.group(1), scope)

        def _sub_win_user(m: re.Match[str]) -> str:
            return self.register_path(m.group(1), scope)

        def _sub_email(m: re.Match[str]) -> str:
            p = self.register(m.group(1), "EMAIL", scope, is_global=True)
            return p or m.group(1)

        def _sub_url(m: re.Match[str]) -> str:
            p = self.register(m.group(0), "URL", scope, is_global=True)
            return p or m.group(0)

        def _sub_du(m: re.Match[str]) -> str:
            org, usr = m.group(1), m.group(2)
            # Avoid mangling C:\Windows or similar drive paths
            if len(org) == 1 or org.lower() in {"windows", "program", "system32", "users", "appdata", "temp", "cad"}:
                return m.group(0)
            p = self.register(m.group(0), "ACCOUNT", scope, is_global=True)
            return p or m.group(0)

        def _sub_phone(m: re.Match[str]) -> str:
            # Skip things that look like dimensions or tolerances (rare with leading + and 9+ digits)
            digits = re.sub(r"\D", "", m.group(1))
            if len(digits) < 9:
                return m.group(0)
            p = self.register(m.group(1), "PHONE", scope, is_global=True)
            return p or m.group(1)

        out = RE_UNC_PATH.sub(_sub_unc, out)
        out = RE_WIN_USER_PATH.sub(_sub_win_user, out)
        out = RE_EMAIL.sub(_sub_email, out)
        out = RE_URL.sub(_sub_url, out)
        out = RE_DOMAIN_USER.sub(_sub_du, out)
        if context in {"metadata", "title_block", "pdf_span", "general"}:
            out = RE_PHONE.sub(_sub_phone, out)

        # 2. Windows/Unix non-user paths containing known tokens or user directories
        if "\\" in out or "/home/" in out or "/Users/" in out:
            out = RE_UNIX_HOME_PATH.sub(lambda m: self.register_path(m.group(1), scope), out)
            if context in {"metadata", "xml", "step", "iges"}:
                out = RE_WIN_DRIVE_PATH.sub(lambda m: self.register_path(m.group(1), scope), out)

        # 3. Registered global + scoped entity dictionary (longest-first, boundary-safe)
        matchers = [self._identity_matcher(GLOBAL_SCOPE)]
        if scope != GLOBAL_SCOPE:
            matchers.append(self._identity_matcher(scope))
        out = replace_tokens(out, matchers)

        # 4. Referenced sibling CAD filenames that were renamed
        if context in {"step", "xml", "cad_ref", "metadata", "general"}:
            out = self.replace_filename_references(out, scope)

        return out

    def replace_fixed_length(self, text: str, scope: str = GLOBAL_SCOPE, encoding: str = "utf-8") -> bytes:
        """Replace identifiers in text and fit exact original byte length for fixed-layout binary slots."""
        orig_bytes = text.encode(encoding, errors="replace")
        target_len = len(orig_bytes)
        replaced = self.replace_text(text, scope, context="metadata")
        if replaced == text:
            return orig_bytes
        rep_bytes = replaced.encode(encoding, errors="replace")
        if len(rep_bytes) == target_len:
            return rep_bytes
        if len(rep_bytes) < target_len:
            pad_char = b" " if encoding == "ascii" or "\x00" not in text else b"\x00"
            return rep_bytes + pad_char * (target_len - len(rep_bytes))
        # Deterministic short hash tag if pseudonym exceeds binary slot width
        digest = hashlib.sha1(rep_bytes).hexdigest()[: max(2, min(6, target_len - 2))].upper()
        prefix = rep_bytes[: max(0, target_len - len(digest) - 1)]
        fitted = (prefix + b"-" + digest.encode("ascii"))[:target_len]
        return fitted

    def compute_path_mapping(self, rel_paths: Iterable[str]) -> dict[str, str]:
        """Assign deterministic, collision-free output relative paths preserving extensions."""
        with self._lock:
            sorted_paths = sorted(set(p.replace("\\", "/").lstrip("/") for p in rel_paths))
            used_targets: set[str] = set()
            self.path_map.clear()
            self.dir_basename_map.clear()
            self.global_basename_map.clear()
            self._filename_matchers.clear()

            # Track unique original basenames across corpus
            basename_counts: dict[str, int] = {}
            for rp in sorted_paths:
                bn = rp.rsplit("/", 1)[-1].lower()
                basename_counts[bn] = basename_counts.get(bn, 0) + 1

            for rp in sorted_paths:
                # Skip .resume-partial truncated fragments (logged as omitted source defects)
                if rp.lower().endswith(".resume-partial"):
                    continue
                scope = self.scope_for_rel_path(rp)
                segs = rp.split("/")
                new_segs: list[str] = []

                for idx, seg in enumerate(segs):
                    is_last = idx == len(segs) - 1
                    if not is_last:
                        new_segs.append(self._transform_dir_segment(segs, idx, scope))
                    else:
                        new_segs.append(self._transform_filename(seg, scope))

                candidate = "/".join(new_segs)
                # Ensure zero collisions
                if candidate.lower() in used_targets:
                    parent, fn = (candidate.rsplit("/", 1) if "/" in candidate else ("", candidate))
                    stem, ext = split_compound_extension(fn)
                    c_idx = 2
                    while True:
                        alt_fn = f"{stem}_{c_idx}{ext}"
                        alt = f"{parent}/{alt_fn}" if parent else alt_fn
                        if alt.lower() not in used_targets:
                            candidate = alt
                            break
                        c_idx += 1

                used_targets.add(candidate.lower())
                self.path_map[rp] = candidate

                old_base = segs[-1]
                new_base = candidate.rsplit("/", 1)[-1]
                if old_base != new_base:
                    self.dir_basename_map.setdefault(scope, {})[old_base.lower()] = new_base
                    if basename_counts.get(old_base.lower(), 0) == 1:
                        self.global_basename_map[old_base.lower()] = new_base

            return dict(self.path_map)

    def _transform_dir_segment(self, segs: list[str], idx: int, scope: str) -> str:
        seg = segs[idx]
        low = seg.lower()
        if idx == 0 and low in {"sources", "archives"}:
            return seg
        if idx == 1 and segs[0].lower() == "sources" and low in {"github", "gitlab", "catalog", "existing", "web"}:
            return seg
        if low in PRESERVED_PATH_SEGMENTS or re.fullmatch(r"[0-9a-f]{8,16}", low):
            return seg

        # Handle .extracted directory matching its sibling archive name
        extracted_suffix = ".extracted" if low.endswith(".extracted") else ""
        base = seg[:-len(".extracted")] if extracted_suffix else seg

        if idx == 2 and segs[0].lower() == "sources":
            src_kind = segs[1].lower()
            if src_kind == "web":
                p = self.register(base, "DOMAIN", scope, is_global=True)
                return (p or base) + extracted_suffix
            if src_kind == "github":
                return self._transform_owner_repo_slug(base, scope) + extracted_suffix
            if src_kind == "gitlab":
                parts = base.split("__")
                if parts[0].lower() == "gitlab.com" and len(parts) >= 3:
                    owner = self.register(parts[1], "ORG", scope, is_global=(len(parts[1]) >= 4)) or parts[1]
                    proj = self.register("__".join(parts[2:]), "PROJECT", scope, is_global=False) or "__".join(parts[2:])
                    return f"gitlab.com__{owner}__{proj}{extracted_suffix}"
            if src_kind == "catalog":
                p = self.register(base, "PROJECT", scope, is_global=False)
                if p:
                    return p + extracted_suffix

        # Replace registered entities inside nested folder names
        replaced = self.replace_text(base, scope, context="path_seg")
        if replaced != base:
            return self._sanitize_path_component(replaced) + extracted_suffix

        # If inside sources/existing/<subcollection>/<repo-like folder>, check owner__repo or identifying names
        if "__" in base:
            return self._transform_owner_repo_slug(base, scope) + extracted_suffix

        return seg

    def _transform_owner_repo_slug(self, slug: str, scope: str) -> str:
        parts = slug.split("__")
        if len(parts) >= 2:
            owner = parts[0]
            has_hash = len(parts) >= 3 and bool(re.fullmatch(r"[0-9a-f]{8,16}", parts[-1].lower()))
            repo_parts = parts[1:-1] if has_hash else parts[1:]
            repo = "__".join(repo_parts)
            owner_p = self.register(owner, "ORG", scope, is_global=(len(owner) >= 4)) or owner
            repo_p = self.register(repo, "PROJECT", scope, is_global=False) or repo
            owner_p = self._sanitize_path_component(owner_p)
            repo_p = self._sanitize_path_component(repo_p)
            if has_hash:
                return f"{owner_p}__{repo_p}__{parts[-1]}"
            return f"{owner_p}__{repo_p}"
        p = self.replace_text(slug, scope, context="path_seg")
        return self._sanitize_path_component(p)

    def _transform_filename(self, filename: str, scope: str) -> str:
        stem, ext = split_compound_extension(filename)
        if "__" in stem and scope.startswith("archives"):
            new_stem = self._transform_owner_repo_slug(stem, scope)
            return f"{self._sanitize_path_component(new_stem)}{ext}"
        # Models may identify an export by its filename, including its format suffix.
        first_suffix = "." + ext.split(".")[1] if ext else ""
        if first_suffix.lower() in PART_FILENAME_SUFFIXES:
            eid = self.variant_to_id.get(_norm_key(stem + first_suffix))
            if eid:
                entry = self.entities[eid]
                if entry.entity_type == "PART_ID" and (scope in entry.scopes or GLOBAL_SCOPE in entry.scopes):
                    return self._sanitize_path_component(entry.pseudonym) + ext
        new_stem = self.replace_text(stem, scope, context="filename")
        if new_stem == stem:
            return filename
        # Also catch identifying part-number prefixes like 810032-11-... or CRNHZMW_9442 ...
        new_stem = self._sanitize_path_component(new_stem)
        if not new_stem:
            new_stem = f"file-{hashlib.sha1(filename.encode('utf-8')).hexdigest()[:8]}"
        return f"{new_stem}{ext}"

    @staticmethod
    def _sanitize_path_component(name: str) -> str:
        name = name.replace("\\", "_").replace("/", "_").replace(":", "_").strip()
        name = re.sub(r"\s+", " ", name)
        return name

    def resolve_filename(self, filename: str, scope: str) -> str:
        low = filename.lower()
        sc_map = self.dir_basename_map.get(scope, {})
        if low in sc_map:
            return sc_map[low]
        if low in self.global_basename_map:
            return self.global_basename_map[low]
        return self._transform_filename(filename, scope)

    def replace_filename_references(self, text: str, scope: str) -> str:
        """Update references to renamed sibling/global CAD filenames inside CAD files."""
        sc_map = self.dir_basename_map.get(scope, {})
        if not sc_map and not self.global_basename_map:
            return text
        matchers = []
        if sc_map:
            matchers.append(self._filename_matcher(scope, sc_map))
        if self.global_basename_map:
            matchers.append(self._filename_matcher(GLOBAL_SCOPE, self.global_basename_map))
        return replace_tokens(text, matchers)

    def _filename_matcher(self, scope: str, mapping: dict[str, str]) -> TokenMatcher:
        if scope not in self._filename_matchers:
            changed = {k: v for k, v in mapping.items() if k != v.lower() and len(k) >= 4}
            self._filename_matchers[scope] = TokenMatcher(changed, filenames=True)
        return self._filename_matchers[scope]

    def get_raw_tokens_for_audit(self, scope: str | None = None) -> list[tuple[str, str]]:
        """Return (raw_variant, entity_type) pairs for independent leak auditing."""
        out: list[tuple[str, str]] = []
        for ent in self.entities.values():
            if scope is not None and GLOBAL_SCOPE not in ent.scopes and scope not in ent.scopes:
                continue
            for v in ent.variants:
                if len(v) >= 4 and not is_safe_engineering_token(v):
                    out.append((v, ent.entity_type))
        return out

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "counters": self.counters,
            "entities": [e.to_dict() for e in self.entities.values()],
            "path_map": self.path_map,
            "dir_basename_map": self.dir_basename_map,
            "global_basename_map": self.global_basename_map,
            "omitted_defects": self.omitted_defects,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> "IdentityRegistry":
        data = json.loads(path.read_text(encoding="utf-8"))
        reg = cls()
        reg.counters = {k: int(v) for k, v in data.get("counters", {}).items()}
        for ed in data.get("entities", []):
            ent = IdentityEntry.from_dict(ed)
            reg.entities[ent.entity_id] = ent
            for v in ent.variants:
                reg.variant_to_id[_norm_key(v)] = ent.entity_id
                reg.raw_to_id[v.lower()] = ent.entity_id
        reg.path_map = dict(data.get("path_map", {}))
        reg.dir_basename_map = {k: dict(v) for k, v in data.get("dir_basename_map", {}).items()}
        reg.global_basename_map = dict(data.get("global_basename_map", {}))
        reg.omitted_defects = list(data.get("omitted_defects", []))
        return reg
