"""Framework mapping completeness/attachment + operational skill manifests are well-formed."""


from knowledge_base.index import KnowledgeBase, repo_root
from vuln_search.catalog import load_catalog
from vuln_search.mapping import FRAMEWORK_MAP, label, mapping_for
from vuln_search.search import VulnSearch

CATALOG = repo_root() / "vuln_search" / "catalog"
SKILLS = repo_root() / "ai_framework" / "skills"


def _catalog_slugs() -> set[str]:
    return {p.parent.name for p in CATALOG.glob("*/README.md")}


# ── mapping ──
def test_every_catalog_slug_is_mapped_with_a_cwe():
    slugs = _catalog_slugs()
    assert slugs, "expected catalog dirs"
    missing = [s for s in slugs if not FRAMEWORK_MAP.get(s, {}).get("cwe")]
    assert not missing, f"catalog slugs missing a CWE mapping: {missing}"


def test_no_stray_mappings():
    # Every mapped slug corresponds to a real catalog entry (no drift/typos).
    assert set(FRAMEWORK_MAP) <= _catalog_slugs()


def test_mapping_shape_and_label():
    m = mapping_for("sql_injection")
    assert m["cwe"] == ["CWE-89"] and "A03:2021" in m["owasp"] and "T1190" in m["attack"]
    lbl = label("sql_injection")
    assert "CWE-89" in lbl and "ATT&CK T1190" in lbl and "WSTG-INPV-05" in lbl


def test_unmapped_slug_returns_shaped_empty():
    m = mapping_for("does-not-exist")
    assert m == {"cwe": [], "owasp": "", "attack": [], "wstg": []}


def test_vuln_search_attaches_mapping_to_candidates():
    kb = KnowledgeBase(CATALOG).index()
    vs = VulnSearch(catalog=load_catalog(kb))
    res = vs.search("sql injection")
    top = res.techniques[0]
    assert top.slug == "sql_injection"
    assert top.mapping["cwe"] == ["CWE-89"]


# ── skills ──
REQUIRED_FRONT = {"name", "description", "domain", "tags", "owasp", "catalog"}


def _frontmatter(md: str) -> dict[str, str]:
    """Parse the leading --- fenced key: value block (no yaml dependency)."""
    if not md.startswith("---"):
        return {}
    end = md.index("\n---", 3)
    out: dict[str, str] = {}
    for line in md[3:end].splitlines():
        if line and not line[0].isspace() and ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def test_all_skill_manifests_have_required_frontmatter():
    manifests = list(SKILLS.glob("*/SKILL.md"))
    assert len(manifests) >= 11, "expected the operational skill set"
    for m in manifests:
        front = _frontmatter(m.read_text(encoding="utf-8"))
        missing = REQUIRED_FRONT - set(front)
        assert not missing, f"{m.parent.name} missing {missing}"


def test_skill_catalog_links_resolve():
    for m in SKILLS.glob("*/SKILL.md"):
        front = _frontmatter(m.read_text(encoding="utf-8"))
        catalog_rel = front["catalog"]
        assert (m.parent / catalog_rel).resolve().is_file(), f"{m.parent.name}: bad catalog link"


def test_core_operational_skills_present():
    names = {p.parent.name for p in SKILLS.glob("*/SKILL.md")}
    assert {"exploiting-xss", "exploiting-ssrf", "attacking-jwt", "exploiting-idor",
            "exploiting-command-injection"} <= names
