"""Keeps .vscode/settings.json's yaml.customTags in sync with template.yaml.

CloudFormation's short-form intrinsics (!Ref, !GetAtt, !Sub, !Join, ...) are not
standard YAML tags. The YAML language server flags every undeclared one as
"Unresolved tag", which buries any real template error under a wall of phantom
ones. This test fails if the template grows a tag the editor config doesn't
declare.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = ROOT / ".vscode" / "settings.json"
TEMPLATE = ROOT / "template.yaml"


def _declared_tags():
    settings = json.loads(SETTINGS.read_text())
    # Entries look like "!GetAtt sequence" — the tag is the first token.
    return {entry.split()[0] for entry in settings["yaml.customTags"]}


def _tags_used_in_template():
    # Short-form tags only ever appear as a value, i.e. after ": " or "- ".
    return set(re.findall(r"(?:^|[\s:\-\[,])(![A-Za-z][A-Za-z0-9]*)", TEMPLATE.read_text()))


def test_settings_file_is_valid_json():
    json.loads(SETTINGS.read_text())


def test_every_intrinsic_tag_used_in_the_template_is_declared():
    undeclared = _tags_used_in_template() - _declared_tags()
    assert not undeclared, (
        f"template.yaml uses {sorted(undeclared)} but .vscode/settings.json does "
        "not declare them in yaml.customTags — the editor will report them as "
        "'Unresolved tag'"
    )
