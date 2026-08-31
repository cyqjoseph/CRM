"""The shared layer has to be importable inside Lambda.

Every API function does `from crm_common import ...` at module scope, so a broken
layer artifact fails the function during init. API Gateway turns that into a bare
502 Bad Gateway with no CORS headers, so the browser reports a CORS error and the
real ImportError is only visible in CloudWatch. That makes layer packaging worth
asserting on rather than discovering in production.

A Python layer is only importable if the zip root contains `python/`. SAM
packages a LayerVersion's ContentUri verbatim, which produces exactly that.
Adding `Metadata: BuildMethod: <python runtime>` instead routes the layer through
SAM's pip builder, which expects a requirements.txt manifest at the ContentUri
root. This layer has no third-party dependencies, so that step buys nothing and
its behaviour without a manifest varies by SAM version.
"""
from pathlib import Path

from test_template import RESOURCES

ROOT = Path(__file__).resolve().parent.parent
LAYER = RESOURCES["CommonLayer"]
CONTENT_URI = LAYER["Properties"]["ContentUri"]


def test_layer_content_has_the_python_prefix_lambda_requires():
    content_root = ROOT / CONTENT_URI
    assert content_root.is_dir(), f"{CONTENT_URI} does not exist"
    assert (content_root / "python").is_dir(), (
        f"{CONTENT_URI} has no python/ directory — a Python layer is only "
        "importable when the zip root contains python/"
    )
    assert (content_root / "python" / "crm_common" / "__init__.py").is_file()


def test_build_method_is_only_declared_when_there_is_a_manifest_to_build():
    build_method = (LAYER.get("Metadata") or {}).get("BuildMethod")
    if build_method is None:
        return  # Packaged verbatim — nothing to reconcile.

    assert isinstance(build_method, str)
    if build_method.startswith("python"):
        manifest = ROOT / CONTENT_URI / "requirements.txt"
        assert manifest.is_file(), (
            f"CommonLayer declares Metadata.BuildMethod: {build_method}, which "
            f"routes it through SAM's pip builder, but {CONTENT_URI}"
            "requirements.txt does not exist. Either add the manifest or drop "
            "BuildMethod so SAM packages ContentUri verbatim."
        )


def test_layer_runtime_matches_the_functions_runtime():
    from test_template import TEMPLATE

    function_runtime = TEMPLATE["Globals"]["Function"]["Runtime"]
    assert function_runtime in LAYER["Properties"]["CompatibleRuntimes"], (
        f"functions run on {function_runtime} but the layer does not list it as "
        "compatible — Lambda refuses to attach it"
    )
