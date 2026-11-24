"""SDK v2 (AC-403): both analyzers explicitly declare extraction protocol 2.0.

Core reads the declaration via
``attackmap.sdk.analyzer_contracts.declared_extraction_protocol``; an explicit
``EXTRACTION_PROTOCOL_VERSION`` attribute wins over the SDK default, so the
plugins keep declaring "2.0" even if they are imported under an older SDK.
Protocol-1.0 plugins are not broken by this: core's v1 -> v2 adapter
(``attackmap.extraction.adapters``) lifts their v1 ``ScanResult`` payloads
into the v2 ``ExtractionResult`` container losslessly, so they keep loading
indefinitely alongside 2.0-declared analyzers.
"""

from attackmap.sdk.analyzer_contracts import declared_extraction_protocol

from attackmap_analyzer_swift import ObjCAnalyzer, SwiftAnalyzer


def test_declares_extraction_protocol_2_0() -> None:
    for analyzer_cls in (SwiftAnalyzer, ObjCAnalyzer):
        assert analyzer_cls.EXTRACTION_PROTOCOL_VERSION == "2.0"
        assert declared_extraction_protocol(analyzer_cls) == "2.0"
        assert declared_extraction_protocol(analyzer_cls()) == "2.0"
