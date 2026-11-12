"""AI response parsing tests; no external API calls are made."""
from codeguardian.core.ai_reviewer import _parse_response, _prepare_diff
from codeguardian.models import DiffFile, Severity


def test_ai_parser_accepts_json_fenced_response():
    result = _parse_response("""```json
{"findings":[{"file":"app.py","line":4,"severity":"high","category":"security","title":"Injection","description":"Unsafe query"}],"summary":"One issue","risk_score":30}
```""")
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.HIGH
    assert result.risk_score == 30


def test_ai_parser_does_not_treat_malformed_response_as_clean():
    result = _parse_response("not json")
    assert result.findings == []
    assert result.risk_score == 100
    assert "manual review" in result.summary.lower()


def test_ai_parser_fails_closed_on_invalid_finding_and_score():
    result = _parse_response(
        '{"findings":[{"file":"","line":0,"severity":"bad","category":"bad","title":""}],'
        '"summary":"ok","risk_score":900}'
    )
    assert result.findings == []
    assert result.risk_score == 100
    assert "manual review" in result.summary.lower()


def test_ai_parser_fails_closed_when_required_fields_are_missing():
    result = _parse_response('{"findings":[]}')
    assert result.findings == []
    assert result.risk_score == 100
    assert "manual review" in result.summary.lower()


def test_ai_parser_fails_closed_on_non_object_finding():
    result = _parse_response(
        '{"findings":[null],"summary":"ok","risk_score":0}'
    )
    assert result.findings == []
    assert result.risk_score == 100
    assert "manual review" in result.summary.lower()


def test_ai_parser_rejects_unclosed_markdown_fence():
    result = _parse_response('```json\n{"findings":[],"summary":"clean","risk_score":0}')
    assert result.risk_score == 100
    assert "manual review" in result.summary.lower()


def test_prepare_diff_never_silently_truncates_input():
    result = _prepare_diff([DiffFile(path="large.py", raw_diff="x" * 100_001)])
    assert result is None
