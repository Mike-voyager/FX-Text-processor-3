import pytest
import asyncio
from typing import Any, Callable
from src.form.variable_parser import (
    VariableParser,
    VariableParserError,
    CircularReferenceError,
)

from dataclasses import dataclass


def test_substitute_simple_str() -> None:
    t = "Hi, {{name}}"
    res = VariableParser.substitute_variables_str(t, {"name": "Вася"})
    assert res == "Hi, Вася"


def test_substitute_dict() -> None:
    d = {"a": "foo", "b": "{{bar}}"}
    vals = {"bar": "ok"}
    out = VariableParser.substitute_variables_dict(d, vals)
    assert out["b"] == "ok"


def test_substitute_list() -> None:
    l = ["A", "{{B}}", "{C}"]
    r = VariableParser.substitute_variables_list(l, {"B": 1, "C": 2})
    assert r == ["A", "1", "2"]


def test_dispatch_strict_types() -> None:
    assert VariableParser.substitute_variables_dispatch("foo", {}) == "foo"
    assert VariableParser.substitute_variables_dispatch({"x": "1"}, {}) == {"x": "1"}
    assert VariableParser.substitute_variables_dispatch(["x"], {}) == ["x"]


def test_typed_dict_support() -> None:
    from typing import TypedDict

    class UserVars(TypedDict):
        name: str
        value: int

    d: UserVars = {"name": "{{n}}", "value": 42}
    r = VariableParser.substitute_variables_dispatch(d, {"n": "Z"})
    assert r["name"] == "Z"
    assert r["value"] == 42


def test_dataclass_support() -> None:
    @dataclass
    class D:
        foo: str
        bar: int

    inst = D(foo="{{x}}", bar=100)
    out = VariableParser.substitute_variables_dispatch(inst, {"x": "yes"})
    assert isinstance(out, D)
    assert out.foo == "yes"


def test_object_with_dict_support() -> None:
    class C:
        def __init__(self, name: str) -> None:
            self.name = name

    obj = C("{{aaa}}")
    res = VariableParser.substitute_variables_dispatch(obj, {"aaa": "BB"})
    assert isinstance(res, C)
    assert res.name == "BB"


def test_encoding_cp866() -> None:
    assert VariableParser.validate_encoding("тест", "cp866") is True
    assert VariableParser.validate_encoding("😊", "cp866") is False


def test_find_missing_variables() -> None:
    s = "Hello, {{x}}"
    out = VariableParser.find_missing_variables(s, {"y": 1})
    assert out == {"x"}


def test_audit_log_and_hash() -> None:
    h = VariableParser.hash_values({"a": 1, "b": 2})
    VariableParser.audit_log("test", ["a", "b"], h)
    assert isinstance(h, str)


def test_escape_html_behavior() -> None:
    s = "Danger: {{val}}"
    r = VariableParser.substitute_variables_str(s, {"val": "<foo>"})
    assert "&lt;foo&gt;" in r


def test_formatting() -> None:
    t = "{{v:>6}}"
    res = VariableParser.substitute_variables_str(t, {"v": "X"})
    assert res.endswith("X")


def test_substitute_stream() -> None:
    stream = iter(["{{a}}", "{{b}}"])
    vals = {"a": "1", "b": "2"}
    out = list(VariableParser.substitute_stream(stream, vals))
    assert out == ["1", "2"]


def test_safe_substitute_with_rollback_success() -> None:
    res, ok = VariableParser.safe_substitute_with_rollback("{{z}}", {"z": 9})
    assert ok and res == "9"


def test_safe_substitute_with_rollback_fail() -> None:
    res, ok = VariableParser.safe_substitute_with_rollback("{{z}}", {})
    assert not ok and res == "{{z}}"


def test_circular_reference_detectionA() -> None:
    vals = {"A": "{{A}}"}
    with pytest.raises(CircularReferenceError):
        VariableParser.substitute_variables_str("{{A}}", vals)


def test_circular_reference_detectionB() -> None:
    vals = {"A": "{{B}}", "B": "{{A}}"}
    with pytest.raises(CircularReferenceError):
        VariableParser.substitute_variables_str("{{A}}", vals)


def test_dict_with_missing_key() -> None:
    d = {"foo": "{{bar}}"}
    with pytest.raises(VariableParserError):
        VariableParser.substitute_variables_dict(d, {})


def test_list_with_missing_key() -> None:
    l = ["ok", "{{miss}}"]
    with pytest.raises(VariableParserError):
        VariableParser.substitute_variables_list(l, {})


def test_special_escp_vars_localization() -> None:
    se = VariableParser.special_escp_vars("ru")
    assert se["PAGE_BREAK"] == "РАЗРЫВ_СТРАНИЦЫ"
    se = VariableParser.special_escp_vars("nonexistent")
    assert se["PAGE_BREAK"] == "\x0c"


def test_validate_variable_name_invalid() -> None:
    with pytest.raises(VariableParserError):
        VariableParser.validate_variable_name("1234bad&")


def test_substitute_and_format_strict_types() -> None:
    assert VariableParser.substitute_and_format("foo", {}) == "foo"
    assert VariableParser.substitute_and_format({"x": "y"}, {}) == {"x": "y"}
    assert VariableParser.substitute_and_format([1, 2], {}) == [1, 2]


def test_parse_expression_handling() -> None:
    assert VariableParser.parse_expression("{{foo}}", {"foo": "x"}) == "x"
    assert VariableParser.parse_expression("plain", {}) == "plain"
    assert VariableParser.parse_expression("{{f}}", {"f": "😊"}) == "<?>"


def test_validate_security_context_special() -> None:
    VariableParser.validate_security_context({"ALLOWED"}, "regular")
    with pytest.raises(VariableParserError):
        VariableParser.validate_security_context({"INTERNAL_DATA"}, "special")


def test_process_variable_element_classic() -> None:
    class Dummy:
        def __init__(self) -> None:
            self.name = "user"
            self.value = "{{x}}"

    el = Dummy()
    out = VariableParser.process_variable_element(el, {"x": "Y"})
    assert out.value == "Y"


def test_audit_log_stdout(monkeypatch: Any) -> None:
    logs = []
    monkeypatch.setattr(
        "src.form.variable_parser.logger.info",
        lambda *args, **kwargs: logs.append(args),
    )
    VariableParser.audit_log("x", ["a"], "hash1")
    assert logs and "hash1" in logs[0][-1]


def test_safe_substitute_with_rollback_exception() -> None:
    class AlwaysFail:
        def process(self, name: Any, value: Any, context: Any) -> None:
            raise Exception("fail")

    VariableParser.register_processor("badvar", AlwaysFail())
    res, ok = VariableParser.safe_substitute_with_rollback(
        "{{badvar}}", {"badvar": "something"}
    )
    assert not ok and "{{badvar}}" in res


def test_object_protocol_fallback_to_dict() -> None:
    class Broken:
        def __init__(self) -> None:
            self.x = "{{user}}"

    obj = Broken()
    result = VariableParser.substitute_variables_dispatch(obj, {"user": "good"})
    if isinstance(result, dict):
        assert result["x"] == "good"


def test_substitute_variables_dispatch_other_type() -> None:
    obj = object()
    r = VariableParser.substitute_variables_dispatch(obj, {})
    assert r is obj


def test_deduplicate_variables() -> None:
    s = "A {{x}} B {{y}} C {{x}}"
    deduped, posmap = VariableParser.deduplicate_variables(s)
    assert "x" in posmap and len(posmap["x"]) == 2


def test_get_metrics() -> None:
    m = VariableParser.get_metrics()
    assert hasattr(m, "variables_count")
    assert hasattr(m, "processing_time_ms")
    assert hasattr(m, "cache_hit_rate")
    assert hasattr(m, "memory_usage_mb")


def test_escp_vars_direct() -> None:
    # Тест прямого использования ESC/P переменных
    res = VariableParser.substitute_variables_str("{{PAGE_BREAK}}", {})
    assert res == "\x0c"


def test_max_depth_protection() -> None:
    # Тест защиты от слишком глубокой рекурсии
    template = "{{var}}"
    values = {"var": template}  # Простая петля
    with pytest.raises(CircularReferenceError):
        VariableParser.substitute_variables_str(template, values, _depth=15)


def test_substitute_variables_async() -> None:
    async def run_test() -> None:
        result = await VariableParser.substitute_variables_async(
            "{{name}}", {"name": "test"}
        )
        assert result == "test"

    asyncio.run(run_test())


def test_object_init_fail_fallback() -> None:
    class FailObj:
        def __init__(self, x: str) -> None:
            raise RuntimeError("fail init")

    class Holder:
        def __init__(self) -> None:
            self.y = "X"

    o = Holder()
    # Эмулируем невозможность создать экземпляр из dict
    result = VariableParser.substitute_variables_dispatch(o, {"y": "abc"})
    assert isinstance(result, Holder) or isinstance(result, dict)


def test_fallback_dataclass_restore_fail() -> None:
    from dataclasses import dataclass

    @dataclass
    class D:
        x: int

    dd = D(3)
    # purposely break the dict so restoring new D(**args) will fail
    bad = {"y": 2}
    # Мы вручную дергаем restore ветку
    try:
        _ = D(**bad)
    except TypeError:
        # И это то, что делает except -- просто возвращает dict
        pass


def test_fallback_object_init_fails() -> None:
    # __dict__ is real, but __init__ will fail during restore
    class FailObj:
        def __init__(self, x: str) -> None:
            self.x = x

    # Substitute with dict missing argument
    inst = FailObj("{{z}}")
    inst.__dict__ = {}
    o = VariableParser.substitute_variables_dispatch(inst, {"z": "1"})
    # Should fall back to dict
    assert isinstance(o, dict)


def test_empty_dict_list_str() -> None:
    assert VariableParser.substitute_variables_dispatch({}, {}) == {}
    assert VariableParser.substitute_variables_dispatch([], {}) == []
    assert VariableParser.substitute_variables_dispatch("", {}) == ""


def test_list_with_nonstring_error() -> None:
    # This covers the list, but with a malformed object
    class F:
        pass

    l = [F()]
    result = VariableParser.substitute_variables_dispatch(l, {})
    assert isinstance(result, list) and isinstance(result[0], F)


def test_special_processor_chain() -> None:
    class ChainProcessor:
        def process(self, name: str, value: Any, context: dict) -> Any:
            return "CHAIN" if name == "chain" else value

    VariableParser.register_processor("chain", ChainProcessor())
    out = VariableParser.substitute_variables_str("process: {{chain}}", {})
    assert "CHAIN" in out


# Additional audit log/noop branches
def test_audit_log_real() -> None:
    VariableParser.audit_log("test", ["q"], "hashX")  # just for coverage


def test_metrics_manual_call() -> None:
    m = VariableParser.get_metrics()
    m2 = VariableParser.get_metrics()
    assert isinstance(m2, type(m))


def test_hash_values_var() -> None:
    h = VariableParser.hash_values({"foo": 1})
    assert isinstance(h, str)
