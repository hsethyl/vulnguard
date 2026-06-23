from vulnguard.scanner.js_scanner import scan_js_source


def _rule_ids(source: str) -> set[str]:
    return {f.rule_id for f in scan_js_source(source, "f.js")}


def test_detects_inner_html():
    assert "JS001" in _rule_ids("el.innerHTML = userInput;")


def test_detects_document_write():
    assert "JS002" in _rule_ids("document.write(data);")


def test_detects_eval():
    assert "JS003" in _rule_ids("eval(code);")


def test_method_named_eval_not_flagged():
    # obj.eval(...) is a method call, not the global eval
    assert "JS003" not in _rule_ids("myParser.eval(code);")


def test_detects_new_function():
    assert "JS004" in _rule_ids("const f = new Function('return 1');")


def test_detects_child_process_exec():
    assert "JS005" in _rule_ids("child_process.exec('ls ' + dir);")


def test_detects_dangerously_set_inner_html():
    assert "JS006" in _rule_ids("<div dangerouslySetInnerHTML={{__html: x}} />")


def test_commented_line_not_flagged():
    assert "JS003" not in _rule_ids("// eval(code);")


def test_clean_js_no_findings():
    assert _rule_ids("const x = 1 + 2;") == set()
