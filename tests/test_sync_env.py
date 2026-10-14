from scripts.sync_env import sync


def test_adds_only_missing_keys_and_keeps_values(tmp_path):
    example = tmp_path / ".env.example"
    env = tmp_path / ".env"
    example.write_text("# senha do site\nAPP_PASSWORD=troque\n\n# VirusTotal\n# chave gratuita\nVIRUSTOTAL_API_KEY=\nURLSCAN_DAYS=90\n",
                       encoding="utf-8")
    env.write_text("APP_PASSWORD=minha-senha-real\n", encoding="utf-8")
    assert sync(env, example) == ["VIRUSTOTAL_API_KEY", "URLSCAN_DAYS"]
    text = env.read_text(encoding="utf-8")
    assert text.startswith("APP_PASSWORD=minha-senha-real\n")
    assert "# chave gratuita\nVIRUSTOTAL_API_KEY=" in text and "troque" not in text
    assert sync(env, example) == []  # segunda vez não muda nada


def test_creates_env_when_missing(tmp_path):
    (tmp_path / ".env.example").write_text("A=1\n", encoding="utf-8")
    assert sync(tmp_path / ".env", tmp_path / ".env.example")
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "A=1\n"


def test_notepad_bom_and_ansi_files_are_not_duplicated(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("APP_PASSWORD=troque\nCOMPANY_NAME=UXGUARD\nNOVA=1\n", encoding="utf-8")
    env = tmp_path / ".env"
    env.write_bytes(b"\xef\xbb\xbfAPP_PASSWORD=segredo\nCOMPANY_NAME=Seguran\xc3\xa7a\n")  # UTF-8 com BOM
    assert sync(env, example) == ["NOVA"]
    assert env.read_bytes().count(b"APP_PASSWORD") == 1 and env.read_bytes().startswith(b"\xef\xbb\xbf")
    env.write_bytes(b"APP_PASSWORD=segredo\nCOMPANY_NAME=Seguran\xe7a\n")  # ANSI (cp1252)
    assert sync(env, example) == ["NOVA"]
    assert "Segurança" in env.read_bytes().decode("cp1252")
