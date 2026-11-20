from backend.ufw_parse import parse_ufw_numbered


SAMPLE = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH management
[ 2] 80/tcp                     ALLOW IN    Anywhere
[ 3] 443/tcp                    ALLOW IN    192.168.1.0/24             # LAN HTTPS
[ 4] 8080/tcp                   DENY IN     10.0.0.5
not a rule line
[xx] garbage                    ALLOW IN    Anywhere
"""


def test_parses_numbered_rules_with_and_without_comments():
    rules = parse_ufw_numbered(SAMPLE)
    assert len(rules) == 4
    assert rules[0].number == 1
    assert rules[0].to == "22/tcp"
    assert rules[0].action == "ALLOW"
    assert rules[0].direction == "IN"
    assert rules[0].from_ == "Anywhere"
    assert rules[0].comment == "SSH management"
    assert rules[1].comment == ""
    assert rules[2].comment == "LAN HTTPS"
    assert rules[3].action == "DENY"
    assert rules[3].from_ == "10.0.0.5"


def test_skips_junk_lines():
    rules = parse_ufw_numbered("hello\n[ 9] 53/udp ALLOW IN Anywhere # DNS\n")
    assert len(rules) == 1
    assert rules[0].number == 9
