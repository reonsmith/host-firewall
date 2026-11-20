from pathlib import Path

from backend.ufw_logs import parse_ufw_log_line, read_ufw_hits


SAMPLE = (
    "2026-11-16T13:34:13.474605+00:00 server kernel: [UFW BLOCK] IN=bond0 OUT= "
    "MAC=00:15:17:ae:a5:a8:04:f4:1c:37:1d:f7:0800 SRC=89.167.77.49 DST=192.168.1.5 "
    "LEN=99 TOS=0x00 PREC=0x00 TTL=43 ID=41160 DF PROTO=TCP SPT=443 DPT=48328 "
    "WINDOW=513 RES=0x00 ACK PSH URGP=0 "
)


def test_parse_block_line():
    hit = parse_ufw_log_line(SAMPLE)
    assert hit is not None
    assert hit.action == "BLOCK"
    assert hit.src == "89.167.77.49"
    assert hit.dst == "192.168.1.5"
    assert hit.dpt == "48328"
    assert hit.proto == "TCP"
    assert "89.167.77.49" in hit.summary


def test_read_ufw_hits_newest_first(tmp_path: Path):
    log = tmp_path / "ufw.log"
    log.write_text(
        SAMPLE.replace("48328", "1111") + "\n" + SAMPLE.replace("48328", "2222") + "\n",
        encoding="utf-8",
    )
    hits = read_ufw_hits([log], limit=10)
    assert len(hits) == 2
    assert hits[0].dpt == "2222"
    assert hits[1].dpt == "1111"
