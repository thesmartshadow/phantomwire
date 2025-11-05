from pathlib import Path

import pytest

from phantomwire.net import pcap


def test_sessionize_without_dpkt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pcap, "maybe_import", lambda name: None)
    data = (0xA1B2C3D4).to_bytes(4, "little") + b"\x00" * 20
    path = tmp_path / "sample.pcap"
    path.write_bytes(data)
    evidence = pcap.sessionize(path)
    assert evidence.kind == "pcap.header"
    assert "magic_number" in evidence.data


def test_sessionize_with_dpkt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeReader:
        def __init__(self, fh):
            self._records = [(0.0, b"\x00" * 64)]

        def __iter__(self):
            return iter(self._records)

    from types import SimpleNamespace

    class FakeTCP:
        sport = 21
        dport = 1025
        data = b"USER test"

    class FakeIP:
        def __init__(self) -> None:
            self.p = 6
            self.src = b"\x7f\x00\x00\x01"
            self.dst = b"\x7f\x00\x00\x01"
            self.data = FakeTCP()

    class FakeEthernet:
        def __init__(self, buf: bytes) -> None:
            self.data = FakeIP()

    fake_module = SimpleNamespace(
        ethernet=SimpleNamespace(Ethernet=FakeEthernet),
        ip=SimpleNamespace(IP_PROTO_TCP=6, IP_PROTO_UDP=17),
        utils=SimpleNamespace(inet_to_str=lambda addr: "127.0.0.1"),
        pcap=SimpleNamespace(Reader=FakeReader),
    )

    monkeypatch.setattr(pcap, "maybe_import", lambda name: fake_module)
    path = tmp_path / "sample.pcap"
    path.write_bytes(b"pcap data")
    result = pcap.sessionize(path)
    assert isinstance(result, list)
    assert any(f.id == "PCAP-N-001" for f in result)
