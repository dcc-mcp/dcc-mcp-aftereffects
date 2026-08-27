from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from dcc_mcp_aftereffects import install_io

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows identity semantics")


def _receipt_for(root: Path) -> dict[str, object]:
    files = install_io.file_manifest(root)
    return {
        "dcc_type": "aftereffects",
        "extension_path": str(root),
        "files": files,
        "manifest_sha256": install_io._manifest_digest(files),
    }


def _prior_transaction_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    destination = tmp_path / "CEP" / "dcc-mcp-aftereffects"
    staged = tmp_path / "CEP" / ".dcc-mcp-aftereffects.stage"
    receipt_path = tmp_path / "state" / "aftereffects.json"
    destination.mkdir(parents=True)
    staged.mkdir()
    (destination / "manifest.xml").write_bytes(b"prior\n")
    (staged / "manifest.xml").write_bytes(b"new\n")
    install_io.write_receipt(receipt_path, _receipt_for(destination))
    return staged, destination, receipt_path


def test_callback_rollback_preserves_replacement_of_committed_extension(
    tmp_path: Path,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    escaped_committed = tmp_path / "escaped-committed"
    foreign = b"foreign directory created after commit\n"
    attempted = False
    blocked = False

    def replace_new_then_fail(_path: Path, _receipt: object) -> None:
        nonlocal attempted, blocked
        attempted = True
        try:
            os.replace(destination, escaped_committed)
        except OSError as exc:
            assert install_io._locked_error(exc)
            blocked = True
        else:
            destination.mkdir()
            (destination / "foreign.txt").write_bytes(foreign)
        raise RuntimeError("reviewer callback failure")

    with pytest.raises(install_io.ReceiptCallbackError):
        install_io.commit_staged_install(
            staged=staged,
            destination=destination,
            receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
            receipt_path=receipt_path,
            receipt_writer=replace_new_then_fail,
        )

    assert (destination / "manifest.xml").read_bytes() == b"prior\n"
    assert attempted and blocked
    assert not escaped_committed.exists()
    assert not any(path.read_bytes() == foreign for path in tmp_path.rglob("foreign.txt"))


def test_committed_receipt_is_leased_before_post_publish_attestation(
    tmp_path: Path,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    escaped_receipt = tmp_path / "escaped-new-receipt.json"
    armed = False
    attempted = False
    blocked = False

    def writer(path: Path, receipt: object) -> None:
        nonlocal armed
        install_io.write_receipt(path, receipt)
        armed = True

    def attest() -> bool:
        nonlocal attempted, blocked
        if not armed or attempted or not receipt_path.exists():
            return True
        attempted = True
        try:
            os.replace(receipt_path, escaped_receipt)
        except OSError as exc:
            assert install_io._locked_error(exc)
            blocked = True
        return True

    transaction = install_io.commit_staged_install(
        staged=staged,
        destination=destination,
        receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
        receipt_path=receipt_path,
        receipt_writer=writer,
        identity_attestor=attest,
    )
    transaction.finalize()

    assert attempted and blocked
    assert not escaped_receipt.exists()


def test_post_publish_receipt_failure_rolls_back_without_a_swap(
    tmp_path: Path,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    escaped_receipt = tmp_path / "escaped-rollback-receipt.json"
    armed = False
    attempted = False
    blocked = False

    def writer(path: Path, receipt: object) -> None:
        nonlocal armed
        install_io.write_receipt(path, receipt)
        armed = True

    def attest() -> bool:
        nonlocal attempted, blocked
        if not armed or attempted or not receipt_path.exists():
            return True
        attempted = True
        try:
            os.replace(receipt_path, escaped_receipt)
        except OSError as exc:
            assert install_io._locked_error(exc)
            blocked = True
        return False

    with pytest.raises(install_io.IdentityAttestationError):
        install_io.commit_staged_install(
            staged=staged,
            destination=destination,
            receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
            receipt_path=receipt_path,
            receipt_writer=writer,
            identity_attestor=attest,
        )

    assert attempted and blocked
    assert not escaped_receipt.exists()
    assert (destination / "manifest.xml").read_bytes() == b"prior\n"


def test_finalize_holds_recovery_archive_lease_until_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    transaction = install_io.commit_staged_install(
        staged=staged,
        destination=destination,
        receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
        receipt_path=receipt_path,
    )
    escaped_archive = tmp_path / "escaped-recovery.zip"
    original_delete = install_io._delete_leased_tree
    attempted = False
    blocked = False

    def attempt_archive_swap(lease: object) -> dict[str, object]:
        nonlocal attempted, blocked
        archive = transaction.recovery_archive
        assert archive is not None and archive.exists()
        attempted = True
        try:
            os.replace(archive, escaped_archive)
        except OSError as exc:
            assert install_io._locked_error(exc)
            blocked = True
        return original_delete(lease)

    monkeypatch.setattr(install_io, "_delete_leased_tree", attempt_archive_swap)
    transaction.finalize()

    assert attempted and blocked
    assert not escaped_archive.exists()


def test_uninstall_holds_recovery_archive_lease_until_deletion(tmp_path: Path) -> None:
    destination = tmp_path / "CEP" / "dcc-mcp-aftereffects"
    receipt_path = tmp_path / "state" / "aftereffects.json"
    destination.mkdir(parents=True)
    (destination / "manifest.xml").write_bytes(b"installed\n")
    install_io.write_receipt(receipt_path, _receipt_for(destination))
    escaped_archive = tmp_path / "escaped-uninstall-recovery.zip"
    attempted = False
    blocked = False
    calls = 0

    def race() -> None:
        nonlocal attempted, blocked, calls
        calls += 1
        if calls != 3:
            return
        archives = list(destination.parent.glob(f".{destination.name}.recovery-*.zip"))
        assert len(archives) == 1
        attempted = True
        try:
            os.replace(archives[0], escaped_archive)
        except OSError as exc:
            assert install_io._locked_error(exc)
            blocked = True

    install_io.remove_receipted_install(
        destination,
        receipt_path,
        before_mutation=race,
    )

    assert attempted and blocked
    assert not escaped_archive.exists()
    assert not destination.exists()
    assert not receipt_path.exists()


def test_receipt_lease_rejects_a_hardlinked_object(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    alias_path = tmp_path / "receipt-hardlink.json"
    receipt_path.write_bytes(b"checked-receipt")
    os.link(receipt_path, alias_path)

    with pytest.raises(install_io.IdentityAttestationError, match="multiple links"):
        install_io._ExactObjectLease.acquire(receipt_path)

    assert receipt_path.read_bytes() == b"checked-receipt"
    assert alias_path.read_bytes() == b"checked-receipt"


def test_receipt_lease_fails_closed_while_a_writer_is_open(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(b"checked-receipt")

    with receipt_path.open("r+b"):
        with pytest.raises(OSError):
            install_io._ExactObjectLease.acquire(receipt_path)

    assert receipt_path.read_bytes() == b"checked-receipt"


def test_close_handle_failure_keeps_the_lease_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = install_io._ExactObjectLease(
        path=Path("C:/reviewer-object"),
        physical={},
        is_directory=False,
        native_handle=123,
    )
    monkeypatch.setattr(
        install_io,
        "_KERNEL32",
        SimpleNamespace(CloseHandle=lambda _handle: 0),
    )

    with pytest.raises(OSError):
        lease.close()
    assert lease.closed is False


def test_transaction_aggregates_close_failures_and_releases_other_leases(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class Lease:
        def __init__(self, name: str, *, fails: bool = False) -> None:
            self.name = name
            self.fails = fails

        def close(self) -> None:
            calls.append(self.name)
            if self.fails:
                raise OSError(f"{self.name} close failed")

    transaction = install_io.InstallTransaction(
        destination=tmp_path / "extension",
        backup=tmp_path / "backup",
        receipt_path=tmp_path / "receipt.json",
        old_receipt=None,
        old_receipt_valid=False,
    )
    failed = Lease("failed", fails=True)
    transaction.previous_extension_lease = failed  # type: ignore[assignment]
    transaction.previous_receipt_lease = Lease("released")  # type: ignore[assignment]

    with pytest.raises(install_io.RollbackError, match="lease cleanup failed"):
        transaction._release_exact_object_leases()

    assert calls == ["failed", "released"]
    assert transaction.previous_extension_lease is failed
    assert transaction.previous_receipt_lease is None
