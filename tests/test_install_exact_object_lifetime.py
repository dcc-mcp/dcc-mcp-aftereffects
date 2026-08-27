from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_install_lifecycle import BridgeRunner, healthy_dependencies, resolved_install

from dcc_mcp_aftereffects import install_io, install_service
from dcc_mcp_aftereffects.install_contract import EXIT_OK
from dcc_mcp_aftereffects.install_models import InstallRequest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows identity semantics")


class _PostCommitBoundaryFault(BaseException):
    pass


class _MarkerRunner(BridgeRunner):
    def __init__(self, marker: bytes) -> None:
        super().__init__()
        self.marker = marker

    def __call__(self, command: object, **kwargs: object):
        result = super().__call__(command, **kwargs)
        arguments = list(command)  # type: ignore[arg-type]
        destination = Path(arguments[arguments.index("--dest") + 1])
        (destination / "manifest.xml").write_bytes(self.marker)
        return result


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


def _round_trip_same_inode(path: Path) -> tuple[os.stat_result, os.stat_result]:
    original = path.read_bytes()
    before = path.stat()
    replacement = bytes(value ^ 0x5A for value in original)
    if replacement == original:
        replacement = b"x" * len(original)
    with path.open("r+b", buffering=0) as stream:
        stream.seek(0)
        stream.write(replacement)
        os.fsync(stream.fileno())
        stream.seek(0)
        stream.write(original)
        stream.truncate(len(original))
        os.fsync(stream.fileno())
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
    after = path.stat()
    assert (after.st_dev, after.st_ino, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
    )
    assert after.st_mtime_ns != before.st_mtime_ns
    assert path.read_bytes() == original
    return before, after


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


def test_recovery_archive_never_adopts_path_reuse_before_its_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "extension"
    source.mkdir()
    (source / "manifest.xml").write_bytes(b"owned payload\n")
    receipt = _receipt_for(source)
    archive_path = tmp_path / "recovery.zip"
    original_acquire = install_io._ExactObjectLease.acquire
    displaced: list[Path] = []
    returned_lease: install_io._ExactObjectLease | None = None

    def replace_before_acquire(
        cls: type[install_io._ExactObjectLease], path: Path
    ) -> install_io._ExactObjectLease:
        if path.name.endswith(".tmp"):
            contents = path.read_bytes()
            original = path.with_name(f"{path.name}.displaced")
            os.replace(path, original)
            path.write_bytes(contents)
            displaced.append(original)
        return original_acquire(path)

    monkeypatch.setattr(
        install_io._ExactObjectLease,
        "acquire",
        classmethod(replace_before_acquire),
    )
    try:
        with pytest.raises(install_io.IdentityAttestationError):
            returned_lease = install_io._write_recovery_archive(source, receipt, archive_path)
    finally:
        if returned_lease is not None and not returned_lease.closed:
            returned_lease.delete()
        for path in displaced:
            path.unlink(missing_ok=True)


def test_recovery_archive_cleanup_failure_preserves_validation_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "extension"
    source.mkdir()
    (source / "manifest.xml").write_bytes(b"owned payload\n")
    receipt = _receipt_for(source)
    primary = install_io.IdentityAttestationError(
        "primary recovery validation failure",
        stage="identity_attestation",
    )

    def fail_validation(*_args: object, **_kwargs: object) -> None:
        raise primary

    def fail_cleanup(_lease: install_io._ExactObjectLease) -> None:
        raise OSError("recovery archive cleanup failed")

    monkeypatch.setattr(install_io, "_validate_recovery_archive", fail_validation)
    monkeypatch.setattr(install_io._ExactObjectLease, "delete", fail_cleanup)

    with pytest.raises(
        install_io.IdentityAttestationError,
        match="primary recovery validation failure",
    ) as caught:
        install_io._write_recovery_archive(source, receipt, tmp_path / "recovery.zip")

    assert caught.value is primary
    assert getattr(caught.value, "cleanup_failures", ()) == ("recovery archive cleanup failed",)
    retained = getattr(caught.value, "retained_cleanup_leases", ())
    assert len(retained) == 1
    lease = retained[0]
    assert lease.closed is False
    lease.close()
    lease.path.unlink(missing_ok=True)


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


def test_uninstall_recovery_cleanup_preserves_identity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "CEP" / "dcc-mcp-aftereffects"
    receipt_path = tmp_path / "state" / "aftereffects.json"
    destination.mkdir(parents=True)
    (destination / "manifest.xml").write_bytes(b"installed\n")
    install_io.write_receipt(receipt_path, _receipt_for(destination))
    receipt_before = receipt_path.read_bytes()
    primary = install_io.IdentityAttestationError(
        "primary uninstall identity failure",
        stage="identity_attestation",
    )

    class RecoveryLease:
        def delete(self) -> None:
            raise OSError("recovery lease cleanup failed")

    recovery_lease = RecoveryLease()
    monkeypatch.setattr(
        install_io,
        "_write_recovery_archive",
        lambda *_args, **_kwargs: recovery_lease,
    )
    callbacks = 0

    def fail_after_recovery_capture() -> None:
        nonlocal callbacks
        callbacks += 1
        if callbacks == 3:
            raise primary

    with pytest.raises(
        install_io.IdentityAttestationError,
        match="primary uninstall identity failure",
    ) as caught:
        install_io.remove_receipted_install(
            destination,
            receipt_path,
            before_mutation=fail_after_recovery_capture,
        )

    assert caught.value is primary
    assert getattr(caught.value, "cleanup_failures", ()) == ("recovery lease cleanup failed",)
    assert getattr(caught.value, "retained_cleanup_leases", ()) == (recovery_lease,)
    assert (destination / "manifest.xml").read_bytes() == b"installed\n"
    assert receipt_path.read_bytes() == receipt_before


def test_uninstall_recovery_close_failure_never_replaces_delete_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "CEP" / "dcc-mcp-aftereffects"
    receipt_path = tmp_path / "state" / "aftereffects.json"
    destination.mkdir(parents=True)
    (destination / "manifest.xml").write_bytes(b"installed payload\n")
    receipt = _receipt_for(destination)
    install_io.write_receipt(receipt_path, receipt)
    receipt_before = receipt_path.read_bytes()

    seed_archive = tmp_path / "seed-recovery.zip"
    seed_lease = install_io._write_recovery_archive(destination, receipt, seed_archive)
    archive_bytes = seed_lease.read_bytes(maximum=272 * 1024 * 1024)
    seed_lease.delete()

    class RecoveryLease:
        def read_bytes(self, *, maximum: int) -> bytes:
            assert maximum >= len(archive_bytes)
            return archive_bytes

        def delete(self) -> None:
            raise OSError("primary recovery retirement failure")

        def close(self) -> None:
            raise OSError("secondary CloseHandle failure")

    recovery_lease = RecoveryLease()
    monkeypatch.setattr(
        install_io,
        "_write_recovery_archive",
        lambda *_args, **_kwargs: recovery_lease,
    )

    with pytest.raises(install_io.RestartRequired, match="cleanup failed") as caught:
        install_io.remove_receipted_install(destination, receipt_path)

    assert getattr(caught.value, "cleanup_failures", ()) == ("secondary CloseHandle failure",)
    assert getattr(caught.value, "retained_cleanup_leases", ()) == (recovery_lease,)
    assert (destination / "manifest.xml").read_bytes() == b"installed payload\n"
    assert receipt_path.read_bytes() == receipt_before


def test_receipt_lease_rejects_a_hardlinked_object(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    alias_path = tmp_path / "receipt-hardlink.json"
    receipt_path.write_bytes(b"checked-receipt")
    os.link(receipt_path, alias_path)

    with pytest.raises(install_io.IdentityAttestationError, match="multiple links"):
        install_io._ExactObjectLease.acquire(receipt_path)

    assert receipt_path.read_bytes() == b"checked-receipt"
    assert alias_path.read_bytes() == b"checked-receipt"


def test_payload_manifest_rejects_a_hardlinked_file(tmp_path: Path) -> None:
    external = tmp_path / "operator-owned.js"
    external.write_bytes(b"shared payload\n")
    payload = tmp_path / "staged"
    payload.mkdir()
    os.link(external, payload / "bridge.js")

    with pytest.raises(OSError, match="hardlink|multiple links|owned"):
        install_io.file_manifest(payload)

    assert external.read_bytes() == b"shared payload\n"


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


class _AuxiliaryUninstallAbort(BaseException):
    pass


@pytest.mark.parametrize("failure_type", [RuntimeError, _AuxiliaryUninstallAbort])
def test_uninstall_restores_prior_install_after_post_quarantine_callback_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    destination = tmp_path / "CEP" / "dcc-mcp-aftereffects"
    receipt_path = tmp_path / "state" / "aftereffects.json"
    destination.mkdir(parents=True)
    (destination / "manifest.xml").write_bytes(b"installed\n")
    install_io.write_receipt(receipt_path, _receipt_for(destination))
    receipt_before = receipt_path.read_bytes()
    original_archive = install_io._write_recovery_archive
    recovery_leases: list[install_io._ExactObjectLease] = []

    def capture_archive(*args: object, **kwargs: object) -> install_io._ExactObjectLease:
        lease = original_archive(*args, **kwargs)
        recovery_leases.append(lease)
        return lease

    failure = failure_type("post-quarantine callback failure")
    callbacks = 0

    def fail_after_quarantine_cleanup() -> None:
        nonlocal callbacks
        callbacks += 1
        if callbacks == 4:
            raise failure

    monkeypatch.setattr(install_io, "_write_recovery_archive", capture_archive)
    try:
        with pytest.raises(failure_type, match="post-quarantine callback failure") as caught:
            install_io.remove_receipted_install(
                destination,
                receipt_path,
                before_mutation=fail_after_quarantine_cleanup,
            )

        assert caught.value is failure
        assert (destination / "manifest.xml").read_bytes() == b"installed\n"
        assert receipt_path.read_bytes() == receipt_before
        assert not list(destination.parent.glob(f".{destination.name}.recovery-*.zip"))
        assert recovery_leases and all(lease.closed for lease in recovery_leases)
    finally:
        for lease in recovery_leases:
            if not lease.closed:
                lease.close()
            lease.path.unlink(missing_ok=True)


def test_rollback_preserves_restored_install_when_old_backup_path_is_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    original_rename = install_io._ExactObjectLease.rename
    replacement_path: Path | None = None

    def rename_and_reuse_old_path(
        lease: install_io._ExactObjectLease,
        target: Path,
        *,
        replace: bool = False,
    ) -> None:
        nonlocal replacement_path
        old_path = lease.path
        original_rename(lease, target, replace=replace)
        if old_path.name.startswith(f".{destination.name}.backup-") and target == destination:
            old_path.mkdir()
            (old_path / "foreign.txt").write_bytes(b"foreign replacement\n")
            replacement_path = old_path

    def fail_receipt_callback(_path: Path, _receipt: object) -> None:
        raise RuntimeError("force rollback")

    monkeypatch.setattr(install_io._ExactObjectLease, "rename", rename_and_reuse_old_path)

    with pytest.raises(install_io.ReceiptCallbackError):
        install_io.commit_staged_install(
            staged=staged,
            destination=destination,
            receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
            receipt_path=receipt_path,
            receipt_writer=fail_receipt_callback,
        )

    assert (destination / "manifest.xml").read_bytes() == b"prior\n"
    assert replacement_path is not None
    assert (replacement_path / "foreign.txt").read_bytes() == b"foreign replacement\n"


def test_receipt_publication_uses_a_transaction_owned_object_after_callback_replacement(
    tmp_path: Path,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    displaced = tmp_path / "displaced-callback-receipt.json"
    callback_identity: tuple[int, int] | None = None

    def replace_callback_output(path: Path, receipt: object) -> None:
        nonlocal callback_identity
        install_io.write_receipt(path, receipt)
        contents = path.read_bytes()
        os.replace(path, displaced)
        path.write_bytes(contents)
        details = path.stat()
        callback_identity = (int(details.st_dev), int(details.st_ino))

    transaction = install_io.commit_staged_install(
        staged=staged,
        destination=destination,
        receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
        receipt_path=receipt_path,
        receipt_writer=replace_callback_output,
    )
    try:
        published = receipt_path.stat()
        assert callback_identity is not None
        assert (int(published.st_dev), int(published.st_ino)) != callback_identity
    finally:
        transaction.finalize()


def test_callback_cleanup_never_reacquires_a_retired_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    original_delete = install_io._ExactObjectLease.delete
    replacement_path: Path | None = None
    callback_retired = False

    def delete_and_reuse_callback_path(lease: install_io._ExactObjectLease) -> None:
        nonlocal callback_retired, replacement_path
        retired_path = lease.path
        original_delete(lease)
        if ".callback-" in retired_path.name and not callback_retired:
            retired_path.write_bytes(b"foreign replacement\n")
            replacement_path = retired_path
            callback_retired = True

    monkeypatch.setattr(
        install_io._ExactObjectLease,
        "delete",
        delete_and_reuse_callback_path,
    )

    transaction = install_io.commit_staged_install(
        staged=staged,
        destination=destination,
        receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
        receipt_path=receipt_path,
    )
    try:
        assert replacement_path is not None
        assert replacement_path.read_bytes() == b"foreign replacement\n"
    finally:
        transaction.finalize()


def test_receipt_callback_cannot_swap_a_same_bytes_payload_child(tmp_path: Path) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    swapped = False

    def swap_child_then_write(path: Path, receipt: object) -> None:
        nonlocal swapped
        child = destination / "manifest.xml"
        before = child.stat()
        replacement = destination / ".replacement.tmp"
        replacement.write_bytes(child.read_bytes())
        os.replace(replacement, child)
        after = child.stat()
        swapped = (int(before.st_dev), int(before.st_ino)) != (
            int(after.st_dev),
            int(after.st_ino),
        )
        install_io.write_receipt(path, receipt)

    with pytest.raises(install_io.IdentityAttestationError):
        install_io.commit_staged_install(
            staged=staged,
            destination=destination,
            receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
            receipt_path=receipt_path,
            receipt_writer=swap_child_then_write,
        )

    assert swapped
    assert (destination / "manifest.xml").read_bytes() == b"prior\n"


def test_receipt_callback_cannot_rewrite_the_canonical_payload_snapshot(
    tmp_path: Path,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)

    def rewrite_child_and_manifest(path: Path, receipt: object) -> None:
        assert isinstance(receipt, dict)
        (destination / "manifest.xml").write_bytes(b"bad\n")
        replacement_manifest = install_io.file_manifest(destination)
        receipt["files"][:] = replacement_manifest
        receipt["manifest_sha256"] = install_io._manifest_digest(replacement_manifest)
        install_io.write_receipt(path, receipt)

    with pytest.raises(install_io.IdentityAttestationError):
        install_io.commit_staged_install(
            staged=staged,
            destination=destination,
            receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
            receipt_path=receipt_path,
            receipt_writer=rewrite_child_and_manifest,
        )

    assert (destination / "manifest.xml").read_bytes() == b"prior\n"


def test_finalize_rejects_a_post_commit_same_bytes_payload_child_swap(tmp_path: Path) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    transaction = install_io.commit_staged_install(
        staged=staged,
        destination=destination,
        receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
        receipt_path=receipt_path,
    )
    child = destination / "manifest.xml"
    replacement = destination / ".replacement.tmp"
    replacement.write_bytes(child.read_bytes())
    os.replace(replacement, child)

    with pytest.raises(install_io.IdentityAttestationError):
        transaction.finalize()
    transaction.rollback()

    assert (destination / "manifest.xml").read_bytes() == b"prior\n"


def test_finalize_rejects_same_inode_round_trip_payload_drift(tmp_path: Path) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    transaction = install_io.commit_staged_install(
        staged=staged,
        destination=destination,
        receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
        receipt_path=receipt_path,
    )
    _round_trip_same_inode(destination / "manifest.xml")

    with pytest.raises(install_io.IdentityAttestationError):
        transaction.finalize()
    transaction.rollback()

    assert (destination / "manifest.xml").read_bytes() == b"prior\n"


def test_install_rejects_callback_round_trip_payload_drift(tmp_path: Path) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(_MarkerRunner(b"new-install\n"))

    def mutate_then_write_receipt(path: Path, receipt: object) -> None:
        _round_trip_same_inode(resolved.extension_path / "manifest.xml")
        install_io.write_receipt(path, receipt)  # type: ignore[arg-type]

    dependencies.receipt_writer = mutate_then_write_receipt
    report, exit_code = install_service.run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code != EXIT_OK, report
    assert report["status"] == "failed"
    assert report["verify"]["failure_stage"] == "identity_attestation"
    assert not resolved.extension_path.exists()
    assert not resolved.receipt_path.exists()


def test_service_never_path_cleans_a_retired_staging_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = resolved_install(tmp_path)
    dependencies = healthy_dependencies(BridgeRunner())
    original_commit = install_service.commit_staged_install
    replacement_path: Path | None = None

    def commit_then_reuse_staging(*args: object, **kwargs: object):
        nonlocal replacement_path
        transaction = original_commit(*args, **kwargs)
        retired_path = Path(kwargs["staged"])
        retired_path.mkdir()
        (retired_path / "foreign.txt").write_bytes(b"foreign replacement\n")
        replacement_path = retired_path
        return transaction

    monkeypatch.setattr(install_service, "commit_staged_install", commit_then_reuse_staging)

    report, exit_code = install_service.run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code == EXIT_OK, report
    assert replacement_path is not None
    assert (replacement_path / "foreign.txt").read_bytes() == b"foreign replacement\n"


@pytest.mark.parametrize("failure_type", [RuntimeError, _PostCommitBoundaryFault])
def test_post_commit_import_failure_restores_the_exact_prior_install(
    tmp_path: Path,
    failure_type: type[BaseException],
) -> None:
    resolved = resolved_install(tmp_path)
    first_report, first_exit = install_service.run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(_MarkerRunner(b"prior-install\n")),
    )
    assert first_exit == EXIT_OK, first_report
    receipt_before = resolved.receipt_path.read_bytes()
    failure = failure_type("post-commit import callback failure")
    upgrade_dependencies = healthy_dependencies(_MarkerRunner(b"replacement-install\n"))
    upgrade_dependencies.import_probe = lambda _python: (_ for _ in ()).throw(failure)

    if issubclass(failure_type, Exception):
        report, exit_code = install_service.run_lifecycle(
            InstallRequest("upgrade", as_json=True, yes=True),
            resolved=resolved,
            dependencies=upgrade_dependencies,
        )
        assert exit_code != EXIT_OK, report
    else:
        with pytest.raises(failure_type) as caught:
            install_service.run_lifecycle(
                InstallRequest("upgrade", as_json=True, yes=True),
                resolved=resolved,
                dependencies=upgrade_dependencies,
            )
        assert caught.value is failure

    assert (resolved.extension_path / "manifest.xml").read_bytes() == b"prior-install\n"
    assert resolved.receipt_path.read_bytes() == receipt_before
    assert not any(resolved.extension_path.parent.glob(".dcc-mcp-aftereffects.backup-*"))
    assert not any(resolved.extension_path.parent.glob(".dcc-mcp-aftereffects.failed-*"))
    assert not any(resolved.extension_path.parent.glob(".dcc-mcp-aftereffects.recovery-*.zip"))


def test_post_commit_import_failure_classifies_rollback_failure_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = resolved_install(tmp_path)
    first_report, first_exit = install_service.run_lifecycle(
        InstallRequest("install", as_json=True, yes=True),
        resolved=resolved,
        dependencies=healthy_dependencies(_MarkerRunner(b"prior-install\n")),
    )
    assert first_exit == EXIT_OK, first_report
    failure = RuntimeError("post-commit import callback failure")
    dependencies = healthy_dependencies(_MarkerRunner(b"replacement-install\n"))
    dependencies.import_probe = lambda _python: (_ for _ in ()).throw(failure)

    def fail_rollback(_transaction: install_io.InstallTransaction) -> None:
        raise OSError("simulated rollback failure")

    monkeypatch.setattr(install_io.InstallTransaction, "rollback", fail_rollback)

    report, exit_code = install_service.run_lifecycle(
        InstallRequest("upgrade", as_json=True, yes=True),
        resolved=resolved,
        dependencies=dependencies,
    )

    assert exit_code != EXIT_OK
    assert report["verify"]["error_type"] == "runtime_error"
    assert report["rollback_failed"] is True
    assert "previous_install_restored" not in report


def test_acquisition_cleanup_preserves_primary_error_when_lease_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged, destination, receipt_path = _prior_transaction_paths(tmp_path)
    primary = RuntimeError("primary receipt acquisition failure")
    acquisitions = 0

    class FailingCloseLease:
        def close(self) -> None:
            raise OSError("CloseHandle failed during acquisition cleanup")

    def acquire(_path: Path) -> FailingCloseLease:
        nonlocal acquisitions
        acquisitions += 1
        if acquisitions == 1:
            return FailingCloseLease()
        raise primary

    monkeypatch.setattr(install_io._ExactObjectLease, "acquire", acquire)

    with pytest.raises(RuntimeError, match="primary receipt acquisition failure") as caught:
        install_io.commit_staged_install(
            staged=staged,
            destination=destination,
            receipt={"dcc_type": "aftereffects", "extension_path": str(destination)},
            receipt_path=receipt_path,
        )

    assert caught.value is primary
    assert getattr(caught.value, "cleanup_failures", ()) == (
        "CloseHandle failed during acquisition cleanup",
    )


def test_identity_path_guard_reports_close_handle_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked = tmp_path / "checked.json"
    checked.write_bytes(b"checked")

    class Function:
        def __init__(self, result: int) -> None:
            self.result = result
            self.argtypes = None
            self.restype = None

        def __call__(self, *_args: object) -> int:
            return self.result

    class Kernel32:
        CreateFileW = Function(123)
        CloseHandle = Function(0)

    monkeypatch.setattr(install_io.ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel32())

    with pytest.raises(OSError, match="ownership is indeterminate") as caught:
        with install_io._hold_identity_paths((checked,)):
            pass

    assert getattr(caught.value, "open_native_handles", ()) == (123,)


def test_posix_identity_path_cleanup_preserves_the_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked = tmp_path / "checked.json"
    checked.write_bytes(b"checked")
    primary = RuntimeError("primary transaction failure")

    def fail_close(descriptor: int) -> None:
        assert descriptor == 73
        raise OSError("descriptor close failed")

    monkeypatch.setattr(
        install_io,
        "os",
        SimpleNamespace(
            name="posix",
            path=os.path,
            O_RDONLY=os.O_RDONLY,
            open=lambda _path, _flags: 73,
            close=fail_close,
        ),
    )

    with pytest.raises(RuntimeError, match="primary transaction failure") as caught:
        with install_io._hold_identity_paths((checked,)):
            raise primary

    assert caught.value is primary
    assert getattr(caught.value, "cleanup_failures", ()) == ("descriptor close failed",)
    assert getattr(caught.value, "open_file_descriptors", ()) == (73,)
    assert getattr(caught.value, "retained_native_handles", ()) == ()


@pytest.mark.parametrize(
    ("failure_mode", "expected_error"),
    [
        ("information", OSError),
        ("reparse", install_io.IdentityAttestationError),
        ("hardlink", install_io.IdentityAttestationError),
    ],
)
def test_exact_object_acquisition_records_close_failure_on_validation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
    expected_error: type[BaseException],
) -> None:
    checked = tmp_path / "checked.json"
    checked.write_bytes(b"checked")

    def get_information(_handle: object, pointer: object) -> int:
        if failure_mode == "information":
            return 0
        information = pointer._obj  # type: ignore[attr-defined]
        information.attributes = 0x400 if failure_mode == "reparse" else 0
        information.links = 2 if failure_mode == "hardlink" else 1
        return 1

    kernel32 = SimpleNamespace(
        CreateFileW=lambda *_args: 123,
        GetFileInformationByHandle=get_information,
        CloseHandle=lambda _handle: 0,
    )
    monkeypatch.setattr(install_io, "_KERNEL32", kernel32)

    with pytest.raises(expected_error) as caught:
        install_io._ExactObjectLease.acquire(checked)

    assert getattr(caught.value, "cleanup_failures", ())
    assert getattr(caught.value, "open_native_handles", ()) == (123,)
