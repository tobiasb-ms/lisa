# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from collections import namedtuple
import json

from assertpy import assert_that
from tempfile import TemporaryDirectory

from lisa import (
    Logger,
    Node,
    TestCaseMetadata,
    TestSuite,
    TestSuiteMetadata,
    simple_requirement,
)
from lisa.operating_system import CBLMariner
import lisa.tools
from lisa.tools import Cat, Curl, Echo, OpenSSL, Nproc, Rm
from lisa.util import LisaException, SkippedException, get_matched_str
from lisa.sut_orchestrator.azure.common import METADATA_ENDPOINT


def openssl_test_encrypt_decrypt(log: Logger, node: Node) -> None:
    # Key and IV for encryption and decryption.
    openssl = node.tools[lisa.tools.OpenSSL]
    key_hex = openssl.run("rand -hex 32", expected_exit_code=0).stdout.strip()
    iv_hex = openssl.run("rand -hex 16", expected_exit_code=0).stdout.strip()

    # Encrypt and decrypt some data to make sure it works.
    plaintext = "cool"
    encrypted_data = openssl.encrypt(plaintext, key_hex, iv_hex)
    decrypted_data = openssl.decrypt(encrypted_data, key_hex, iv_hex)
    assert_that(plaintext).is_equal_to(decrypted_data)

    log.debug("Sucessfully encrypted and decrypted a file.")


def openssl_test_sign_verify(log: Logger, node: Node) -> None:
    # Create a plaintext file that we can test with.

    # Create a private key and public key.
    openssl = node.tools[lisa.tools.OpenSSL]
    private_key, public_key = openssl.create_key_pair()

    # Sign and verify some data.
    plaintext = "cool"
    signature = openssl.sign(plaintext, private_key)
    openssl.verify(plaintext, public_key, signature)

    log.debug("Sucessfully signed and verified a file.")


def is_fips_enabled(node: Node) -> bool:
    # Check if the system is in FIPS mode.
    return (
        node.execute(
            "cat /proc/sys/crypto/fips_enabled", expected_exit_code=0, shell=True
        ).stdout.strip()
        == "1"
    )


def run_go_tests(log: Logger, node: Node) -> None:
    # TOBIASB

    node.os.install_packages(
        ["golang", "glibc-devel", "gcc", "binutils", "kernel-headers"]
    )

    # node.os.uninstall_packages(["SymCrypt", "SymCrypt-OpenSSL"])

    # log.debug(f"Test -json output: \n---\n{result.stdout}\n---")
    node.execute(
        "go clean -testcache",
        cwd="/usr/lib/golang/src",
        expected_exit_code=0,
        shell=True,
    )
    node.execute(
        "go test -short ./crypto/... -skip TestBoringFinalizers",
        cwd="/usr/lib/golang/src",
        update_envs={
            "GOOS": "linux",
            "CGO_ENABLED": "1",
            "GOEXPERIMENT": "systemcrypto",
        },
        expected_exit_code=0,
    )

    log.info("golang tests passed.")


@TestSuiteMetadata(
    area="security",
    category="functional",
    description="""
    Tests the functionality of OpenSSL.
    """,
)
class OpenSSL(TestSuite):
    # @staticmethod
    # def ensure_azl3(node: Node) -> None:
    #     // TODO: Assert that
    #     node.os.assert_release("2.0", "3.0")
    #     if node.os.information.release == "2.0":
    #         raise SkippedException("AZL2 is not supported.")

    @TestCaseMetadata(
        description="""
        Tests basic functionality of openssl.
        """,
        priority=2,
    )
    def verify_openssl_basic(self, log: Logger, node: Node) -> None:
        if isinstance(node.os, CBLMariner) and node.os.information.release == "3.0":
            node.os.install_packages(["SymCrypt", "SymCrypt-OpenSSL"])

        openssl_test_encrypt_decrypt(log, node)
        openssl_test_sign_verify(log, node)
        log.debug("OpenSSL basic functionality test passed.")

        if (
            isinstance(node.os, CBLMariner)
            and node.os.information.release == "3.0"
            and not is_fips_enabled(node)
        ):
            node.os.uninstall_packages(["SymCrypt", "SymCrypt-OpenSSL"])
            openssl_test_encrypt_decrypt(log, node)
            openssl_test_sign_verify(log, node)
            log.debug("OpenSSL basic functionality test passed without SymCrypt.")

    @TestCaseMetadata(
        description="""
        This test runs openssl speed, which will excercise much of of the functionality openssl provides.
        """,
        priority=2,
        requirement=simple_requirement(
            min_core_count=8,
        ),
    )
    def verify_openssl_speed(self, log: Logger, node: Node) -> None:
        if isinstance(node.os, CBLMariner) and node.os.information.release == "3.0":
            node.os.install_packages(["SymCrypt", "SymCrypt-OpenSSL"])

        # Run openssl speed test
        num_procs = node.tools[Nproc].get_num_procs()
        result = node.execute(
            f"openssl speed -seconds 1 -multi {num_procs}", expected_exit_code=0
        )
        assert_that(result.stderr).is_empty()

        log.debug("OpenSSL speed successfully ran.")

        if (
            isinstance(node.os, CBLMariner)
            and node.os.information.release == "3.0"
            and not is_fips_enabled(node)
        ):
            node.os.uninstall_packages(["SymCrypt", "SymCrypt-OpenSSL"])
            result = node.execute("openssl speed -seconds 1", expected_exit_code=0)
            assert_that(result.stderr).is_empty()
            log.debug("OpenSSL speed successfully ran without SymCrypt.")

    @TestCaseMetadata(
        description="""
        TOBIASB_DESC: Doing golang things.
        """,
        priority=2,
        requirement=simple_requirement(
            supported_os=[CBLMariner],
        ),
    )
    def verify_golang_tests(self, log: Logger, node: Node) -> None:
        node.os.install_packages(
            ["golang", "glibc-devel", "gcc", "binutils", "kernel-headers"]
        )
        if not is_fips_enabled(node):
            node.os.uninstall_packages(["SymCrypt", "SymCrypt-OpenSSL"])
            run_go_tests(log, node)
        # known_failures.extend(symcrypt_known_failures)
        node.os.install_packages(["SymCrypt", "SymCrypt-OpenSSL"])
        run_go_tests(log, node)

        return

    # @TestCaseMetadata(
    #     description="""
    #     This test case will
    #     1. Check whether FIPS can be enabled on the VM
    #     2. Enable FIPS
    #     3. Restart the VM for the changes to take effect
    #     4. Verify that FIPS was enabled properly
    #     """,
    #     priority=3,
    #     requirement=simple_requirement(
    #         supported_os=[CBLMariner],
    #     ),
    # )
    # def verify_openssl_providers_azl3(self, log: Logger, node: Node) -> None:
    #     log.debug("TOBIASB_DBG: verify_openssl_providers_azl3")
    #     # curl = node.tools[Curl]
    #     # thinger = curl.fetch(
    #     #     arg="--header Metadata:true --silent",
    #     #     execute_arg="",
    #     #     url=METADATA_ENDPOINT
    #     # )
    #     # log.debug(f"TOBIASB_DBG: thinger='{thinger}'")

    #     sku = OpenSSL.get_marketplace_image_sku(node)
    #     log.debug(f"TOBIASB_DBG: sku='{sku}'")
    #     OpenSSL.ensure_azl3(node)
