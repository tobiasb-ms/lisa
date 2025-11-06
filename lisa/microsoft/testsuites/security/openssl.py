# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from typing import cast

from assertpy import assert_that

from lisa import (
    Logger,
    Node,
    TestCaseMetadata,
    TestSuite,
    TestSuiteMetadata,
    simple_requirement,
)
from lisa.operating_system import CBLMariner, Posix
from lisa.tools import Git, OpenSSL
from lisa.util import SkippedException


@TestSuiteMetadata(
    area="security",
    category="functional",
    description="""
    Tests the functionality of OpenSSL, including encryption and decryption
    operations. Validates that OpenSSL can successfully encrypt plaintext data
    and decrypt it back to its original form using generated keys and IVs.
    Validates that OpenSSL signs and verifies signatures correctly.
    """,
)
class OpenSSLTestSuite(TestSuite):
    """
    Test suite for OpenSSL functionality.
    """

    @TestCaseMetadata(
        description="""
        Verifies basic OpenSSL encryption and decryption behavior by generating
        a random key and IV, encrypting various types of plaintext, and
        decrypting them back to their original form.
        """,
        priority=2,
    )
    def verify_openssl_basic(self, log: Logger, node: Node) -> None:
        """This function tests the basic functionality of
        OpenSSL by calling helper functions"""
        node.tools[OpenSSL].tobiasb_dump_providers()
        self._openssl_test_encrypt_decrypt(log, node)
        self._openssl_test_sign_verify(log, node)

    @TestCaseMetadata(
        description="""
        This test will use Go experimental system crypto tests
        """,
        priority=3,
        requirement=simple_requirement(
            supported_os=[CBLMariner],
        ),
    )
    def verify_golang_sys_crypto(self, node: Node) -> None:
        """
        This test sets up the dependencies to run the
        experimental Go system crypto tests and cleans go builds.
        """
        if float(node.os.information.release) < 3.0:
            raise SkippedException(
                "Go system crypto tests are only supported on CBLMariner 3.0. or later"
            )
        node.tools[OpenSSL].tobiasb_dump_providers()
        # installs go dependencies for tests
        posix_os = cast(Posix, node.os)
        posix_os.install_packages(
            ["golang", "glibc-devel", "gcc", "binutils", "kernel-headers"]
        )
        # cleans up previous go builds
        node.execute(
            "go clean -testcache",
            cwd=node.get_pure_path("/usr/lib/golang/src"),
            expected_exit_code=0,
            expected_exit_code_failure_message=("Go clean up failed."),
            shell=True,
        )
        node.execute(
            "go test -short ./crypto/...",
            cwd=node.get_pure_path("/usr/lib/golang/src"),
            update_envs={
                "GOEXPERIMENT": "systemcrypto",
            },
            expected_exit_code=0,
            expected_exit_code_failure_message=(
                "Setting up Go system crypto environment failed."
            ),
        )

    @TestCaseMetadata(
        description="""
        This test will first Run OpenSSL speed test
        that measures the performance of cryptographic
        functions. The parameter `sec` is set to 1 second
        to ensure that the test runs for a short duration
        and test avoids timeout.
        """,
        priority=2,
        timeout=3600,  # 1 hour
    )
    def verify_openssl_speed_test(self, node: Node) -> None:
        """This function runs OpenSSL speed test to measure the
        performance of cryptographic operations.

        "sec=1" sets the duration of every
        cryptographic operation to 1 second by default,
        this ensures that the many operations that openssl
        speed measures complete in a reasonable time frame.
        """

        node.tools[OpenSSL].tobiasb_dump_providers()
        node.tools[OpenSSL].speed(sec=1)

    @TestCaseMetadata(
        description="""
        Run dotnet crypto tests.
        """,
        priority=3,
        timeout=3600,  # 1 hour
        requirement=simple_requirement(
            supported_os=[CBLMariner],
            min_core_count=16,
            min_memory_mb=64 * 1024,  # 64 GB
        ),
    )
    def tobiasb_verify_dotnet_crypto(self, node: Node) -> None:
        """
        Runs dotnet crypto tests.
        Based on https://gist.github.com/vcsjones/6c0bddcc6bbe721a5f43673359552f67
        """
        if float(node.os.information.release) < 3.0:
            raise SkippedException(
                "Dotnet system crypto tests are only supported on CBLMariner 3.0. or later"
            )

        node.tools[OpenSSL].tobiasb_dump_providers()
        # installs dotnet crypto dependencies for tests
        posix_os = cast(Posix, node.os)
        # git installed via tool
        posix_os.install_packages(
            [
                "ca-certificates",
                "ninja-build",
                "tar",
                "awk",
                "curl",
                "cmake",
                "make",
                "g++",
                "glibc-devel",
                "gcc",
                "gcc-c++",
                "kernel-headers",
            ]
        )

        # Get the runtime repo.
        work_dir = node.get_working_path_with_required_space(required_size_in_gb=3)
        work_dir_path = node.get_pure_path(work_dir)
        runtime_code_path = node.tools[Git].clone(
            "https://github.com/dotnet/runtime.git", work_dir_path
        )

        # Get dependencies
        node.execute(
            "./eng/common/native/install-dependencies.sh",
            cwd=runtime_code_path,
            sudo=True,
            expected_exit_code=0,
            expected_exit_code_failure_message=(
                "Failed to get dotnet runtime build dependencies."
            ),
        )

        # Build the runtime
        node.execute(
            "./build.sh -rc release -s clr+libs /p:FullAssemblySigningSupported=false",
            cwd=runtime_code_path,
            expected_exit_code=0,
            expected_exit_code_failure_message=("Failed to build dotnet runtime."),
            timeout=3600,  # 1 hour
        )

        # Core Crypto Tests
        node.execute(
            "./dotnet.sh test src/libraries/System.Security.Cryptography/tests /p:FullAssemblySigningSupported=false",
            cwd=runtime_code_path,
            expected_exit_code=0,
            expected_exit_code_failure_message=("Dotnet core crypto tests failed."),
        )

        # Networking/TLS tests.
        node.execute(
            "./dotnet.sh test src/libraries/System.Net.Security/tests/FunctionalTests /p:FullAssemblySigningSupported=false",
            cwd=runtime_code_path,
            expected_exit_code=0,
            expected_exit_code_failure_message=("Dotnet networking/TLS tests failed."),
        )

    def _openssl_test_encrypt_decrypt(self, log: Logger, node: Node) -> None:
        """
        Tests OpenSSL encryption and decryption functionality.
        This function generates a random key and IV, encrypts various types of
        plaintext, and then decrypts them to verify the functionality.
        """

        # Key and IV for encryption and decryption.
        openssl = node.tools[OpenSSL]
        key_hex = openssl.run(
            "rand -hex 32",
            expected_exit_code=0,
        ).stdout.strip()
        iv_hex = openssl.run(
            "rand -hex 16",
            expected_exit_code=0,
        ).stdout.strip()
        # Test with different data types and sizes
        test_data = [
            "cool",  # Short string
            "A" * 1024,  # Longer string
            "Special chars: !@#$%^&*()",  # Special characters
            json.dumps({"resourceId": "test123"}),  # JSON Azure resource data
        ]

        for plaintext in test_data:
            # Encrypt and decrypt the plaintext
            log.debug(f"Output plaintext: {plaintext}")
            encrypted_data = openssl.encrypt(plaintext, key_hex, iv_hex)
            decrypted_data = openssl.decrypt(encrypted_data, key_hex, iv_hex)
            assert_that(plaintext).described_as(
                "Plaintext and decrypted data do not match"
            ).is_equal_to(decrypted_data)

    def _openssl_test_sign_verify(self, log: Logger, node: Node) -> None:
        """
        Tests OpenSSL signing and verification functionality.
        This function generates a key pair, signs a message,
        and verifies the signature.
        """
        openssl = node.tools[OpenSSL]
        private_key, public_key = openssl.create_key_pair()

        plaintext = "cool"
        signature = openssl.sign(plaintext, private_key)
        openssl.verify(plaintext, public_key, signature)

        log.debug("Successfully signed and verified a file.")
