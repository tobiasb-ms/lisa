# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from typing import TYPE_CHECKING

from lisa.executable import Tool

if TYPE_CHECKING:
    from lisa.operating_system import Posix


class OpenSSL(Tool):
    @property
    def command(self) -> str:
        return "openssl"

    @property
    def can_install(self) -> bool:
        return True

    def encrypt(
        self,
        plaintext: str,
        hex_key: str,
        hex_iv: str,
        algorithm: str = "aes-256-cbc",
    ) -> str:
        return self._run_with_piped_input(
            plaintext,
            f"enc -{algorithm} -K '{hex_key}' -iv '{hex_iv}' -base64 -A",
        )

    def decrypt(
        self,
        ciphertext: str,
        hex_key: str,
        hex_iv: str,
        algorithm: str = "aes-256-cbc",
    ) -> str:
        return self._run_with_piped_input(
            ciphertext,
            f"enc -d -{algorithm} -K '{hex_key}' -iv '{hex_iv}' -base64 -A",
        )

    def create_key_pair(self, algorithm: str = "RSA") -> tuple[str, str]:
        private_key = self.run(
            f"genpkey -algorithm {algorithm} -outform PEM", expected_exit_code=0
        ).stdout.strip()

        public_key = self._run_with_piped_input(private_key, "pkey -pubout")

        return private_key, public_key

    def sign(
        self,
        data: str,
        private_key: str,
        algorithm: str = "sha256",
    ) -> str:
        return self._run_with_piped_input(
            data,
            f"dgst -{algorithm} -sign <(echo '{private_key}') | openssl base64 -A",
        )

    def verify(
        self,
        data: str,
        public_key: str,
        signature_base64: str,
        algorithm: str = "sha256",
    ) -> None:
        # Because this is run with expected_exit_code=0, the command will assert/throw
        # if it fails.
        self._run_with_piped_input(
            data,
            f"dgst -{algorithm} -verify <(echo '{public_key}') "
            f"-signature <(echo '{signature_base64}' | "
            "openssl base64 -A -d)",
        )

    # openssl.run(
    #     f"dgst -sha256 -verify {public_key_path} -signature {signature_path} {plaintext_path}",
    #     expected_exit_code=0,
    # )

    def _run_with_piped_input(self, piped_input_cmd: str, openssl_cmd: str) -> str:
        cmd = f"printf '%s' '{piped_input_cmd}' | {self.command} {openssl_cmd}"
        return self.node.execute(cmd, shell=True, expected_exit_code=0).stdout.strip()

    def _install(self) -> bool:
        posix_os: Posix = self.node.os  # type: ignore
        posix_os.install_packages([self])
        return self._check_exists()
