import requests
from acme import client, messages, crypto_util
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class VenafiAcmeClient:
    def __init__(self, acme_directory_url: str, email: str, rsa_key_size: int = 2048):
        self.acme_directory_url = acme_directory_url
        self.email = email
        self.rsa_key_size = rsa_key_size
        self.acme_client = self._initialize_acme_client()

    def _initialize_acme_client(self):
        # Generate a new RSA key
        account_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size
        )

        # Convert the private key to DER format
        account_key_der = account_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Initialize the ACME client
        net = client.ClientNetwork(account_key_der)
        directory = client.Directory(self.acme_directory_url, net)
        acme_client = client.ClientV2(directory, net)

        # Register the account
        registration = acme_client.new_account(
            messages.NewRegistration.from_data(email=self.email, terms_of_service_agreed=True)
        )

        return acme_client

    def create_csr(self, common_name: str) -> bytes:
        """Create a Certificate Signing Request (CSR)"""
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size
        )

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).sign(private_key, hashes.SHA256())

        # Convert CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        return csr_pem

    def request_certificate(self, common_name: str):
        """Request a new certificate using ACME protocol"""
        # Create CSR
        csr_pem = self.create_csr(common_name)

        # Order a certificate
        order = self.acme_client.new_order(csr_pem)

        # Get the authorization challenges
        authz_list = order.authorizations

        for authz in authz_list:
            # Example for handling HTTP-01 challenge (you need to adapt this for DNS-01 or others)
            challenge = authz.body.challenges[0]
            acme_client.answer_challenge(challenge, challenge.response(self.acme_client.net.key))

        # Finalize the order after challenges are completed
        finalized_order = self.acme_client.poll_and_finalize(order)

        # Retrieve the certificate
        certificate_pem = finalized_order.fullchain_pem

        print(f"Certificate issued for {common_name}")
        print(certificate_pem)

        return certificate_pem

    def renew_certificate(self, certificate_pem: str):
        """Renew an existing certificate"""
        # Load the existing certificate
        cert = crypto_util.ComparableX509(x509.load_pem_x509_certificate(certificate_pem.encode()))

        # Reuse the same common name for renewal
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Request a new certificate for renewal
        return self.request_certificate(common_name)


# Example usage of the VenafiAcmeClient
def main():
    acme_directory_url = "https://acme.example.com/directory"  # Replace with your ACME directory URL from Venafi TPP
    email = "admin@example.com"

    acme_client = VenafiAcmeClient(acme_directory_url, email)

    # Request a new certificate
    common_name = "example.com"
    certificate_pem = acme_client.request_certificate(common_name)

    # Renew the certificate
    renewed_certificate = acme_client.renew_certificate(certificate_pem)


if __name__ == "__main__":
    main()
