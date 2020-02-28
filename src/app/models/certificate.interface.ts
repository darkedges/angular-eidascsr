export interface CertificateResponse {
    csr: string;
    privateKey: string;
    publicKey: string;
    jwks: string;
}
