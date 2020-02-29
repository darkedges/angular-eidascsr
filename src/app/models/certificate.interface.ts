export interface CertificateResponse {
    type: string;
    csr: string;
    privateKey: string;
    publicKey: string;
    jwks: string;
}
