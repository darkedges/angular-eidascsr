import { kdfWithCounter } from 'pkijs/src/common';

export interface CertificateResponse {
    type: string;
    csr: string;
    privateKey: string;
    publicKey: string;
    jwk: string;
}
