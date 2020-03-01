import { kdfWithCounter } from 'pkijs/src/common';

export interface CertificateResponse {
  [x: string]: any;
    type: string;
    csr: string;
    privateKey: string;
    publicKey: string;
    jwk: string;
}
