import * as jose from 'node-jose';
import * as qcStatement from '../models/qcstatement.class';
import { arrayBufferToString, toBase64 } from 'pvutils';
import { flatMap, tap, map } from 'rxjs/operators';
import { from, Observable, of } from 'rxjs';
import { Injectable } from '@angular/core';
import { PKCS10Service } from './pkcs10.service';
import { CertificateResponse } from '../models/certificate.interface';

@Injectable({
    providedIn: 'root'
})
export class EIDASService {
    constructor(
        private pkcs10Service: PKCS10Service
    ) {

    }
    createBundle(
        countryName: string,
        organizationName: string,
        organizationIdentifier: string,
        commonName: string,
        roles: qcStatement.Role[],
        type: string,
        sign: boolean
    ): Observable<any> {
        const privateKeystore = jose.JWK.createKeyStore();
        const publicKeystore = jose.JWK.createKeyStore();
        let privateKey;
        let publicKey;
        let csr;
        let kid;
        if (sign) {
            return this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type)
                .pipe(
                    tap(data => {
                        privateKey = '-----BEGIN PRIVATE KEY-----\n';
                        privateKey = `${privateKey}${this.formatPEM(toBase64(arrayBufferToString(data.pk.pkcs8)))}`;
                        privateKey = `${privateKey}\n-----END PRIVATE KEY-----`;
                        csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n';
                        csr = `${csr}${this.formatPEM(toBase64(arrayBufferToString(data.csr)))}`;
                        csr = `${csr}\n-----END NEW CERTIFICATE REQUEST-----`;
                    }),
                    flatMap(data => {
                        kid = data.pk.jwk.kid;
                        return from(privateKeystore.add(data.pk.jwk, 'json'));
                    }),
                    flatMap(data => {
                        return this.pkcs10Service.getPublicKey(csr);
                    })
                    ,
                    flatMap(data => {
                        publicKey = data.result.certificate;
                        return from(publicKeystore.add(publicKey, 'pem', { kid }));
                    }),
                    flatMap(result => {
                        return of({
                            csr,
                            privateKey,
                            publicKey,
                            jwks: JSON.stringify({
                                publicJwks: publicKeystore.toJSON(true),
                                privateJwks: privateKeystore.toJSON(true)
                            }, null, 2)
                        } as CertificateResponse);
                    })
                );
        } else {
            return this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type).pipe(
                tap(data => {
                    privateKey = '-----BEGIN PRIVATE KEY-----\n';
                    privateKey = `${privateKey}${this.formatPEM(toBase64(arrayBufferToString(data.pk.pkcs8)))}`;
                    privateKey = `${privateKey}\n-----END PRIVATE KEY-----`;
                    csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n';
                    csr = `${csr}${this.formatPEM(toBase64(arrayBufferToString(data.csr)))}`;
                    csr = `${csr}\n-----END NEW CERTIFICATE REQUEST-----`;
                }),
                flatMap(data => {
                    kid = data.pk.jwk.kid;
                    return from(privateKeystore.add(data.pk.jwk, 'json'));
                }),
                flatMap(result => {
                    return of({
                        csr,
                        privateKey,
                        jwks: JSON.stringify({
                            privateJwks: privateKeystore.toJSON(true)
                        }, null, 2)
                    } as CertificateResponse );
                })
            );
        }
    }

    formatPEM(pemString) {
        const stringLength = pemString.length;
        let resultString = '';

        for (let i = 0, count = 0; i < stringLength; i++ , count++) {
            if (count > 63) {
                resultString = `${resultString}\n`;
                count = 0;
            }

            resultString = `${resultString}${pemString[i]}`;
        }

        return resultString;
    }
}
