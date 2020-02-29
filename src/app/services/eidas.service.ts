import * as jose from 'node-jose';
import * as qcStatement from '../models/qcstatement.class';
import { arrayBufferToString, toBase64 } from 'pvutils';
import { flatMap, tap, map, mergeMap } from 'rxjs/operators';
import { from, Observable, of, forkJoin } from 'rxjs';
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
        types: string[],
        sign: boolean
    ): Observable<any> {
        return this.createBundleCore( countryName,
            organizationName,
            organizationIdentifier,
            commonName,
            roles,
            types,
            sign).pipe(
                tap(data => {
                    console.log(data);
                })
            );
    }

    createBundleCore(
        countryName: string,
        organizationName: string,
        organizationIdentifier: string,
        commonName: string,
        roles: qcStatement.Role[],
        types: string[],
        sign: boolean
    ): Observable<any> {
        console.log(types);
        const privateKeystore = jose.JWK.createKeyStore();
        const publicKeystore = jose.JWK.createKeyStore();
        let privateKey;
        let csr;
        if (sign) {
            const obs = types.map(type => {
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
                            return this.pkcs10Service.getPublicKey(csr);
                        }),
                        // flatMap(data => {
                        //     publicKey = data.result.certificate;
                        //     return from(publicKeystore.add(publicKey, 'pem', { kid }));
                        // }),
                        flatMap(data => {
                            return of({
                                type,
                                csr,
                                privateKey,
                                publicKey: data.result.certificate,
                                // jwks: JSON.stringify({
                                //     publicJwks: publicKeystore.toJSON(true),
                                //     privateJwks: privateKeystore.toJSON(true)
                                // }, null, 2)
                            } as CertificateResponse);
                        })
                    );
            });
            return from(obs).pipe(
                mergeMap((id, index) => {
                    return id;
                })
            );
        } else {
            const obs = types.map(type => {
                return this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type).pipe(
                    tap(data => {
                        privateKey = '-----BEGIN PRIVATE KEY-----\n';
                        privateKey = `${privateKey}${this.formatPEM(toBase64(arrayBufferToString(data.pk.pkcs8)))}`;
                        privateKey = `${privateKey}\n-----END PRIVATE KEY-----`;
                        csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n';
                        csr = `${csr}${this.formatPEM(toBase64(arrayBufferToString(data.csr)))}`;
                        csr = `${csr}\n-----END NEW CERTIFICATE REQUEST-----`;
                    }),
                    // flatMap(data => {
                    //     kid = data.pk.jwk.kid;
                    //     return from(privateKeystore.add(data.pk.jwk, 'json'));
                    // }),
                    flatMap(result => {
                        return of({
                            type,
                            csr,
                            privateKey
                        } as CertificateResponse);
                    })
                );
            });

            // return forkJoin(...obs);
            return from(obs).pipe(
                mergeMap((id, index) => {
                    return id;
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
