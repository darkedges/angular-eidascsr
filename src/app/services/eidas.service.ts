import * as qcStatement from '../models/qcstatement.class';
import { arrayBufferToString, toBase64 } from 'pvutils';
import { flatMap, tap, map, mergeMap } from 'rxjs/operators';
import { from, Observable, of, forkJoin } from 'rxjs';
import { Injectable } from '@angular/core';
import { PKCS10Service } from './pkcs10.service';
import { CertificateResponse } from '../models/certificate.interface';
import { Meta } from '@angular/platform-browser';

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
        return this.createBundleCore(countryName,
            organizationName,
            organizationIdentifier,
            commonName,
            roles,
            types,
            sign).pipe(
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

        if (sign) {
            const obs = types.map(type => {
                let privateKey;
                let csr;
                let jwk;
                return this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type)
                    .pipe(
                        flatMap(data => {
                            privateKey = '-----BEGIN PRIVATE KEY-----\n';
                            privateKey = `${privateKey}${this.formatPEM(toBase64(arrayBufferToString(data.pk.pkcs8)))}`;
                            privateKey = `${privateKey}\n-----END PRIVATE KEY-----`;
                            csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n';
                            csr = `${csr}${this.formatPEM(toBase64(arrayBufferToString(data.csr)))}`;
                            csr = `${csr}\n-----END NEW CERTIFICATE REQUEST-----`;
                            jwk = data.pk.jwk;
                            return this.pkcs10Service.getPublicKey(csr);
                        },
                            (outerValue, innerValue) => (
                                { meta: outerValue, publicKey: innerValue, metaData: { privateKey, csr, jwk } })
                        ),
                        flatMap(data => {
                            return of({
                                type,
                                csr: data.metaData.csr,
                                privateKey: data.metaData.privateKey,
                                jwk: data.metaData.jwk,
                                publicKey: data.publicKey.result.certificate,
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
                return this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type)
                    .pipe(
                        flatMap(data => {
                            let privateKey = '-----BEGIN PRIVATE KEY-----\n';
                            privateKey = `${privateKey}${this.formatPEM(toBase64(arrayBufferToString(data.pk.pkcs8)))}`;
                            privateKey = `${privateKey}\n-----END PRIVATE KEY-----`;
                            let csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n';
                            csr = `${csr}${this.formatPEM(toBase64(arrayBufferToString(data.csr)))}`;
                            csr = `${csr}\n-----END NEW CERTIFICATE REQUEST-----`;
                            const jwk = data.pk.jwk;
                            return of({
                                type,
                                csr,
                                privateKey,
                                jwk
                            } as CertificateResponse);
                        })
                    );
            });
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
