import * as asn1js from 'asn1js';
import AttributeTypeAndValue from 'pkijs/src/AttributeTypeAndValue';
import CertificationRequest from 'pkijs/src/CertificationRequest';
import Extension from 'pkijs/src/Extension';
import Extensions from 'pkijs/src/Extensions';
import { Injectable } from '@angular/core';
import { flatMap, map } from 'rxjs/operators';
import { from, Observable, throwError, forkJoin } from 'rxjs';
import { getAlgorithmParameters, getCrypto } from 'pkijs/src/common';
import Attribute from 'pkijs/src/Attribute';
import ExtKeyUsage from 'pkijs/src/ExtKeyUsage';
import * as qcstatements from '../models/qcstatement.class';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { DefaultDataServiceConfig } from '../shared/default-data-service-config';



@Injectable({
  providedIn: 'root'
})
export class PKCS10Service {
  hashAlg = 'SHA-1';
  signQWACAlg = 'RSASSA-PKCS1-v1_5';
  signQSealAlg = 'ECDSA';

  protected getDelay = 0;
  protected timeout = 0;
  protected saveDelay = 0;
  protected delete404OK: boolean;
  protected root = '';

  constructor(
    public http: HttpClient,
    config?: DefaultDataServiceConfig) {
    const {
      root = 'api',
      delete404OK = true,
      getDelay = 0,
      saveDelay = 0,
      timeout: to = 0,
    } =
      config || {};
    this.root = root;
    this.getDelay = getDelay;
    this.timeout = to;
    this.delete404OK = delete404OK;
    this.saveDelay = saveDelay;
  }

  getPublicKey(csr): Observable<any> {
    return this.http.post(`${this.root}/api/v1/cfssl/authsign`, { certificate_request: csr },
      {
        headers: this.getRegisterHeaders(),
        withCredentials: true
      });
  }

  createCSR(
    countryName: string,
    organizationName: string,
    organizationIdentifier: string,
    commonName: string,
    roles: qcstatements.Role[],
    type: string
  ): Observable<any> {
    let publicKey: CryptoKey;
    let privateKey: CryptoKey;
    const pkcs10 = new CertificationRequest();
    const crypto = getCrypto();
    if (typeof crypto === 'undefined') {
      return throwError('Some error information');
    }
    pkcs10.version = 0;

    pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
      type: '2.5.4.6',
      value: new asn1js.PrintableString({ value: countryName })
    }));
    pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
      type: '2.5.4.10',
      value: new asn1js.PrintableString({ value: organizationName })
    }));
    pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
      type: '2.5.4.97',
      value: new asn1js.PrintableString({ value: organizationIdentifier })
    }));
    pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
      type: '2.5.4.3', // Common name
      value: new asn1js.PrintableString({ value: commonName })
    }));

    pkcs10.attributes = [];
    const bitArray = new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);
    let qcType;
    let extKeyUsage;
    let algorithm;

    if (type === 'QSEAL') {
      algorithm = getAlgorithmParameters(this.signQSealAlg, 'generatekey');
      bitView[0] |= 0x80; // DigitalSignature
      bitView[0] |= 0x40; // NonRepudiation
      qcType = qcstatements.QSEALType;
    } else {
      algorithm = getAlgorithmParameters(this.signQWACAlg, 'generatekey');
      bitView[0] |= 0x80; // DigitalSignature
      qcType = qcstatements.QWACType;
      extKeyUsage = new ExtKeyUsage({
        keyPurposes: [
          '1.3.6.1.5.5.7.3.1', // id-kp-serverAuth
          '1.3.6.1.5.5.7.3.2', // id-kp-clientAuth
        ]
      });
    }
    if ('hash' in algorithm.algorithm) {
      algorithm.algorithm.hash.name = this.hashAlg;
    }

    const keyUsage = new asn1js.BitString({ valueHex: bitArray });
    // const qcRoles: qcstatements.Role[] = [];
    // qcRoles.push(qcstatements.RoleAccountInformation);

    const ca = qcstatements.competentAuthorityForCountryCode('GB');

    const arrayBuffer = qcstatements.serializeCreditKudos(roles, ca, qcType);

    return from(crypto.generateKey(algorithm.algorithm, true, algorithm.usages)).pipe(
      flatMap(
        (keyPair: CryptoKeyPair) => {
          publicKey = keyPair.publicKey;
          privateKey = keyPair.privateKey;
          return from(pkcs10.subjectPublicKeyInfo.importKey(publicKey));
        }),
      flatMap(() => {
        return from(crypto.digest({ name: this.hashAlg }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
      }
      ),
      flatMap(result => {
        const extensions = [
          new Extension({
            extnID: '2.5.29.15',
            critical: true,
            extnValue: keyUsage.toBER(false),
            parsedValue: keyUsage // Parsed value for well-known extensions
          })];
        if (type === 'QWAC') {
          extensions.push(new Extension({
            extnID: '2.5.29.37',
            critical: false,
            extnValue: extKeyUsage.toSchema().toBER(false),
            parsedValue: extKeyUsage // Parsed value for well-known extensions
          }));
        }
        // @ts-ignore: Unreachable code error
        extensions.push(
          new Extension({
            extnID: '2.5.29.14',
            critical: false,
            extnValue: new asn1js.OctetString({ valueHex: result as ArrayBuffer }).toBER(false)
          }), new Extension({
            extnID: '1.3.6.1.5.5.7.1.3',
            critical: false,
            extnValue: arrayBuffer,
            parsedValue: arrayBuffer // Parsed value for well-known extensions
          })
        );

        pkcs10.attributes.push(new Attribute({
          type: '1.2.840.113549.1.9.14', // pkcs-9-at-extensionRequest
          values: [(new Extensions({
            extensions
          })).toSchema()]
        }));
        return from(pkcs10.sign(privateKey, this.hashAlg));
      }),
      flatMap(() => {
        // return from(crypto.exportKey('pkcs8', privateKey));
        return forkJoin(
          crypto.exportKey('pkcs8', privateKey),
          crypto.exportKey('jwk', privateKey)
        );
      }),
      map((result) => {
        console.log(pkcs10.toSchema().toBER(false));
        return {
          pk: {
            pkcs8: result[0],
            jwk: result[1]
          },
          csr: pkcs10.toSchema().toBER(false)
        };
      }, err => {
        console.log(err);
      }
      )
    );
  }
  private getRegisterHeaders() {
    const headers = new HttpHeaders()
      .append('content-type', 'application/json');
    return headers;
  }
}
