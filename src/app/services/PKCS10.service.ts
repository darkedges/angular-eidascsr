import * as asn1js from 'asn1js';
import AttributeTypeAndValue from 'pkijs/src/AttributeTypeAndValue';
import CertificationRequest from 'pkijs/src/CertificationRequest';
import Extension from 'pkijs/src/Extension';
import Extensions from 'pkijs/src/Extensions';
import { Injectable } from '@angular/core';
import { flatMap, map } from 'rxjs/operators';
import { from, Observable, throwError } from 'rxjs';
import { getAlgorithmParameters, getCrypto } from 'pkijs/src/common';
import Attribute from 'pkijs/src/Attribute';
import ExtKeyUsage from 'pkijs/src/ExtKeyUsage';
import * as qcstatements from '../models/qcstatement.class';



@Injectable({
  providedIn: 'root'
})
export class PKCS10Service {
  hashAlg = 'SHA-1';
  signAlg = 'RSASSA-PKCS1-v1_5';
  constructor() { }

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
    // region Get default algorithm parameters for key generation
    const algorithm = getAlgorithmParameters(this.signAlg, 'generatekey');
    if ('hash' in algorithm.algorithm) {
      algorithm.algorithm.hash.name = this.hashAlg;
    }
    // end region

    const bitArray = new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);

    let extKeyUsage;

    let qcType;
    if (type === 'QSEAL') {
      bitView[0] |= 0x80; // DigitalSignature
      bitView[0] |= 0x40; // NonRepudiation
      qcType = qcstatements.QSEALType;
    } else {
      bitView[0] |= 0x80; // DigitalSignature
      qcType = qcstatements.QWACType;
      extKeyUsage = new ExtKeyUsage({
        keyPurposes: [
          '1.3.6.1.5.5.7.3.1', // id-kp-serverAuth
          '1.3.6.1.5.5.7.3.2', // id-kp-clientAuth
        ]
      });
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
        console.log(result);
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
        return from(crypto.exportKey('pkcs8', privateKey));
      }),
      map((result) => {
        return {
          pk: result,
          csr: pkcs10.toSchema().toBER(false)
        };
      }, err => {
        console.log(err);
      }
      )
    );
  }
}
