import * as jose from 'node-jose';
import * as JSZip from 'jszip';
import * as qcStatement from '../models/qcstatement.class';
import { arrayBufferToString, toBase64 } from 'pvutils';
import { Component, OnInit } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { flatMap, tap } from 'rxjs/operators';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PKCS10Service } from '../services/pkcs10.service';
import { saveAs } from 'file-saver';
import { from } from 'rxjs';

@Component({
  selector: 'app-eidascsr',
  templateUrl: './eidascsr.component.html',
  styleUrls: ['./eidascsr.component.scss']
})
export class EidascsrComponent implements OnInit {
  isLinear = true;
  eidascsr: FormGroup;
  certificates: FormGroup;
  countryIds = Object.keys(qcStatement.caMap);
  types = ['QWAC', 'QSEAL'];
  roles = qcStatement.roles;

  constructor(
    private formBuilder: FormBuilder,
    private pkcs10Service: PKCS10Service
  ) { }

  ngOnInit(): void {
    this.eidascsr = this.formBuilder.group({
      countryName: ['GB', Validators.required],
      organizationName: ['Your Organization Limited', Validators.required],
      organizationIdentifier: ['PSDGB-FCA-123456', Validators.required],
      commonName: ['0123456789abcdef', Validators.required],
      type: ['QWAC', Validators.required],
      roles: [[qcStatement.RoleAccountInformation], Validators.required]
    });
    this.certificates = this.formBuilder.group({
      privateKey: [''],
      csr: [''],
      publicKey: [''],
      jwks: ['']
    });
  }

  hasError(formGroupName: string, controlName: string, errorName: string) {
    let c;
    if (formGroupName) {
      c = this.eidascsr.controls[formGroupName];
    } else {
      c = this.eidascsr;
    }
    if (c.controls[controlName].touched) {
      return c.controls[controlName].hasError(errorName);
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

  public createOwner = () => {
    let privateKey;
    let publicKey;
    let csr;
    let kid;

    const countryName = this.eidascsr.value.countryName;
    const organizationName = this.eidascsr.value.organizationName;
    const organizationIdentifier = this.eidascsr.value.organizationIdentifier;
    const commonName = this.eidascsr.value.commonName;
    const type = this.eidascsr.value.type;
    const roles = this.eidascsr.value.roles;
    const privateKeystore = jose.JWK.createKeyStore();
    const publicKeystore = jose.JWK.createKeyStore();

    this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type).pipe(
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
      })
    ).subscribe(result => {
      this.certificates.patchValue({
        csr,
        privateKey,
        publicKey,
        jwks: JSON.stringify({
          publicJwks: publicKeystore.toJSON(true),
          privateJwks: publicKeystore.toJSON(true)
        }, null, 2)
      });
    });
  }

  csrToClipoard() {
    return this.certificates.value.csr;
  }

  privateKeyToClipoard() {
    return this.certificates.value.privateKey;
  }

  publicKeyToClipoard() {
    return this.certificates.value.publicKey;
  }

  jwksToClipoard() {
    return this.certificates.value.jwks;
  }

  downloadFiles() {
    const organizationIdentifier = this.eidascsr.value.organizationIdentifier;
    const j: JSZip = new JSZip();
    j.file(`${organizationIdentifier}.key`, this.certificates.value.privateKey);
    j.file(`${organizationIdentifier}.csr`, this.certificates.value.csr);
    j.file(`${organizationIdentifier}.crt`, this.certificates.value.publicKey);
    j.file(`${organizationIdentifier}.json`, this.certificates.value.jwks);
    j.generateAsync({ type: 'blob' }).then(data => {
      saveAs(data, `${organizationIdentifier}.zip`);
    });
  }

}
