import * as jose from 'node-jose';
import * as JSZip from 'jszip';
import * as qcStatement from '../models/qcstatement.class';
import { arrayBufferToString, toBase64 } from 'pvutils';
import { Component, OnInit } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { flatMap, tap, mergeMap } from 'rxjs/operators';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PKCS10Service } from '../services/pkcs10.service';
import { saveAs } from 'file-saver';
import { from, of } from 'rxjs';
import { EIDASService } from '../services/eidas.service';
import { CertificateResponse } from '../models/certificate.interface';

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
    private eidasService: EIDASService
  ) { }

  ngOnInit(): void {
    this.eidascsr = this.formBuilder.group({
      countryName: ['GB', Validators.required],
      organizationName: ['Your Organization Limited', Validators.required],
      organizationIdentifier: ['PSDGB-FCA-123456', Validators.required],
      commonName: ['0123456789abcdef', Validators.required],
      type: [{ value: 'QWAC', disabled: false }, Validators.required],
      roles: [[qcStatement.RoleAccountInformation], Validators.required],
      signed: [false]
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



  public createOwner = () => {
    const countryName = this.eidascsr.value.countryName;
    const organizationName = this.eidascsr.value.organizationName;
    const organizationIdentifier = this.eidascsr.value.organizationIdentifier;
    const commonName = this.eidascsr.value.commonName;
    const type = this.eidascsr.value.type;
    const roles = this.eidascsr.value.roles;
    const sign = this.eidascsr.value.signed;
    this.eidasService.createBundle(
      countryName, organizationName, organizationIdentifier, commonName, type, roles, sign
    ).subscribe((data: CertificateResponse) => {
      this.certificates.patchValue({
        csr: data.csr,
        publicKey: data.publicKey,
        privateKey: data.privateKey,
        jwks: data.jwks
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
    if (this.eidascsr.value.signed) {
      j.file(`${organizationIdentifier}.crt`, this.certificates.value.publicKey);
    }
    j.file(`${organizationIdentifier}.json`, this.certificates.value.jwks);
    j.generateAsync({ type: 'blob' }).then(data => {
      saveAs(data, `${organizationIdentifier}.zip`);
    });
  }

}
