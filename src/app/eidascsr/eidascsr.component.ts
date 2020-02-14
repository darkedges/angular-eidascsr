import * as JSZip from 'jszip';
import * as qcStatement from '../models/qcstatement.class';
import { arrayBufferToString, toBase64 } from 'pvutils';
import { Component, OnInit } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PKCS10Service } from '../services/pkcs10.service';
import { tap } from 'rxjs/operators';
import { saveAs } from 'file-saver';

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
    private pkcs10Service: PKCS10Service,
    private sanitizer: DomSanitizer
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
      csr: ['']
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
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pemString" type="String">String to format</param>

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
    let csr;

    const countryName = this.eidascsr.value.countryName;
    const organizationName = this.eidascsr.value.organizationName;
    const organizationIdentifier = this.eidascsr.value.organizationIdentifier;
    const commonName = this.eidascsr.value.commonName;
    const type = this.eidascsr.value.type;
    const roles = this.eidascsr.value.roles;


    this.pkcs10Service.createCSR(countryName, organizationName, organizationIdentifier, commonName, roles, type).pipe(
      tap(data => {
        privateKey = '-----BEGIN PRIVATE KEY-----\n';
        privateKey = `${privateKey}${this.formatPEM(toBase64(arrayBufferToString(data.pk)))}`;
        privateKey = `${privateKey}\n-----END PRIVATE KEY-----`;

        csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\n';
        csr = `${csr}${this.formatPEM(toBase64(arrayBufferToString(data.csr)))}`;
        csr = `${csr}\n-----END NEW CERTIFICATE REQUEST-----`;
      })
    ).subscribe(result => {
      this.certificates.patchValue({ csr, privateKey });
    });
  }

  csrToClipoard() {
    return this.certificates.value.csr;
  }

  pkToClipoard() {
    return this.certificates.value.privateKey;
  }

  downloadFiles() {
    const organizationIdentifier = this.eidascsr.value.organizationIdentifier;
    const j: JSZip = new JSZip();
    j.file(`${organizationIdentifier}.key`, this.certificates.value.privateKey);
    j.file(`${organizationIdentifier}.csr`, this.certificates.value.csr);
    j.generateAsync({ type: 'blob' }).then(data => {
      saveAs(data, `${organizationIdentifier}.zip`);
    });
  }

}
