import * as jose from 'node-jose';
import * as JSZip from 'jszip';
import * as qcStatement from '../models/qcstatement.class';
import { CertificateResponse } from '../models/certificate.interface';
import { COMMA, ENTER } from '@angular/cdk/keycodes';
import {
  Component,
  ElementRef,
  OnInit,
  ViewChild
} from '@angular/core';
import { CustomValidators } from './custom.validator';
import { EIDASService } from '../services/eidas.service';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { map, startWith, tap, mergeMap } from 'rxjs/operators';
import { MatAutocomplete, MatAutocompleteSelectedEvent } from '@angular/material/autocomplete';
import { MatChipInputEvent } from '@angular/material/chips';
import { Observable, of, forkJoin, empty } from 'rxjs';
import { saveAs } from 'file-saver';

@Component({
  selector: 'app-eidascsr',
  templateUrl: './eidascsr.component.html',
  styleUrls: ['./eidascsr.component.scss']
})
export class EidascsrComponent implements OnInit {
  isLinear = true;
  eidascsr: FormGroup;
  qsealcertificates: FormGroup;
  qwaccertificates: FormGroup;
  certificates: FormGroup;
  countryIds = Object.keys(qcStatement.caMap);
  allTypes = ['QWAC', 'QSEAL'];
  filteredTypes: Observable<string[]>;
  roles = qcStatement.roles;
  separatorKeysCodes: number[] = [ENTER, COMMA];
  certificateTab = 0;
  downloadEnabled = false;
  privateKeystore;
  publicKeystore;

  @ViewChild('typeInput') typeInput: ElementRef<HTMLInputElement>;
  @ViewChild('auto') matAutocomplete: MatAutocomplete;

  constructor(
    private formBuilder: FormBuilder,
    private eidasService: EIDASService
  ) {
  }

  ngOnInit(): void {
    this.eidascsr = this.formBuilder.group({
      countryName: ['GB', Validators.required],
      organizationName: ['Your Organization Limited', Validators.required],
      organizationIdentifier: ['PSDGB-FCA-123456', Validators.required],
      commonName: ['0123456789abcdef', Validators.required],
      type: [['QWAC', 'QSEAL'], [
        CustomValidators.validateRequired,
        CustomValidators.validateCertificateType
      ]],
      roles: [[qcStatement.RoleAccountInformation], Validators.required],
      signed: [false]
    });
    this.qwaccertificates = this.formBuilder.group({
      privateKey: [''],
      csr: [''],
      publicKey: [''],
      jwk: ['']
    });
    this.qsealcertificates = this.formBuilder.group({
      privateKey: [''],
      csr: [''],
      publicKey: [''],
      jwk: ['']
    });
    this.qsealcertificates.disable();
    this.qwaccertificates.disable();
    this.certificates = this.formBuilder.group({
      jwks: [''],
      qwaccertificates: this.qsealcertificates,
      qsealcertificates: this.qsealcertificates
    });

    this.filteredTypes = this.eidascsr.controls.type.valueChanges.pipe(
      startWith(''),
      map(value => this._filter(value))
    );

    this.privateKeystore = jose.JWK.createKeyStore();
    this.publicKeystore = jose.JWK.createKeyStore();
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
    this.certificates.reset();
    this.qwaccertificates.reset();
    this.qsealcertificates.reset();
    this.qsealcertificates.disable();
    this.qwaccertificates.disable();
    this.downloadEnabled = false;
    this.eidasService.createBundle(
      countryName,
      organizationName,
      organizationIdentifier,
      commonName,
      roles,
      type,
      sign
    ).subscribe(
      (responses: any[]) => {
        console.log(responses);
        responses.forEach(data => {
          if (data.type.toLowerCase() === 'qwac') {

            this.qwaccertificates.patchValue({
              csr: data.csr,
              publicKey: data.publicKey,
              privateKey: data.privateKey,
              jwk: data.jwk
            });
            this.qwaccertificates.enable();
          }
          if (data.type.toLowerCase() === 'qseal') {
            this.qsealcertificates.patchValue({
              csr: data.csr,
              publicKey: data.publicKey,
              privateKey: data.privateKey,
              jwk: data.jwk
            });
            this.qsealcertificates.enable();
          }
          if (data.type.toLowerCase() === 'jwks') {
            let jwks = {};
            if (data.publicJwks.keys.length > 0) {
              jwks = JSON.stringify({
                publicJwks: data.publicJwks,
                privateJwks: data.privateJwks
              }, null, 2);
            } else {
              jwks = JSON.stringify({
                privateJwks: data.privateJwks
              }, null, 2);
            }
            this.certificates.patchValue(
              {
                jwks
              });
            this.downloadEnabled = true;
          }
        });
        this.certificateTab = 0;
        if (!this.qwaccertificates.enabled) {
          this.certificateTab = 1;
        }
      },
      (error) => { console.log(error); },
    );
  }

  qwacPrivateKeyToClipoard() {
    return this.qwaccertificates.value.privateKey;
  }

  qwacCsrToClipoard() {
    return this.qwaccertificates.value.csr;
  }
  qwacPublicKeyToClipoard() {
    return this.qwaccertificates.value.publicKey;
  }

  qwacJwksToClipoard() {
    return this.qwaccertificates.value.jwks;
  }

  qsealPrivateKeyToClipoard() {
    return this.qsealcertificates.value.privateKey;
  }

  qsealCsrToClipoard() {
    return this.qsealcertificates.value.csr;
  }
  qsealPublicKeyToClipoard() {
    return this.qsealcertificates.value.publicKey;
  }

  jwksToClipoard() {
    return this.certificates.value.jwks;
  }

  downloadFiles() {
    const organizationIdentifier = this.eidascsr.value.organizationIdentifier;
    const j: JSZip = new JSZip();
    if (this.qwaccertificates.value.privateKey) {
      j.file(`${organizationIdentifier}-qwac.key`, this.qwaccertificates.value.privateKey);
      j.file(`${organizationIdentifier}-qwac.csr`, this.qwaccertificates.value.csr);
      if (this.eidascsr.value.signed) {
        j.file(`${organizationIdentifier}-qwac.crt`, this.qwaccertificates.value.publicKey);
      }
    }
    if (this.qsealcertificates.value.privateKey) {
      j.file(`${organizationIdentifier}-qseal.key`, this.qsealcertificates.value.privateKey);
      j.file(`${organizationIdentifier}-qseal.csr`, this.qsealcertificates.value.csr);
      if (this.eidascsr.value.signed) {
        j.file(`${organizationIdentifier}-qseal.crt`, this.qsealcertificates.value.publicKey);
      }
    }
    j.file(`${organizationIdentifier}.json`, this.certificates.value.jwks);
    j.generateAsync({ type: 'blob' }).then(data => {
      saveAs(data, `${organizationIdentifier}.zip`);
    });
  }

  add(event: MatChipInputEvent): void {
    const input = event.input;
    const value = event.value;
    const controller = this.eidascsr.controls.type;
    if ((value.trim() !== '')) {
      if ((value || '').trim()) {
        controller.setErrors(null);   // 1
        const tempEmails = controller.value; // 2
        tempEmails.push(value.trim());
        controller.setValue(tempEmails);     // 3
        if (controller.valid) {              // 4
          controller.markAsDirty();
          input.value = '';                                    // 5
        } else {
          const index = controller.value.findIndex(value1 => value1 === value.trim());
          if (index !== -1) {
            controller.value.splice(index, 1);           // 6
          }
        }
      }
      if (input) {
        input.value = '';
      }
    } else {
      controller.updateValueAndValidity();
    }
  }

  remove(type: string): void {
    const controller = this.eidascsr.controls.type;
    const index = controller.value.indexOf(type);
    if (index >= 0) {
      controller.value.splice(index, 1);
      controller.markAsDirty();
    }
    controller.updateValueAndValidity();
  }

  selected(event: MatAutocompleteSelectedEvent): void {
    const value = event.option.value;
    const controller = this.eidascsr.controls.type;
    if ((value.trim() !== '')) {
      if ((value || '').trim()) {
        controller.setErrors(null);   // 1
        const tempEmails = controller.value; // 2
        tempEmails.push(value.trim());
        controller.setValue(tempEmails);     // 3
        if (controller.valid) {              // 4
          controller.markAsDirty();
          this.typeInput.nativeElement.value = '';                              // 5
        } else {
          const index = controller.value.findIndex(value1 => value1 === value.trim());
          if (index !== -1) {
            controller.value.splice(index, 1);           // 6
          }
        }
        this.typeInput.nativeElement.value = '';
      }
    } else {
      controller.updateValueAndValidity();
    }
  }

  private _filter(value: string): string[] {
    const controller = this.eidascsr.controls.type;
    const filteredArray = this.allTypes.filter(type => !controller.value.includes(type));
    return filteredArray;
  }

}
