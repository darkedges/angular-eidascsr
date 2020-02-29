import { FormControl } from '@angular/forms';

export class CustomValidators {

    static validateCertificateType(c: FormControl) {
        const EMAIL_REGEXP = [ 'QWAC' , 'QSEAL'];
        let inValid = null;
        c.value.forEach((item) => {
            if (EMAIL_REGEXP.indexOf(item) === -1) {
                inValid = { pattern: true };
            }
        });
        return inValid;
    }

    static validateRequired(c: FormControl) {
        if (c.value.length === 0) {
            return { required: true };
        } else {
            return null;
        }
    }
}
