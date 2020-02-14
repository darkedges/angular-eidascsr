
import * as asn1js from 'asn1js';
import AttributeTypeAndValue from 'pkijs/src/AttributeTypeAndValue';

export interface CompetentAuthority {
    // Name of the authority, e.g. 'Financial Conduct Authority'.
    Name: string;
    // NCA identifier of the authority, e.g. 'GB-FCA'.
    ID: string;
}

export interface Role {
    // Name of the authority, e.g. 'Financial Conduct Authority'.
    Name: string;
    // NCA identifier of the authority, e.g. 'GB-FCA'.
    ID: number;
    ShortName: string;
}

type CompetentAuthorityType = Record<string, CompetentAuthority>;
type RoleMapType = Record<string, Role>;

export const RoleAccountServicing: Role = { ID: 1, Name: 'Role Account Servicing', ShortName: 'PSP_AS' };
export const RolePaymentInitiation: Role = { ID: 2, Name: 'Role Payment Initiation', ShortName: 'PSP_PI' };
export const RoleAccountInformation: Role = { ID: 3, Name: 'Role Account Information', ShortName: 'PSP_AI' };
export const RolePaymentInstrument: Role = { ID: 4, Name: 'Role Payment Instrument', ShortName: 'PSP_IC' };

// Need to work out how to fix this
export const roles: Role[] = [
    RoleAccountServicing,
    RolePaymentInitiation,
    RoleAccountInformation,
    RolePaymentInstrument
];

export const caMap: CompetentAuthorityType = {
    AT: {
        ID: 'AT-FMA',
        Name: 'Austria Financial Market Authority',
    },
    BE: {
        ID: 'BE-NBB',
        Name: 'National Bank of Belgium',
    },
    BG: {
        ID: 'BG-BNB',
        Name: 'Bulgarian National Bank',
    },
    HR: {
        ID: 'HR-CNB',
        Name: 'Croatian National Bank',
    },
    CY: {
        ID: 'CY-CBC',
        Name: 'Central Bank of Cyprus',
    },
    CZ: {
        ID: 'CZ-CNB',
        Name: 'Czech National Bank',
    },
    DK: {
        ID: 'DK-DFSA',
        Name: 'Danish Financial Supervisory Authority',
    },
    EE: {
        ID: 'EE-FI',
        Name: 'Estonia Financial Supervisory Authority',
    },
    FI: {
        ID: 'FI-FINFSA',
        Name: 'Finnish Financial Supervisory Authority',
    },
    FR: {
        ID: 'FR-ACPR',
        Name: 'Prudential Supervisory and Resolution Authority',
    },
    DE: {
        ID: 'DE-BAFIN',
        Name: 'Federal Financial Supervisory Authority',
    },
    GR: {
        ID: 'GR-BOG',
        Name: 'Bank of Greece',
    },
    HU: {
        ID: 'HU-CBH',
        Name: 'Central Bank of Hungary',
    },
    IS: {
        ID: 'IS-FME',
        Name: 'Financial Supervisory Authority',
    },
    IE: {
        ID: 'IE-CBI',
        Name: 'Central Bank of Ireland',
    },
    IT: {
        ID: 'IT-BI',
        Name: 'Bank of Italy',
    },
    LI: {
        ID: 'LI-FMA',
        Name: 'Financial Market Authority Liechtenstein',
    },
    LV: {
        ID: 'LV-FCMC',
        Name: 'Financial and Capital Markets Commission',
    },
    LT: {
        ID: 'LT-BL',
        Name: 'Bank of Lithuania',
    },
    LU: {
        ID: 'LU-CSSF',
        Name: 'Commission for the Supervision of Financial Sector',
    },
    NO: {
        ID: 'NO-FSA',
        Name: 'The Financial Supervisory Authority of Norway',
    },
    MT: {
        ID: 'MT-MFSA',
        Name: 'Malta Financial Services Authority',
    },
    NL: {
        ID: 'NL-DNB',
        Name: 'The Netherlands Bank',
    },
    PL: {
        ID: 'PL-PFSA',
        Name: 'Polish Financial Supervision Authority',
    },
    PT: {
        ID: 'PT-BP',
        Name: 'Bank of Portugal',
    },
    RO: {
        ID: 'RO-NBR',
        Name: 'National bank of Romania',
    },
    SK: {
        ID: 'SK-NBS',
        Name: 'National Bank of Slovakia',
    },
    SI: {
        ID: 'SI-BS',
        Name: 'Bank of Slovenia',
    },
    ES: {
        ID: 'ES-BE',
        Name: 'Bank of Spain',
    },
    SE: {
        ID: 'SE-FINA',
        Name: 'Swedish Financial Supervision Authority',
    },
    GB: {
        ID: 'GB-FCA',
        Name: 'Financial Conduct Authority',
    }
};

// QSIGNType is the ASN.1 object identifier for QSign certificates.
export const QSIGNType = new asn1js.ObjectIdentifier({ value: '0.4.0.1862.1.6.1' });
// QSEALType is the ASN.1 object identifier for QSeal certificates.
export const QSEALType = new asn1js.ObjectIdentifier({ value: '0.4.0.1862.1.6.2' });
// QWACType is the ASN.1 object identifier for QWA certificates.
export const QWACType = new asn1js.ObjectIdentifier({ value: '0.4.0.1862.1.6.3' });

export function competentAuthorityForCountryCode(code: string): CompetentAuthority | null {
    const ca = caMap[code];
    return ca;
}

export function serializeCompliant(qcRoles: Role[], ca: CompetentAuthority, t: asn1js.ObjectIdentifier): ArrayBuffer | null {
    const root = new asn1js.Sequence();
    // QcCompliance
    const QcCompliance = new asn1js.Sequence();
    QcCompliance.valueBlock.value.push(new asn1js.ObjectIdentifier({ value: '0.4.0.1862.1.1' }));
    root.valueBlock.value.push(QcCompliance);

    // QCStatement
    const Roles = new asn1js.Sequence();
    for (const rv of qcRoles) {
        const role = new AttributeTypeAndValue({
            type: `0.4.0.19495.1.${rv.ID}`,
            value: new asn1js.Utf8String({ value: rv.ShortName })
        });
        Roles.valueBlock.value.push(role.toSchema());
    }

    const rolesInfo = new asn1js.Sequence();
    rolesInfo.valueBlock.value.push(Roles);
    rolesInfo.valueBlock.value.push(new asn1js.Utf8String({ value: ca.Name }));
    rolesInfo.valueBlock.value.push(new asn1js.Utf8String({ value: ca.ID }));

    const QcStatement = new AttributeTypeAndValue({
        type: '0.4.0.19495.2',
        value: rolesInfo
    });
    root.valueBlock.value.push(QcStatement.toSchema());

    // QcPDS
    const pkiInfo = new asn1js.Sequence();
    pkiInfo.valueBlock.value.push(new asn1js.IA5String({ value: 'url=https://www.btrust.org/documents/pds/psd2_pds_en.pdf' }));
    pkiInfo.valueBlock.value.push(new asn1js.PrintableString({ value: 'language=en' }));
    const QcPDS = new AttributeTypeAndValue({
        type: '0.4.0.1862.1.5',
        value: pkiInfo
    });
    root.valueBlock.value.push(QcPDS.toSchema());

    // QCType
    const Detail = new asn1js.Sequence();
    Detail.valueBlock.value.push(t);

    const QCType = new AttributeTypeAndValue({
        type: '0.4.0.1862.1.6',
        value: Detail
    });
    root.valueBlock.value.push(QCType.toSchema());

    return root.toBER(false);
}

export function serializeCreditKudos(qcRoles: Role[], ca: CompetentAuthority, t: asn1js.ObjectIdentifier): ArrayBuffer | null {
    const root = new asn1js.Sequence();

    // QCType
    const Detail = new asn1js.Sequence();
    Detail.valueBlock.value.push(t);

    const QCType = new AttributeTypeAndValue({
        type: '0.4.0.1862.1.6',
        value: Detail
    });
    root.valueBlock.value.push(QCType.toSchema());

    // QCStatement
    const Roles = new asn1js.Sequence();
    for (const rv of qcRoles) {
        Roles.valueBlock.value.push(new asn1js.ObjectIdentifier({ value: `0.4.0.19495.1.${rv.ID}` }));
        Roles.valueBlock.value.push(new asn1js.Utf8String({ value: rv.ShortName }));
    }
    const Roless = new asn1js.Sequence();
    Roless.valueBlock.value.push(Roles);

    const rolesInfo = new asn1js.Sequence();
    rolesInfo.valueBlock.value.push(Roless);
    rolesInfo.valueBlock.value.push(new asn1js.Utf8String({ value: ca.Name }));
    rolesInfo.valueBlock.value.push(new asn1js.Utf8String({ value: ca.ID }));

    const QcStatement = new AttributeTypeAndValue({
        type: '0.4.0.19495.2',
        value: rolesInfo
    });
    root.valueBlock.value.push(QcStatement.toSchema());

    return root.toBER(false);
}
