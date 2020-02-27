import { ClipboardModule } from '@angular/cdk/clipboard';
import { CommonModule } from '@angular/common';
import { FlexLayoutModule } from '@angular/flex-layout';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatDividerModule } from '@angular/material/divider';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatStepperModule } from '@angular/material/stepper';
import { MatToolbarModule } from '@angular/material/toolbar';
import { NgcCookieConsentConfig, NgcCookieConsentModule } from 'ngx-cookieconsent';
import { NgModule } from '@angular/core';
import { defaultDataServiceConfig } from './default-service.config';
import { DefaultDataServiceConfig } from './default-data-service-config';
import { HttpClientModule } from '@angular/common/http';
const cookieConfig: NgcCookieConsentConfig = {
  cookie: {
    domain: 'localhost' // or 'your.domain.com' // it is mandatory to set a domain, for cookies to work properly (see https://goo.gl/S2Hy2A)
  },
  palette: {
    popup: {
      background: '#000'
    },
    button: {
      background: '#f1d600'
    }
  },
  theme: 'edgeless',
  type: 'opt-out'
};

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    FlexLayoutModule,

    MatButtonModule,
    MatCardModule,
    MatInputModule,
    MatToolbarModule,
    MatSelectModule,
    MatStepperModule,
    MatDividerModule,
    ClipboardModule,
    MatIconModule,
    NgcCookieConsentModule.forRoot(cookieConfig)
  ],
  declarations: [],
  exports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    FlexLayoutModule,
    HttpClientModule,

    MatButtonModule,
    MatCardModule,
    MatInputModule,
    MatToolbarModule,
    MatSelectModule,
    MatStepperModule,
    MatDividerModule,
    ClipboardModule,
    MatIconModule,
  ],
  providers: [
    { provide: DefaultDataServiceConfig, useValue: defaultDataServiceConfig }
],
})
export class SharedModule { }
