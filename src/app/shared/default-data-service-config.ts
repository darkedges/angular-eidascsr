export abstract class DefaultDataServiceConfig {
    /** root path of the web api (default: 'api') */
    root?: string;
    /**
     * Known entity HttpResourceUrls.
     * HttpUrlGenerator will create these URLs for entity types not listed here.
     */
    /** Is a DELETE 404 really OK? (default: true) */
    delete404OK?: boolean;
    /** Simulate GET latency in a demo (default: 0) */
    getDelay?: number;
    /** Simulate save method (PUT/POST/DELETE) latency in a demo (default: 0) */
    saveDelay?: number;
    /** request timeout in MS (default: 0) */
    timeout?: number; //
}
