// Mock for import.meta.env in Jest
globalThis.import = globalThis.import || {};
globalThis.import.meta = globalThis.import.meta || { env: {} };
