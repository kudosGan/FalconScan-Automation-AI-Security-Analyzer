// Stands in for api/client.ts in the public website build, which has no server to talk to.
// Nothing calls it there (the session is static); it exists so none of the real API code is published.
export const api = {} as never;
