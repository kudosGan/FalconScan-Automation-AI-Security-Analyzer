import logoUrl from "../assets/falcon-scan-logo-report.png";

// Reports are saved and emailed as files, so the logo has to travel inside them as a data: URI.
let dataUri: string | null = null;

/** Resolves once the logo has been read; reports built before that fall back to the page's own logo URL. */
export const logoReady: Promise<void> = fetch(logoUrl)
  .then((r) => r.blob())
  .then((b) => new Promise<string>((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(String(fr.result));
    fr.onerror = () => rej(fr.error);
    fr.readAsDataURL(b);
  }))
  .then((u) => { dataUri = u; })
  .catch(() => { /* keep the fallback */ });

export const logoSrc = (): string => dataUri ?? new URL(logoUrl, location.href).href;
