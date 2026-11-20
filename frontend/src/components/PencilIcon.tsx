import "./PencilIcon.css";
export type IconName = "link" | "search" | "chart" | "puzzle" | "party";

// Hand-drawn look: wobbly open paths, doubled strokes, and a graphite-roughening filter.
const PATHS: Record<IconName, string[]> = {
  link: [
    "M13 19 C9.5 22.5 5.5 22 4.5 18.5 C3.8 16 5 14.5 7.5 12 L10.5 9 C13 6.8 16 7.4 17 9.8",
    "M19 13 C22.5 9.5 26.5 10 27.5 13.5 C28.2 16 27 17.5 24.5 20 L21.5 23 C19 25.2 16 24.6 15 22.2",
    "M12 20.5 C14.5 18 17.5 15 20 12.5",
  ],
  search: [
    "M13.5 5 C19 4.6 23.5 8.5 23.2 14 C22.9 19.5 18.5 23 13.2 22.6 C8 22.2 4.5 18 5 13 C5.4 8.6 9 5.3 13.5 5 Z",
    "M20 20.5 C23 24 26 27 28 28.5 M8.5 12 C9 9.8 10.8 8.5 12.8 8.2",
  ],
  chart: [
    "M5 4.5 C5.3 11 4.8 20 5.2 27.5 C12 27.2 20 27.8 28 27.3",
    "M9.5 27 C9.2 22 9.8 19 9.4 17 C11 16.8 12 17.2 13 17 C13.2 20 12.8 24 13 27",
    "M16.5 27 C16.2 20 16.8 14 16.5 11 C18 10.8 19.5 11.2 20.2 11 C20 16 20.4 22 20.2 27",
    "M23.5 27 C23.3 17 23.7 9 23.4 6 C25 5.8 26.3 6.3 27 6 C26.8 13 27.2 20 27 27",
  ],
  puzzle: [
    "M6 9 C10 8.7 12 9.2 14 8.8 C13 5.5 14.5 3.8 17 4 C19.5 4.2 20.5 6 19.2 8.8 C21.5 9.2 24 8.8 26 9.2 C26.3 12 26 14 25.8 16 C28.5 15 30 17 29.5 19.2 C29 21.5 27 22.5 25.6 21.6 C25.8 24 26 26 25.8 27.5 C20 27.8 14 27.2 6.3 27.6 C5.8 20 6.4 14 6 9 Z",
  ],
  party: [
    "M5 27 C8 18 11 12 13.5 10.5 C17 15 21 19 26.5 21.5 C18 25 11 27 5 27 Z",
    "M17 6 L18 9 M22 8 L20.5 10.5 M24.5 14 L27.5 13 M13 4.5 L12.5 7.5",
  ],
};

export default function PencilIcon({ name, size = 32 }: { name: IconName; size?: number }) {
  return (
    <svg className="pencil-icon" width={size} height={size} viewBox="0 0 32 32" fill="none"
      stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <defs>
        <filter id="graphite" x="-10%" y="-10%" width="120%" height="120%">
          <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="3" result="n" />
          <feDisplacementMap in="SourceGraphic" in2="n" scale="1.1" />
        </filter>
      </defs>
      <g filter="url(#graphite)">
        {PATHS[name].map((d, i) => <path key={`a${i}`} d={d} strokeWidth="1.4" opacity="0.9" />)}
        {/* second, offset pass = pencil sketch doubling */}
        <g transform="translate(0.5 0.4) rotate(0.6 16 16)" opacity="0.45">
          {PATHS[name].map((d, i) => <path key={`b${i}`} d={d} strokeWidth="0.8" />)}
        </g>
      </g>
    </svg>
  );
}
