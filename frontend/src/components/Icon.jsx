import React from "react";

const paths = {
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z",
  grid: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  scan: "M4 8V4h4 M16 4h4v4 M20 16v4h-4 M8 20H4v-4 M8 12h8",
  graph: "M5 5h4v4H5z M15 15h4v4h-4z M15 3h4v4h-4z M9 7h3v10h3 M12 5h3",
  arrow: "M5 12h14 M13 6l6 6-6 6",
  download: "M12 3v12 M7 10l5 5 5-5 M4 16v5h16v-5",
  search: "M10 17a7 7 0 1 1 0-14 7 7 0 0 1 0 14 M15 15l6 6",
  check: "M5 12l4 4L19 6",
  close: "M6 6l12 12 M6 18 18 6",
  clock: "M12 8v5l3 2 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0",
  code: "M8 5 2 12l6 7 M16 5l6 7-6 7 M14 3l-4 18",
  help: "M9 8a3 3 0 0 1 6 0c0 2-3 2-3 5 M12 17h.01 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0",
  alert: "M12 9v4 M12 17h.01 M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z",
  zap: "M13 2L3 14h9l-1 8 10-12h-9l1-8z",
  copy: "M8 4v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7.242a2 2 0 0 0-.602-1.43L16.083 2.57A2 2 0 0 0 14.685 2H10a2 2 0 0 0-2 2z M16 18v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h2",
  external: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6 M15 3h6v6 M10 14L21 3",
  layers: "M12 2L2 7l10 5 10-5-10-5z M2 17l10 5 10-5 M2 12l10 5 10-5",
  filter: "M22 3H2l8 9.46V19l4 2v-8.54L22 3z",
  refresh: "M21 12a9 9 0 1 1-2.636-6.364M21 3v6h-6",
  terminal: "M4 17l6-6-6-6 M12 19h8",
  commit: "M12 3v6 M12 15v6 M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  chevronDown: "M6 9l6 6 6-6",
  chevronRight: "M9 18l6-6-6-6",
  chevronUp: "M18 15l-6-6-6 6",
  sparkles: "M12 3l1.912 5.885L20 10.5l-5.088 1.615L13 18l-1.912-5.885L6 10.5l5.088-1.615L12 3z",
  diff: "M12 3v18 M3 12h18",
  server: "M2 6a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6zm0 9a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-3zm4-7h.01M6 18h.01",
};

export default function Icon({ name, size = 20, ...props }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={{ display: "inline-block", verticalAlign: "middle", flexShrink: 0 }}
      {...props}
    >
      <path d={paths[name] || paths.shield} />
    </svg>
  );
}
