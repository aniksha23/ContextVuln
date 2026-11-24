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
};
export default function Icon({ name, size = 20, ...props }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      <path d={paths[name] || paths.shield} />
    </svg>
  );
}
