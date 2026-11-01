/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0B0F17",
          card: "#111827",
          border: "#1F2937",
          subtle: "#1E293B",
          accent: "#38BDF8",
        },
        healthy: {
          DEFAULT: "#10B981", // emerald
          bg: "rgba(16, 185, 129, 0.12)",
          border: "rgba(16, 185, 129, 0.3)",
        },
        elevated: {
          DEFAULT: "#F59E0B", // amber
          bg: "rgba(245, 158, 11, 0.12)",
          border: "rgba(245, 158, 11, 0.3)",
        },
        lockdown: {
          DEFAULT: "#F43F5E", // rose/red
          bg: "rgba(244, 63, 94, 0.15)",
          border: "rgba(244, 63, 94, 0.4)",
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      },
    },
  },
  plugins: [],
}
