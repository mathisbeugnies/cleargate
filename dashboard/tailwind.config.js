/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          850: '#1e293b', // Custom darker slate if needed
          900: '#0f172a', // Deep background
        }
      }
    },
  },
  plugins: [],
}
