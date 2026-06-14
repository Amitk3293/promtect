/** Tailwind config for the Promtect landing page (static build). */
module.exports = {
  content: ['./index.html'],
  theme: {
    extend: {
      colors: {
        ink: '#0a0a0f',
        panel: '#12121a',
        accent: '#7c5cff',
        mint: '#43e0a8',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
};
