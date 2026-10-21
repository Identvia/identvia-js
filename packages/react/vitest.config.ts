import { defineConfig } from 'vitest/config';
export default defineConfig({ test: { include: ['test/**/*.test.tsx'], environment: 'happy-dom', environmentOptions: { happyDOM: { url: 'https://app.example.com/' } } } });
