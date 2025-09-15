import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'lcov'],
      reportsDirectory: './coverage',
      thresholds: {
        statements: 90,
        branches: 75,
        functions: 100,
        lines: 90,
      },
    },
    include: ['test/**/*.test.js'],
  },
});
