import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: ["libs/*/ts", "web/*", { test: { name: "repo", include: ["tests/**/*.test.ts"] } }],
  },
});
