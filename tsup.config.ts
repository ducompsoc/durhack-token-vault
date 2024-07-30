import { defineConfig } from "tsup"

export default defineConfig([
  {
    entry: {
      index: "src/index.ts",
      lib: "src/lib.ts",
      "config-schema": "src/config-schema.ts",
      "authority/base": "src/authorities/base.ts",
      "authority/hsa": "src/authorities/hsa.ts",
      "authority/rsa": "src/authorities/rsa.ts",
    },
    format: ["esm"],
    target: "node18",
    sourcemap: false,
    clean: true,
    dts: true,
    outDir: "dist",
  },
])
