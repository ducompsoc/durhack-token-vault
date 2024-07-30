import { z } from "zod"

import { TokenType } from "@/token-type"

const rsaTokenAuthoritySchema = z.object({
  for: z.nativeEnum(TokenType),
  algorithm: z.literal("rsa"),
  publicKeyFilePath: z.string(),
  privateKeyFilePath: z.string(),
})

const hsaTokenAuthoritySchema = z.object({
  for: z.nativeEnum(TokenType),
  algorithm: z.literal("hsa"),
  secret: z.string(),
})

export const tokenAuthoritySchema = z.discriminatedUnion("algorithm", [
  rsaTokenAuthoritySchema,
  hsaTokenAuthoritySchema,
])

export const tokenVaultOptionsSchema = z.object({
  issuer: z.string().url(),
  audience: z.string().url(),
  accessTokenLifetime: z.number().positive(),
  refreshTokenLifetime: z.number().positive(),
  authorities: z.array(tokenAuthoritySchema),
})
