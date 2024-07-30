import ModuleError from "module-error"

type ModuleErrorOptions = ConstructorParameters<typeof ModuleError>[1]

export class TokenError extends ModuleError {
  constructor(message?: string, options?: ModuleErrorOptions) {
    super(message || "", options)
    this.name = "TokenError"
  }
}
