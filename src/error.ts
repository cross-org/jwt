// error.ts
export class JWTValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "JWTValidationError";
    }
}

export class JWTFormatError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "JWTFormatError";
    }
}
