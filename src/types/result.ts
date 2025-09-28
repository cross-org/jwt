// result.ts

/**
 * A Result type for handling operations that can either succeed or fail.
 * This enables functional error handling patterns without throwing exceptions.
 */
export type Result<T, E = Error> = Ok<T> | Err<E>;

/**
 * Represents a successful result containing a value.
 */
export class Ok<T> {
    readonly success = true as const;
    readonly error = false as const;

    constructor(public readonly value: T) {}

    /**
     * Maps the success value to a new value using the provided function.
     */
    map<U>(fn: (value: T) => U): Result<U, never> {
        return new Ok(fn(this.value));
    }

    /**
     * Maps the success value to a new Result using the provided function.
     */
    flatMap<U, F>(fn: (value: T) => Result<U, F>): Result<U, F> {
        return fn(this.value);
    }

    /**
     * Returns the success value or the provided default value.
     */
    unwrapOr(_defaultValue: T): T {
        return this.value;
    }

    /**
     * Returns the success value or throws an error if this is an error result.
     */
    unwrap(): T {
        return this.value;
    }

    /**
     * Returns the success value or throws the provided error message.
     */
    unwrapOrThrow(_errorMessage: string): T {
        return this.value;
    }

    /**
     * Returns true if this is a success result.
     */
    isOk(): this is Ok<T> {
        return true;
    }

    /**
     * Returns false if this is an error result.
     */
    isErr(): this is Err<never> {
        return false;
    }
}

/**
 * Represents an error result containing an error.
 */
export class Err<E> {
    readonly success = false as const;
    readonly error = true as const;

    constructor(public readonly errorValue: E) {}

    /**
     * Maps the error value to a new error using the provided function.
     */
    map<U>(_fn: (value: never) => U): Result<U, E> {
        return this as Result<U, E>;
    }

    /**
     * Maps the error value to a new Result using the provided function.
     */
    flatMap<U, F>(_fn: (value: never) => Result<U, F>): Result<U, F> {
        return this as unknown as Result<U, F>;
    }

    /**
     * Returns the provided default value since this is an error result.
     */
    unwrapOr<T>(defaultValue: T): T {
        return defaultValue;
    }

    /**
     * Throws the error since this is an error result.
     */
    unwrap(): never {
        throw this.errorValue;
    }

    /**
     * Throws the provided error message since this is an error result.
     */
    unwrapOrThrow(errorMessage: string): never {
        throw new Error(errorMessage);
    }

    /**
     * Returns false since this is an error result.
     */
    isOk(): this is Ok<never> {
        return false;
    }

    /**
     * Returns true since this is an error result.
     */
    isErr(): this is Err<E> {
        return true;
    }
}

/**
 * Creates a successful Result containing the provided value.
 */
export function ok<T>(value: T): Ok<T> {
    return new Ok(value);
}

/**
 * Creates an error Result containing the provided error.
 */
export function err<E>(error: E): Err<E> {
    return new Err(error);
}

/**
 * Utility function to wrap a function that might throw into a Result.
 */
export async function tryCatch<T, E = Error>(
    fn: () => Promise<T> | T,
): Promise<Result<T, E>> {
    try {
        const result = await fn();
        return ok(result);
    } catch (error) {
        return err(error as E);
    }
}

/**
 * Utility function to wrap a synchronous function that might throw into a Result.
 */
export function tryCatchSync<T, E = Error>(fn: () => T): Result<T, E> {
    try {
        const result = fn();
        return ok(result);
    } catch (error) {
        return err(error as E);
    }
}
