import { vi } from "vitest";

type Tx = Record<string, Record<string, unknown>>;
type TxFn = (tx: Tx) => Promise<unknown>;

/** Makes `tx.<model>.<method>(...)` reject inside every `prisma.$transaction(fn)`
 * callback, as a database failure part-way through would. Calls outside a
 * transaction are untouched, which is what lets a test prove rollback. Undo with
 * `vi.restoreAllMocks()`. */
export function failInTransactions(prisma: object, model: string, method: string): void {
  const target = prisma as { $transaction: (fn: TxFn, opts?: unknown) => Promise<unknown> };
  const original = target.$transaction.bind(target);
  vi.spyOn(target, "$transaction").mockImplementation((fn: TxFn, opts?: unknown) =>
    original(
      (tx) =>
        fn(
          new Proxy(tx, {
            get(t, prop: string) {
              if (prop !== model) return t[prop];
              return new Proxy(t[prop]!, { get: (m, name: string) => (name === method ? () => Promise.reject(new Error(`forced ${model}.${method} failure`)) : m[name]) });
            },
          })
        ),
      opts
    )
  );
}
