import { defineConfig } from 'vitest/config';
import {
  vitestSetupFilePath,
  getClarinetVitestsArgv,
} from '@stacks/clarinet-sdk/vitest';

/*
  In this file, Vitest is configured so that it works seamlessly with Clarinet and the Simnet.

  The `vitest-environment-clarinet` will initialise the clarinet-sdk
  and make the `simnet` object available globally in the test files.

  `vitestSetupFilePath` points to a file in the `@hirosystems/clarinet-sdk` package that does two things:
    - run `before` hooks to initialize the simnet and `after` hooks to collect costs and coverage reports.
    - load custom vitest matchers to work with Clarity values (such as `expect(...).toBeUint()`)

  The `getClarinetVitestsArgv()` will parse options passed to the command `vitest run --`
    - vitest run -- --manifest ./Clarinet.toml  # pass a custom path
    - vitest run -- --coverage --costs          # collect coverage and cost reports
*/

const setupFiles = [
  vitestSetupFilePath,
  // custom setup files can be added here
  process.env.SUPPRESS_CLARINET_LOGS ? './tests/suppress-stdout.js' : undefined,
].filter((s) => s !== undefined);

export default defineConfig({
  test: {
    environment: 'clarinet',
    pool: 'forks',
    // clarinet handles test isolation by resetting the simnet between tests
    isolate: false,
    maxWorkers: 1,
    setupFiles,
    environmentOptions: {
      clarinet: {
        ...getClarinetVitestsArgv(),
        // add or override options
      },
    },
  },
});
