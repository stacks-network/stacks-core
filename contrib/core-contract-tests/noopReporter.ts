import type { UserConsoleLog } from "vitest";

import { DefaultReporter } from "vitest/reporters";

export default class LoggerReporter extends DefaultReporter {
  onInit() {}
  onPathsCollected() {}
  onCollected() {}
  onFinished() {
    return Promise.resolve();
  }
  onTaskUpdate() {}

  onWatcherStart() {
    return Promise.resolve();
  }
  onWatcherRerun() {
    return Promise.resolve();
  }

  onServerRestart() {}

  onProcessTimeou() {}

  onUserConsoleLog(log: UserConsoleLog) {}
}
