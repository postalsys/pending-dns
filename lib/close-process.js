'use strict';

// Crash and shutdown handling shared by the supervisor (server.js) and every
// workers/<type>.js bootstrap, which are otherwise byte-identical here.
//
// The exit is ours, unconditionally. An error reporter gets a bounded window to
// flush the event first, but nothing may depend on the reporter to do the
// exiting: @sentry/node's onUncaughtException integration returns early when the
// subsystem runs in a worker thread rather than a forked process, and even in a
// process it stands down as soon as another uncaughtException listener is
// registered - lib/logger.js registers one. Leaving the exit to it means a
// crashed worker keeps running with `closing` already latched: deaf to SIGTERM,
// and silent about every crash that follows.
//
// Long enough for Sentry's own 2s flush to land first, short enough that a
// wedged reporter cannot keep a dead worker alive.
const FLUSH_GRACE = 2500;

// Installs the process-level crash and signal handlers and returns the pair the
// bootstraps need: `closeProcess` to start a shutdown, and `isClosing` so the
// respawn logic stops forking once one is underway.
const installCrashHandlers = logger => {
    let closing = false;

    const closeProcess = (code, errType, err) => {
        if (closing) {
            return;
        }
        closing = true;

        if (!code) {
            // clean shutdown, nothing to report
            setTimeout(() => process.exit(code), 10);
            return;
        }

        logger.fatal({
            msg: errType,
            _msg: errType,
            err
        });

        setTimeout(() => process.exit(code), logger.errorReportingEnabled ? FLUSH_GRACE : 10);
    };

    process.on('uncaughtException', err => closeProcess(1, 'uncaughtException', err));
    process.on('unhandledRejection', err => closeProcess(2, 'unhandledRejection', err));
    process.on('SIGTERM', () => closeProcess(0));
    process.on('SIGINT', () => closeProcess(0));

    return { closeProcess, isClosing: () => closing };
};

module.exports = { installCrashHandlers, FLUSH_GRACE };
