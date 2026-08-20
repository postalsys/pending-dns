'use strict';

/* eslint global-require: 0 */

const config = require('wild-config');
const packageData = require('../package.json');
const logger = require('./logger');

// Initialize Sentry error tracking. With no DSN configured, error reporting stays
// disabled and logger.notifyError keeps its no-op default from lib/logger.js.
function initSentry(worker) {
    // The SENTRY_DSN environment variable overrides the configured value, otherwise
    // fall back to the wild-config value. An empty DSN disables error reporting.
    const dsn = (process.env.SENTRY_DSN || (config.sentry && config.sentry.dsn) || '').trim();
    if (!dsn) {
        return;
    }

    // require lazily, the SDK loads several hundred modules in every worker,
    // so only pay that cost when error tracking is actually enabled
    const Sentry = require('@sentry/node');

    Sentry.init({
        dsn,
        release: packageData.version,
        environment: process.env.NODE_ENV || 'development',
        // Error capture only: skip the OpenTelemetry setup and the default
        // integrations that patch http/fetch/console on hot paths. The uncaught
        // exception / unhandled rejection integrations are added back explicitly
        // so crashes are still reported (Bugsnag's autoDetectErrors did this).
        skipOpenTelemetrySetup: true,
        defaultIntegrations: false,
        integrations: [
            Sentry.eventFiltersIntegration(),
            Sentry.functionToStringIntegration(),
            Sentry.linkedErrorsIntegration(),
            Sentry.contextLinesIntegration(),
            Sentry.nodeContextIntegration(),
            Sentry.modulesIntegration(),
            // Both capture the crash and try to flush before exiting. Neither is
            // load-bearing for the exit itself - lib/close-process.js owns that,
            // because onUncaughtException stands down whenever another
            // uncaughtException listener is registered (lib/logger.js registers
            // one) or the subsystem runs in a worker thread.
            Sentry.onUncaughtExceptionIntegration(),
            // 'strict', not 'warn': 'warn' only logs, so the event would still be
            // in flight when close-process.js exits the worker.
            Sentry.onUnhandledRejectionIntegration({ mode: 'strict' })
        ],
        initialScope: {
            tags: { worker, app: packageData.name }
        }
    });

    // Signals to lib/close-process.js that a reporter is active, so a crashing
    // worker waits out a short flush window before exiting instead of exiting
    // immediately (which would drop the in-flight event).
    logger.errorReportingEnabled = true;

    logger.notifyError = (err, opts) => {
        let captureContext = {};
        if (opts && opts.level) {
            captureContext.level = opts.level;
        }
        if (opts && opts.context) {
            captureContext.tags = { context: opts.context };
        }
        if (opts && opts.meta && Object.keys(opts.meta).length) {
            captureContext.contexts = { error: opts.meta };
        }
        Sentry.captureException(err, captureContext);
    };

    logger.info({ msg: 'Enabled Sentry error reporting', worker });
}

module.exports = { initSentry };
