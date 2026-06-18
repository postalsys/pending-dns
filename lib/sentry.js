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
            // captures, flushes and exits the worker so the supervisor restarts it
            Sentry.onUncaughtExceptionIntegration(),
            // captures and warns, but does not exit (matches the previous behaviour)
            Sentry.onUnhandledRejectionIntegration({ mode: 'warn' })
        ],
        initialScope: {
            tags: { worker, app: packageData.name }
        }
    });

    // Signals to the worker bootstraps that an error reporter with its own
    // crash handler is active, so closeProcess() should let Sentry flush and
    // exit instead of exiting immediately (which would drop the in-flight event).
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
