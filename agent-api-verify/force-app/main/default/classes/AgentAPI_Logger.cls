/**
 * AgentAPI_Logger
 * ─────────────────────────────────────────────────────────────────────
 * Debug output formatter for the MIAW Verified User flow.
 * Produces consistent, bordered, step-numbered output blocks designed
 * to be copied from Developer Console into docs/Slack.
 *
 * Every Step class uses this logger. See SETUP_GUIDE.md §4.2 for the
 * full list of support classes.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Logger {

    private static final String BORDER = '══════════════════════════════════════════════════════════════';
    private static final String THIN   = '──────────────────────────────────────────────────────────────';

    public static void banner(String title) {
        System.debug('\n' + BORDER);
        System.debug('  ' + title);
        System.debug(BORDER);
    }

    public static void step(Integer num, String title) {
        System.debug('\n' + THIN);
        System.debug('  STEP ' + num + ': ' + title);
        System.debug(THIN);
    }

    public static void detail(String label, String value) {
        System.debug('  [' + label + '] ' + value);
    }

    public static void json(String label, String jsonString) {
        System.debug('  [' + label + ']:');
        try {
            Object parsed = JSON.deserializeUntyped(jsonString);
            System.debug(JSON.serializePretty(parsed));
        } catch (Exception e) {
            System.debug('  ' + jsonString);
        }
    }

    public static void success(String message) {
        System.debug('  >> SUCCESS: ' + message);
    }

    public static void error(String message) {
        System.debug('  >> ERROR: ' + message);
    }

    public static void note(String message) {
        System.debug('  (!) NOTE: ' + message);
    }

    public static void httpRequest(String method, String url, String body) {
        System.debug('  --> ' + method + ' ' + url);
        if (String.isNotBlank(body)) {
            System.debug('  --> Body: ' + body.abbreviate(1500));
        }
    }

    public static void httpResponse(Integer statusCode, String body) {
        System.debug('  <-- ' + statusCode);
        if (String.isNotBlank(body)) {
            System.debug('  <-- Body: ' + body.abbreviate(2000));
        }
    }

    public static void config(Map<String, String> configMap) {
        System.debug('\n  Configuration:');
        for (String key : configMap.keySet()) {
            System.debug('    ' + key + ': ' + configMap.get(key));
        }
    }

    public static void separator() {
        System.debug(THIN);
    }
}
