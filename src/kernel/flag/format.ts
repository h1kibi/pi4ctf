/** Default format is deliberately generic: CTF prefixes are not always
 *  `flag{}`. Strict format is opt-in via project.flagFormat/ case.configure. */
export const DEFAULT_FLAG_FORMAT =
  '^(?:[A-Za-z][A-Za-z0-9_-]{0,31})\\{[^}\\r\\n]{1,512}\\}$';
