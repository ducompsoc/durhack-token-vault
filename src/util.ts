/**
 * Convert a Date object to 'seconds since UNIX epoch' format.
 * @param date
 */
export function epoch(date: Date) {
  return Math.floor(date.getTime() / 1000)
}
