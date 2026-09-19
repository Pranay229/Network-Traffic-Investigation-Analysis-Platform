/**
 * Forensic Time and Date Utilities
 * Platform: Nova Cyber Spark™
 * 
 * Provides consistent timezone conversion, relative formatting,
 * and high-precision timestamp rendering across the platform.
 */

// Cache detected local timezone abbreviation
export function getLocalTimezoneName(): string {
  try {
    const formatter = new Intl.DateTimeFormat([], { timeZoneName: 'short' });
    const parts = formatter.formatToParts(new Date());
    const tzPart = parts.find((p) => p.type === 'timeZoneName');
    return tzPart ? tzPart.value : 'Local';
  } catch {
    return 'UTC';
  }
}

/**
 * Converts a Unix epoch float or ISO 8601 string into user's local timezone.
 * Example: "19 Sep 2026 13:24:31 IST"
 */
export function formatLocalDateTime(
  val: number | string | null | undefined,
  includeSeconds = true
): string {
  if (!val) return '—';

  let date: Date;
  if (typeof val === 'number') {
    // If epoch seconds (10 digits), convert to ms
    date = new Date(val > 1e11 ? val : val * 1000);
  } else {
    // String - if already formatted, try parsing
    date = new Date(val);
  }

  if (isNaN(date.getTime())) {
    return String(val);
  }

  const tzAbbr = getLocalTimezoneName();

  const pad = (n: number) => n.toString().padStart(2, '0');
  const day = pad(date.getDate());
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const month = months[date.getMonth()];
  const year = date.getFullYear();

  const hours = pad(date.getHours());
  const minutes = pad(date.getMinutes());
  const seconds = pad(date.getSeconds());

  const timeStr = includeSeconds ? `${hours}:${minutes}:${seconds}` : `${hours}:${minutes}`;
  return `${day} ${month} ${year} ${timeStr} ${tzAbbr}`;
}

/**
 * Formats high-precision capture timestamp preserving millisecond precision.
 * Example: "13:20:15.123"
 */
export function formatPreciseTimestamp(
  val: number | string | null | undefined
): string {
  if (val === null || val === undefined || val === '') return '—';

  // If string already has HH:MM:SS.mmm format
  if (typeof val === 'string') {
    if (val.includes(':') && (val.includes('.') || val.length >= 8)) {
      // If it's a full ISO like "2026-09-19 13:20:15.123", slice time part
      const parts = val.split(' ');
      if (parts.length > 1 && parts[1].includes(':')) {
        return parts[1];
      }
    }
  }

  const num = typeof val === 'number' ? val : parseFloat(val);
  if (!isNaN(num) && num > 0) {
    const date = new Date(num > 1e11 ? num : num * 1000);
    const pad = (n: number) => n.toString().padStart(2, '0');
    const ms = date.getMilliseconds().toString().padStart(3, '0');
    return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${ms}`;
  }

  return String(val);
}

/**
 * Returns human-friendly relative time such as "just now", "2m ago", "1h ago".
 */
export function formatRelativeTime(val: number | string | null | undefined): string {
  if (!val) return '—';

  let timeMs = 0;
  if (typeof val === 'number') {
    timeMs = val > 1e11 ? val : val * 1000;
  } else {
    timeMs = new Date(val).getTime();
  }

  if (isNaN(timeMs) || timeMs === 0) return '—';

  const diffSec = Math.floor((Date.now() - timeMs) / 1000);
  if (diffSec < 10) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

/**
 * Formats duration in seconds into clean human notation (e.g. "33s", "1m 15s").
 */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '0s';
  const sec = Math.round(seconds);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

/**
 * Formats byte size into readable human string (e.g. "24.8 MB", "775 KB").
 */
export function formatByteSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/**
 * Formats transfer rate (bytes per second) into readable notation (e.g. "775 KB/s", "12.4 MB/s").
 */
export function formatRate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec === null || bytesPerSec === undefined || isNaN(bytesPerSec)) return '0 B/s';
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  if (bytesPerSec < 1024 * 1024 * 1024) return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
  return `${(bytesPerSec / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}
