/// Page index arithmetic for a list view. Page counts are at most a few
/// thousand, so plain `int` is fine on every target.
Iterable<int> pageNumbers({required int total, required int perPage}) sync* {
  if (perPage <= 0) return;
  final pageCount = (total + perPage - 1) ~/ perPage;
  for (var page = 0; page < pageCount; page++) {
    yield page;
  }
}

/// Translate a page index to an SQL-style offset.
int offsetFor(int page, int perPage) => page * perPage;

/// Bit flags for feature switches. Values are tiny.
const int featureDarkMode = 1 << 0;
const int featureNotifications = 1 << 1;
const int featureLoyalty = 1 << 2;

bool isEnabled(int flags, int feature) => (flags & feature) != 0;

int withFeature(int flags, int feature) => flags | feature;

int withoutFeature(int flags, int feature) => flags & ~feature;
