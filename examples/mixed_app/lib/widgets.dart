/// UI state helpers: counts, indices and progress are all small.
int progressPercent(int loaded, int total) {
  if (total <= 0) return 0;
  return ((loaded * 100) ~/ total).clamp(0, 100);
}

int itemIndexForOffset(int offset, int itemExtent) {
  if (itemExtent <= 0) return 0;
  return offset ~/ itemExtent;
}

int nextPage(int current, int pageCount) =>
    current + 1 > pageCount ? pageCount : current + 1;

int scrollExtent(int itemCount, int itemExtent) => itemCount * itemExtent;
