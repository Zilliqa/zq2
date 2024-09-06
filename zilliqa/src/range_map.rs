use std::cmp::{max, min};
use std::default::Default;
use std::ops::Range;

/// A block map - a reasonably efficient, easily implementable representation of a collection of ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeMap {
    pub ranges: Vec<Range<u64>>,
}

fn merge_ranges(r1: &Range<u64>, r2: &Range<u64>) -> Option<Range<u64>> {
    // <= / >= because std::ops:Range is half-open.
    if r1.end <= r2.start || r1.start >= r2.end {
        // Ranges are disjoint
        None
    } else {
        // We can merge them.
        Some(Range {
            start: std::cmp::min(r1.start, r2.start),
            end: std::cmp::max(r1.end, r2.end),
        })
    }
}

impl Default for RangeMap {
    fn default() -> Self {
        Self { ranges: vec![] }
    }
}

impl RangeMap {
    /// A new, empty blockmap.
    pub fn new() -> Self {
        Self::default()
    }

    /// From a single interval
    pub fn from_closed_interval(start: u64, end: u64) -> Self {
        Self {
            ranges: vec![Range {
                start,
                end: end + 1,
            }],
        }
    }

    /// From a range
    pub fn from_range(range: &Range<u64>) -> Self {
        Self {
            ranges: vec![range.clone()],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Mostly for testing.
    pub fn to_tuple_vec(&self) -> Vec<(u64, u64)> {
        let mut result = Vec::new();
        for range in &self.ranges {
            result.push((range.start, range.end))
        }
        result
    }

    /// Again, mostly for testing
    pub fn from_tuple_vec(vec: &Vec<(u64, u64)>) -> Self {
        let mut result = Self::new();
        for v in vec {
            result.with_range(&Range {
                start: v.0,
                end: v.1,
            });
        }
        result
    }

    /// Add a range
    pub fn with_range(&mut self, range: &Range<u64>) -> &mut Self {
        if !range.is_empty() {
            let mut inserted = false;
            for (idx, r) in self.ranges.iter().enumerate() {
                if r.start > range.start {
                    self.ranges.insert(idx, range.clone());
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                self.ranges.push(range.clone());
            }
            self.canonicalise();
        }
        self
    }

    fn canonicalise(&mut self) -> &mut Self {
        // Counts through the source list.
        let mut src = 1;
        // Counts through the target list.
        let mut dst = 0;
        while src < self.ranges.len() {
            let (first, second) = (&self.ranges[dst], &self.ranges[src]);
            if let Some(merged) = merge_ranges(first, second) {
                self.ranges[dst] = merged.clone();
            } else {
                // We can't merge.
                dst += 1;
                self.ranges[dst] = second.clone();
            }
            src += 1;
        }
        // If the merge_offset is 1, we didn't merge anything.
        self.ranges.truncate(dst + 1);
        self
    }

    pub fn with_range_map(&mut self, ranges: &Self) -> &mut Self {
        for r in ranges.ranges.iter() {
            self.with_range(r);
        }
        self
    }

    // Return the max value in this range map
    pub fn max(&self) -> Option<u64> {
        self.ranges.last().map(|x| x.end - 1)
    }

    /// Set difference - remove to_remove from self and return a pair of
    /// ( intersection, remain )
    pub fn diff_inter(&self, to_remove: &Self) -> (Self, Self) {
        //  We proceed in lock-step between the sets.
        let mut intersection = RangeMap::new();
        let mut remain = RangeMap::new();
        let mut self_iter = self.ranges.iter();
        let mut remove_iter = to_remove.ranges.iter();
        // When we have run out of ranges in self,
        // no more can ever be in the overlap.
        // no more can ever be in the things in self that are not in the overlap.
        // .. so we're done.
        while let Some(next_self) = self_iter.next() {
            if let Some(next_remove) = remove_iter.next() {
                let early = Range {
                    start: next_self.start,
                    end: next_remove.start,
                };
                let mid = Range {
                    start: max(next_self.start, next_remove.start),
                    end: min(next_self.end, next_remove.end),
                };
                let late = Range {
                    start: next_remove.end,
                    end: next_self.end,
                };

                if !early.is_empty() {
                    remain.with_range(&early);
                }
                if !mid.is_empty() {
                    intersection.with_range(&mid);
                }
                if !late.is_empty() {
                    remain.with_range(&late);
                }
            } else {
                // There is nothing more to remove.
                // The rest of self goes into the remain list
                self_iter.for_each(|x| {
                    remain.with_range(x);
                });
                break;
            }
        }
        (intersection, remain)
    }
}

#[cfg(test)]
mod tests {
    use crate::range_map::RangeMap;
    use std::ops::Range;

    #[test]
    fn simple() {
        let map1 = RangeMap::from_closed_interval(0, 10);
        let mut map2 = RangeMap::from_closed_interval(2, 15);
        map2.with_range(&Range { start: 8, end: 23 });

        assert_eq!(map1.max(), Some(10));
        assert_eq!(map2.max(), Some(22));
    }

    #[test]
    fn merge() {
        let mut map1 = RangeMap::new();
        map1.with_range(&Range { start: 5, end: 8 });
        map1.with_range(&Range { start: 13, end: 20 });
        map1.with_range(&Range { start: 3, end: 10 });
        map1.with_range(&Range { start: 20, end: 22 });
        map1.with_range(&Range { start: 30, end: 32 });
        map1.with_range(&Range { start: 19, end: 33 });

        // this should end up as...
        assert_eq!(map1.ranges.len(), 2);
        assert_eq!(map1.to_tuple_vec(), vec![(3, 10), (13, 33)]);
    }

    #[test]
    fn int_diff() {
        let map1 = RangeMap::from_tuple_vec(&vec![(1, 8), (10, 12), (14, 33)]);
        let map2 = RangeMap::from_tuple_vec(&vec![(2, 3), (11, 14), (14, 20)]);

        println!("----------------------");
        let (int, rem) = map1.diff_inter(&map2);
        assert_eq!(
            int,
            RangeMap::from_tuple_vec(&vec![(2, 3), (11, 12), (14, 20)])
        );
        assert_eq!(
            rem,
            RangeMap::from_tuple_vec(&vec![(1, 2), (3, 8), (10, 11), (20, 33)])
        );
    }
}
