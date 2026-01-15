use std::{
    cmp::{Ordering, max, min},
    default::Default,
    fmt,
    fmt::Display,
    ops::Range,
};

use serde::{Deserialize, Serialize};

/// A block map - a reasonably efficient, easily implementable representation of a collection of ranges.
/// Feel free to make this generic - we only ever need the u64 variant so I didn't bother.
/// I did look at crates to implement this, but they were all either overcomplicated, unmaintained, or both;
/// if you can find a good one, please do!
/// (but watch out for the semantics of int_diff() which are quite specialised).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RangeMap {
    /// ranges in this rangemap. These are held as non-overlapping non-empty ranges sorted in ascending order of start
    /// (and thus ascending order of end).
    pub ranges: Vec<Range<u64>>,
}

impl Display for RangeMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut got_one = false;
        for r in &self.ranges {
            if got_one {
                write!(f, ",")?;
            }
            if r.start < r.end + 1 {
                write!(f, "{}-{}", r.start, r.end - 1)?;
            } else {
                write!(f, "{}", r.start)?;
            }
            got_one = true;
        }
        Ok(())
    }
}

/// Merge two ranges, returning the combined range if you can and None if you can't
/// (which would mean that the ranges are disjoint).
fn merge_ranges(r1: &Range<u64>, r2: &Range<u64>) -> Option<Range<u64>> {
    // < and > because the ranges are half-open.
    if r1.end < r2.start || r1.start > r2.end {
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

/// Iterates over all the values in a range_map() by stepping through
/// each range and value in turn.
pub struct ItemIterator<'a> {
    map: &'a RangeMap,
    index: usize,
    value: u64,
}

impl<'a> ItemIterator<'a> {
    pub fn new(map: &'a RangeMap) -> Self {
        let value = if !map.ranges.is_empty() {
            map.ranges[0].start
        } else {
            0
        };
        Self {
            map,
            index: 0,
            value,
        }
    }
}

impl Iterator for ItemIterator<'_> {
    type Item = u64;

    /// Just count up through the ranges and values one by one until
    /// you get to the end.
    fn next(&mut self) -> Option<u64> {
        if self.index < self.map.ranges.len() {
            let range = &self.map.ranges[self.index];
            if self.value < range.end {
                let result = self.value;
                self.value += 1;
                return Some(result);
            } else {
                self.index += 1;
                if self.index < self.map.ranges.len() {
                    // All our ranges are at least 1 long
                    let result = &self.map.ranges[self.index].start;
                    self.value = result + 1;
                    return Some(*result);
                }
            }
        }
        None
    }
}

impl RangeMap {
    /// Create a new, empty RangeMap
    pub fn new() -> Self {
        Self::default()
    }

    /// Iterate over all the values in this RangeMap
    pub fn iter_values(&self) -> ItemIterator<'_> {
        ItemIterator::new(self)
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

    /// Create a RangeMap from a (half-open) Range.
    pub fn from_range(range: &Range<u64>) -> Self {
        Self {
            ranges: vec![range.clone()],
        }
    }

    /// Does this RangeMap contain any items?
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Mostly for testing - convert each Range to a pair of u64s (half-open) so that
    /// we can easily print it.
    pub fn to_tuple_vec(&self) -> Vec<(u64, u64)> {
        let mut result = Vec::new();
        for range in &self.ranges {
            result.push((range.start, range.end))
        }
        result
    }

    /// Again, mostly for testing - from a vector of (half-open!) range tuples.
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

    /// Add a range from a (closed!) tuple.
    pub fn with_closed_tuple(&mut self, tuple: (u64, u64)) -> &mut Self {
        self.with_range(&Range {
            start: tuple.0,
            end: tuple.1 + 1,
        })
    }

    /// Add a single element
    pub fn with_elem(&mut self, val: u64) -> &mut Self {
        self.with_range(&Range {
            start: val,
            end: val + 1,
        })
    }

    /// Add a range to this RangeMap, returning a reference to self.
    pub fn with_range(&mut self, range: &Range<u64>) -> &mut Self {
        if range.is_empty() {
            return self;
        }

        if self.is_empty() {
            self.ranges.push(range.clone());
            return self;
        }

        let last = self.ranges.last_mut().unwrap();
        // Optimise the common case where the new range overlaps with the current greatest range. Note that `end`
        // is exclusive, since `Range`s are half-open, but we still check `range.start <= last.end`. In the case
        // where `range.start == last.end`, the ranges are not overlapping, but adjacent and we can still merge
        // them immediately.
        if last.start <= range.start && range.start <= last.end {
            // If `range` is completely covered by `last`, there is nothing to do
            if range.end <= last.end {
                return self;
            }

            // Otherwise, expand `last` to cover `range`.
            last.end = range.end;
            return self;
        }
        // Optimise the common case where the new range is greater than all current ranges.
        if range.start > last.end {
            self.ranges.push(range.clone());
            return self;
        }

        // General case
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

        self
    }

    /// Canonicalise this RangeMap - go through the RangeMap merging
    /// adjacent ranges.
    /// Note: this function doesn't remove empty ranges.
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

    /// Non-destructively merge this range map with `ranges`, and
    /// return the result.
    pub fn with_range_map(&mut self, ranges: &Self) -> &mut Self {
        for r in ranges.ranges.iter() {
            self.with_range(r);
        }
        self
    }

    /// Return the max value in this range map
    pub fn max(&self) -> Option<u64> {
        self.ranges.last().map(|x| x.end - 1)
    }

    /// Remove any values in this RangeMap greater than limit
    /// (this is used to delete elements of "not here" ranges that we think
    /// might actually exist)
    pub fn with_closed_upper_limit(&mut self, limit: u64) -> &mut Self {
        let mut new_ranges: Vec<Range<u64>> = Vec::new();
        for r in self.ranges.iter() {
            if r.end > limit {
                if r.start < limit {
                    new_ranges.push(Range {
                        start: r.start,
                        end: limit + 1,
                    });
                }
                // Otherwise we start after the limit; nothing to do.
            } else {
                // Below the limit
                new_ranges.push(r.clone());
            }
        }
        self.ranges = new_ranges;
        self
    }

    /// Make an unlimited diff_inter() call - equivalent to diff_inter_limited(to_remove, None).
    pub fn diff_inter(&self, to_remove: &Self) -> (Self, Self) {
        self.diff_inter_limited(to_remove, None)
    }

    /// Set difference
    ///
    /// Returns `(intersection, diff)` where:
    ///  * `intersection` is the set of things in both `self` and `to_remove`.
    ///  * `diff` is the set of things in self with the set of things in `to-remove` removed.
    ///
    /// We will never put more than `limit` ranges in intersection -
    /// the rest will be returned in diff.
    ///
    /// This is used to limit the number of requests to a node. None
    /// == unlimited.  We also don't guarantee to find the "best"
    /// `limit` ranges - just no more than `limit`.
    pub fn diff_inter_limited(&self, to_remove: &Self, limit: Option<usize>) -> (Self, Self) {
        //  We proceed in lock-step between the sets.
        let mut intersection = RangeMap::new();
        let mut diff = RangeMap::new();
        let mut self_iter = self.ranges.iter();
        let mut current_self_iter: Option<Range<u64>> = self_iter.next().cloned();
        let mut remove_iter = to_remove.ranges.iter();
        let mut current_remove_iter: Option<Range<u64>> = remove_iter.next().cloned();
        // Termination: the outer loop terminates when we're through self.
        // Every step of the inner loop either
        //  - breaks, or
        //  - advances remain by one, or
        //  - breaks remain into a smaller range than it was before.
        while let Some(next_self) = &current_self_iter {
            if let Some(val) = limit
                && intersection.ranges.len() >= val
            {
                // Too many things in diff now - we're done. Append the rest of self and return.
                while let Some(n) = &current_self_iter {
                    diff.with_range(n);
                    current_self_iter = self_iter.next().cloned();
                }
                break;
            }
            if let Some(current_remove) = &current_remove_iter {
                // Things in self which are too small to remove - these will always
                // be too small to remove, because current_remove is nondecreasing.
                let early = Range {
                    start: next_self.start,
                    end: min(next_self.end, current_remove.start),
                };

                // Things in both self and to_remove - these will always be removed.
                let mid = Range {
                    start: max(next_self.start, current_remove.start),
                    end: min(next_self.end, current_remove.end),
                };

                if !early.is_empty() {
                    // This means that there is a space between next_self.start (what we have) and
                    // current_remove.start (what we want to remove). Once remove is removed, it will
                    // therefore still be here.
                    diff.with_range(&early);
                }

                if !mid.is_empty() {
                    intersection.with_range(&mid);
                }

                // now, either there are still things in self that too large for to_remove
                match next_self.end.cmp(&current_remove.end) {
                    Ordering::Greater => {
                        current_self_iter = Some(Range {
                            start: max(next_self.start, current_remove.end),
                            end: next_self.end,
                        });
                        // But next_self starts after current_remove.end, so we know that nothing in
                        // current_remove can possibly overlap this, so
                        current_remove_iter = remove_iter.next().cloned();
                    }
                    Ordering::Less => {
                        // or there are things still in to_remove that are not in self
                        current_remove_iter = Some(Range {
                            start: max(current_remove.start, next_self.end),
                            end: current_remove.end,
                        });
                        // But current_remove now starts after next_self, so we can advance self
                        current_self_iter = self_iter.next().cloned();
                    }
                    _ => {
                        // If we get here, then the two ended precisely at the same place. Advance both iterators.
                        current_self_iter = self_iter.next().cloned();
                        current_remove_iter = remove_iter.next().cloned();
                    }
                }
            } else {
                // We've run out of things to remove. Everything else must therefore remain.
                diff.with_range(next_self);
                current_self_iter = self_iter.next().cloned();
            }
        }
        // We've run out of things; anything left to remove will therefore not be removed and we're done.
        (intersection, diff)
    }

    // This is a very strange function. It limits the storage size of a RangeMap at the high end.
    // it's used when trimming the "no blocks for this view" cache to prevent memory exhaustion in large
    // networks.
    pub fn truncate(&mut self, max_ranges: usize) {
        self.ranges.truncate(max_ranges);
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use crate::range_map::RangeMap;

    #[test]
    fn simple() {
        let map1 = RangeMap::from_closed_interval(0, 10);
        let mut map2 = RangeMap::from_closed_interval(2, 15);
        map2.with_range(&Range { start: 8, end: 23 });

        assert_eq!(map1.max(), Some(10));
        assert_eq!(map2.max(), Some(22));
    }

    #[test]
    fn canonical() {
        let mut map = RangeMap::new();
        map.with_elem(1).with_elem(2).with_elem(3);
        assert_eq!(map.to_tuple_vec(), vec![(1, 4)]);
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
        let available = RangeMap::from_tuple_vec(&vec![(1, 8), (10, 12), (14, 33)]);
        let wanted = RangeMap::from_tuple_vec(&vec![(2, 3), (11, 14), (14, 20)]);

        println!("----------------------");
        let (can_get, still_need) = wanted.diff_inter(&available);

        // Things we want that we have also got.
        assert_eq!(
            can_get,
            RangeMap::from_tuple_vec(&vec![(2, 3), (11, 12), (14, 20)])
        );

        // Things we still want.
        assert_eq!(still_need, RangeMap::from_tuple_vec(&vec![(12, 14)]));
    }

    #[test]
    fn int_diff_2() {
        let have = RangeMap::from_tuple_vec(&vec![
            (0, 5),
            (6, 9),
            (10, 13),
            (15, 18),
            (19, 20),
            (22, 45),
            (46, 47),
        ]);
        let want = RangeMap::from_tuple_vec(&vec![(6, 47)]);
        let (get, still_want) = want.diff_inter(&have);

        assert_eq!(
            get,
            RangeMap::from_tuple_vec(&vec![
                (6, 9),
                (10, 13),
                (15, 18),
                (19, 20),
                (22, 45),
                (46, 47)
            ])
        );
        assert_eq!(
            still_want,
            RangeMap::from_tuple_vec(&vec![(9, 10), (13, 15), (18, 19), (20, 22), (45, 46)])
        );
    }

    #[test]
    fn int_diff_3() {
        let have = RangeMap::from_tuple_vec(&vec![(208, 8000)]);
        let to_remove = RangeMap::from_tuple_vec(&vec![(7820, 7827), (7889, 7903)]);
        println!("have = {have:?} to_remove = {to_remove:?}");
        let (get, still_want) = have.diff_inter(&to_remove);
        println!("get = {get:?} still_want = {still_want:?}");
        assert_eq!(
            get,
            RangeMap::from_tuple_vec(&vec![(7820, 7827), (7889, 7903)])
        );
        assert_eq!(
            still_want,
            RangeMap::from_tuple_vec(&vec![(208, 7820), (7827, 7889), (7903, 8000)])
        );
    }

    #[test]
    fn int_diff_4() {
        let have = RangeMap::from_tuple_vec(&vec![(0, 660), (661, 753), (1935, 1945)]);
        let to_remove = RangeMap::from_tuple_vec(&vec![(1871, 1872)]);
        println!("have = {have:?} to_remove = {to_remove:?}");
        let (get, still_want) = have.diff_inter(&to_remove);
        println!("get = {get:?} still_want = {still_want:?}");
        assert_eq!(get, RangeMap::from_tuple_vec(&vec![]));
        assert_eq!(
            still_want,
            RangeMap::from_tuple_vec(&vec![(0, 660), (661, 753), (1935, 1945)])
        );
    }

    #[test]
    fn iterator() {
        let map3 = RangeMap::from_tuple_vec(&vec![(1, 4), (6, 8), (9, 10)]);
        assert_eq!(
            map3.iter_values().collect::<Vec<u64>>(),
            vec![1, 2, 3, 6, 7, 9]
        );
    }

    #[test]
    fn limit() {
        let the_map = RangeMap::from_tuple_vec(&vec![
            (1, 5),
            (6, 9),
            (10, 13),
            (15, 18),
            (19, 20),
            (22, 45),
            (46, 47),
        ]);
        assert_eq!(
            the_map.clone().with_closed_upper_limit(20),
            &RangeMap::from_tuple_vec(&vec![(1, 5), (6, 9), (10, 13), (15, 18), (19, 20)])
        );
        assert_eq!(
            the_map.clone().with_closed_upper_limit(23),
            &RangeMap::from_tuple_vec(&vec![
                (1, 5),
                (6, 9),
                (10, 13),
                (15, 18),
                (19, 20),
                (22, 24)
            ])
        );
        assert_eq!(
            the_map.clone().with_closed_upper_limit(1),
            &RangeMap::from_tuple_vec(&vec![])
        );
        assert_eq!(the_map.clone().with_closed_upper_limit(9999), &the_map);
    }
}
