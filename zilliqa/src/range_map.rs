use std::cmp::{max, min};
use std::ops::Range;

/// A block map - a reasonably efficient, easily implementable representation of a collection of ranges.
#[derive(Debug)]
pub struct RangeMap {
    pub ranges: Vec<Range<u64>>,
}

impl RangeMap {
    /// A new, empty blockmap.
    pub fn new() -> Self {
        Self { ranges: vec![] }
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

    /// Add a range
    pub fn with_range(&mut self, range: &Range<u64>) -> &mut Self {
        // Find the right place to insert this range.
        // @todo use bisection search; for now, linear is easier to verify.
        for (idx, r) in self.ranges.iter().enumerate() {
            if r.start >= range.start {
                self.ranges.insert(idx, range.clone());
                return self;
            }
        }
        self.ranges.push(range.clone());
        return self;
    }

    /// Set difference - remove to_remove from self and return a pair of
    /// ( intersection, remain )
    pub fn diff_inter(&self, to_remove: &Self) -> (Self, Self) {
        //  We proceed in lock-step between the sets.
        let mut intersection = RangeMap::new();
        let mut remain = RangeMap::new();
        let mut self_iter = self.ranges.iter();
        let mut remove_iter = to_remove.ranges.iter();
        loop {
            if let Some(next_self) = self_iter.next() {
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
                        start: next_remove.end - 1,
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
                        remain.with_range(&x);
                    });
                    break;
                }
            } else {
                // We've run out of elements in the range - no more
                // can go in either result list.
            }
        }
        (intersection, remain)
    }
}
