mod scalar_field;
mod test;
pub mod bjj;

pub use crate::scalar_field::ScalarField;
use std::ops::{Add, Neg, Sub};

pub struct Curve<Params> {
    pub x: Field,
    pub y: Field,
}

/// Parametrises a Twisted Edwards curve
trait TECurveParameterTrait {
    fn a() -> Field;
    fn d() -> Field;
    fn gen() -> (Field, Field);
}

/// Defines methods that a valid Curve implementation must satisfy
pub trait CurveTrait<Params>: Add + Sub + Eq + Neg + Default {
    fn new(x: Field, y: Field) -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    fn dbl(self) -> Self;
    fn mul<let NScalarSlices: u32>(self, x: ScalarField<NScalarSlices>) -> Self;
    fn msm<let N: u32, let NScalarSlices: u32>(
        points: [Self; N],
        scalars: [ScalarField<NScalarSlices>; N],
    ) -> Self;

    fn eq(self, x: Self) -> bool {
        self == x
    }
    fn is_zero(self) -> bool {
        self == Self::zero()
    }

    fn is_on_curve(self) -> bool;
    fn assert_is_on_curve(self);
    fn assert_equal(self, other: Self);
}

impl<Params> std::default::Default for Curve<Params>
where
    Params: TECurveParameterTrait,
{
    fn default() -> Self {
        Curve::zero()
    }
}

impl<Params> std::ops::Add for Curve<Params>
where
    Params: TECurveParameterTrait,
{
    fn add(self, other: Self) -> Self {
        Curve::add_internal(self, other, Params::a(), Params::d())
    }
}

impl<Params> std::ops::Neg for Curve<Params> {
    fn neg(self) -> Self {
        Curve { x: -self.x, y: self.y }
    }
}

impl<Params> std::ops::Sub for Curve<Params>
where
    Params: TECurveParameterTrait,
{
    fn sub(self, other: Self) -> Self {
        Curve::add_internal(self, other.neg(), Params::a(), Params::d())
    }
}

impl<Params> std::cmp::Eq for Curve<Params> {
    fn eq(self, other: Self) -> bool {
        (self.x == other.x) & (self.y == other.y)
    }
}

impl<Params> std::convert::From<(Field, Field)> for Curve<Params> {
    /// Construct from tuple of field elements
    ///
    /// Use this method instead of `new` if you know x/y is on the curve
    fn from((x, y): (Field, Field)) -> Self {
        Curve { x, y }
    }
}

impl<Params> CurveTrait<Params> for Curve<Params>
where
    Params: TECurveParameterTrait,
{

    /// Construct a new point
    ///
    /// If you know the x/y coords form a valid point DO NOT USE THIS METHOD
    /// This method calls `assert_is_on_curve` which costs 3 gates.
    /// Instead, directly construct via Curve{x, y} or use from((x, y))
    fn new(x: Field, y: Field) -> Self {
        let result = Curve { x, y };
        result.assert_is_on_curve();
        result
    }

    fn zero() -> Self {
        Curve { x: 0, y: 1 }
    }

    fn one() -> Self {
        let (x, y) = Params::gen();
        Curve { x, y }
    }

    fn assert_is_on_curve(self) {
        let t0 = self.x * self.x;
        let t1 = self.y * self.y;
        std::as_witness(t0);
        std::as_witness(t1);
        let t2 = Params::a() * t0 + t1;
        let t3 = 1 + Params::d() * t0 * t1;
        assert(t2 == t3);
    }

    fn assert_equal(self, other: Self) {
        assert(self.x == other.x);
        assert(self.y == other.y);
    }

    fn is_on_curve(self) -> bool {
        let t0 = self.x * self.x;
        let t1 = self.y * self.y;
        std::as_witness(t0);
        std::as_witness(t1);
        let t2 = Params::a() * t0 + t1;
        let t3 = 1 + Params::d() * t0 * t1;
        (t2 == t3)
    }

    fn dbl(self) -> Self {
        Curve::dbl_internal(self, Params::a(), Params::d())
    }

    /// Compute `self * scalar` using the Straus method.
    fn mul<let NScalarSlices: u32>(self: Self, scalar: ScalarField<NScalarSlices>) -> Self {
        // Reject off-curve inputs at the boundary. The doubling and addition degeneracies that can under-constrain
        // an output are reachable only by off-curve points, so gating here makes scalar multiplication sound for
        // every caller regardless of call-site discipline. Costs 3 gates.
        self.assert_is_on_curve();
        let a = Params::a();
        let d = Params::d();

        let (table_x, table_y): ([Field; 16], [Field; 16]) = self.compute_straus_point_table(a, d);

        let idx = scalar.base4_slices[0] as u32;
        let mut accumulator: Self = Curve { x: table_x[idx], y: table_y[idx] };

        for i in 1..NScalarSlices {
            accumulator = accumulator.dbl_internal(a, d);
            accumulator = accumulator.dbl_internal(a, d);
            accumulator = accumulator.dbl_internal(a, d);
            accumulator = accumulator.dbl_internal(a, d);
            let idx = scalar.base4_slices[i] as u32;
            let x = table_x[idx];
            let y = table_y[idx];
            accumulator = accumulator.add_internal(Curve { x, y }, a, d);
        }

        if (scalar.skew) {
            accumulator = accumulator - self;
        }
        accumulator
    }

    /// Compute `points[0] * scalar[0] + ... + points[N-1] * scalar[N-1]`.
    fn msm<let N: u32, let NScalarSlices: u32>(
        points: [Self; N],
        scalars: [ScalarField<NScalarSlices>; N],
    ) -> Self {
        let a = Params::a();
        let d = Params::d();

        let mut point_tables: [([Field; 16], [Field; 16]); N] = [([0; 16], [0; 16]); N];
        for j in 0..N {
            point_tables[j] = points[j].compute_straus_point_table(a, d);
        }

        let idx = scalars[0].base4_slices[0] as u32;
        let mut accumulator: Self = Curve { x: point_tables[0].0[idx], y: point_tables[0].1[idx] };
        for j in 1..N {
            let idx = scalars[j].base4_slices[0] as u32;
            let P = Curve { x: point_tables[j].0[idx], y: point_tables[j].1[idx] };
            accumulator = accumulator.add_internal(P, a, d);
        }
        for i in 1..NScalarSlices {
            accumulator = accumulator.dbl_internal(a, d);
            accumulator = accumulator.dbl_internal(a, d);
            accumulator = accumulator.dbl_internal(a, d);
            accumulator = accumulator.dbl_internal(a, d);
            for j in 0..N {
                let idx = scalars[j].base4_slices[i] as u32;
                let x = point_tables[j].0[idx];
                let y = point_tables[j].1[idx];
                accumulator = accumulator.add_internal(Curve { x, y }, a, d);
            }
        }

        for j in 0..N {
            if (scalars[j].skew == true) {
                accumulator = accumulator - points[j];
            }
        }
        accumulator
    }
}

impl<Params> Curve<Params> {

    /// This method exists because of a Noir bug where `Params` cannot be accessed by an internal function
    /// called from internal function. e.g. compiler error if `mul` impl tries to call `add` :(
    fn add_internal(self, other: Self, a: Field, d: Field) -> Self {
        let x1 = self.x;
        let x2 = other.x;
        let y1 = self.y;
        let y2 = other.y;
        // Safety: the returned coordinates and lambda are constrained by the identities below.
        let (x, y, lambda) = unsafe { __add_unconstrained(x1, x2, y1, y2, a, d) };
        let x1x2 = x1 * x2;
        let x1y2 = x1 * y2;
        std::as_witness(x1x2);
        std::as_witness(x1y2);
        let x_lhs = x * lambda * d + x - x1y2; // equals y1x2
        let y_lhs = y * lambda * -d + y + x1x2 * a; // equals y1y2
        let y1x2 = y1 * x2;
        let y1y2 = y1 * y2;
        std::as_witness(y1x2);
        std::as_witness(y1y2);
        let y1y2x1x2 = y1y2 * x1x2;
        assert(x_lhs == y1x2);
        assert(y_lhs == y1y2);
        assert(y1y2x1x2 == lambda);
        Self { x, y }
    }

    /// This method exists because of a Noir bug where `Params` cannot be accessed by an internal function
    /// called from internal function. e.g. compiler error if `mul` impl tries to call `dbl` :(
    fn dbl_internal(self, a: Field, d: Field) -> Self {
        // Double via the complete unified addition law so the lambda term is constrained. The standalone doubling
        // discarded lambda (`let (x3, y3, _) = __add_unconstrained(...)`) and pinned x3/y3 only by
        // `x3*t1 = 2*x1*y1` and `y3*(2 - t1) = y1^2 - a*x1^2` (t1 = y1^2 + a*x1^2), leaving x3 free at t1 = 0 and
        // y3 free at t1 = 2. `add_internal` constrains lambda (`y1y2x1x2 == lambda`), so x3/y3 are fully
        // determined. BabyJubJub has `a` a square and `d` a non-square, so the twisted-Edwards law is complete and
        // doubling equals adding a point to itself (Bernstein-Birkner-Joye-Lange-Peters, "Twisted Edwards Curves",
        // eprint 2008/013).
        self.add_internal(self, a, d)
    }

    /// Compute the signed 4-bit lookup table used by Straus multiplication.
    fn compute_straus_point_table(self, a: Field, d: Field) -> ([Field; 16], [Field; 16]) {
        let mut table_x: [Field; 16] = [0; 16];
        let mut table_y: [Field; 16] = [0; 16];
        table_x[8] = self.x;
        table_y[8] = self.y;
        let D = self.dbl_internal(a, d);
        for i in 1..8 {
            let Q = Self { x: table_x[7 + i], y: table_y[7 + i] };
            let V = D.add_internal(Q, a, d);
            table_x[8 + i] = V.x;
            table_y[8 + i] = V.y;
        }
        for i in 0..8 {
            table_x[i] = -table_x[15 - i];
            table_y[i] = table_y[15 - i];
        }
        (table_x, table_y)
    }
}

unconstrained fn __add_unconstrained(
    x1: Field,
    x2: Field,
    y1: Field,
    y2: Field,
    a: Field,
    d: Field,
) -> (Field, Field, Field) {
    let lambda = y1 * y2 * x1 * x2;
    let y = (x1 * x2 * a - y1 * y2) / (lambda * d - 1);
    let x = (x1 * y2 + y1 * x2) / (lambda * d + 1);
    (x, y, lambda)
}
