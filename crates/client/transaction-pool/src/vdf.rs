use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::raw::c_char;

use gmp_mpfr_sys::gmp;

macro_rules! init_big_int {
    ($var:ident) => {
        let mut $var: MaybeUninit<gmp::mpz_t> = MaybeUninit::uninit();
        let $var = unsafe {
            gmp::mpz_init($var.as_mut_ptr());
            &mut $var.assume_init()
        };
    };
}

macro_rules! init_big_int_from_string {
    ($var:ident, $val:expr, $base:expr) => {
        let c_char = CString::new($val).unwrap().into_raw();
        let mut $var: MaybeUninit<gmp::mpz_t> = MaybeUninit::uninit();
        let $var = unsafe {
            gmp::mpz_init_set_str($var.as_mut_ptr(), c_char, $base);
            &mut $var.assume_init()
        };
    };
}

#[derive(Clone, Copy)]
pub struct Vdf {
    base: i32,
}

impl Vdf {
    pub fn new(base: i32) -> Vdf {
        Vdf { base }
    }

    fn mpz_t_to_string(data: &gmp::mpz_t, base: i32) -> String {
        let return_data;
        unsafe {
            let len = gmp::mpz_sizeinbase(data, base) + 2;
            let mut vector: Vec<u8> = Vec::with_capacity(len);
            gmp::mpz_get_str(vector.as_mut_ptr() as *mut c_char, base, data);
            return_data = CStr::from_ptr(vector.as_mut_ptr() as *mut c_char).to_str().unwrap().to_string();
        }
        return_data
    }

    pub fn evaluate(&self, _t: u64, _g: String, _n: String) -> String {
        init_big_int_from_string!(g, _g, self.base);
        init_big_int_from_string!(n, _n, self.base);
        init_big_int!(y);
        init_big_int!(exp);

        unsafe {
            // y = x^2^(2^t) mod n
            gmp::mpz_ui_pow_ui(exp, 2, _t); // 2^t
            gmp::mpz_ui_pow_ui(exp, 2, gmp::mpz_get_ui(exp)); // 2^{2^t}
            gmp::mpz_powm(y, g, exp, n); // g ^ {2^{2^t}} mod n y
        }

        // mpz_t -> String
        Vdf::mpz_t_to_string(y, self.base)
    }
}
