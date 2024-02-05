use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};

use gmp_mpfr_sys::gmp;
use serde::{Deserialize, Serialize};

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

macro_rules! init_randstate {
    ($var:ident) => {
        let mut $var: MaybeUninit<gmp::randstate_t> = MaybeUninit::uninit();
        let $var = unsafe {
            gmp::randinit_mt($var.as_mut_ptr());
            gmp::randseed_ui($var.as_mut_ptr(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
            &mut $var.assume_init()
        };
    };
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ReturnData {
    pub g: String,

    pub t: u64,
    pub two_t: String,
    pub two_two_t: String,

    pub p: String,
    pub q: String,
    pub n: String,

    pub p_minus_one: String,
    pub q_minus_one: String,
    pub pi_n: String,

    pub quotient: String,
    pub remainder: String,
}

#[derive(Clone, Copy)]
pub struct Vdf {
    lambda: gmp::bitcnt_t,
    base: i32,
}

impl Vdf {
    pub fn new(lambda: u64, base: i32) -> Vdf {
        Vdf { lambda, base }
    }

    fn generate_prime(rop: *mut gmp::mpz_t, rstate: *mut gmp::randstate_t, n: gmp::bitcnt_t) {
        unsafe {
            gmp::mpz_urandomb(rop, rstate, n);
            gmp::mpz_nextprime(rop, rop);
        };
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

    /// Sets up the VDF for a given time parameter `_t`.
    pub fn setup(&self, _t: u64) -> String {
        init_randstate!(rstate);
        init_big_int!(p);
        init_big_int!(q);
        Vdf::generate_prime(p, rstate, self.lambda / 2);
        Vdf::generate_prime(q, rstate, self.lambda / 2);
        init_big_int!(n);
        init_big_int!(pi_n);
        init_big_int!(g);

        init_big_int!(two_t);
        init_big_int!(two_two_t);

        init_big_int!(remainder);
        init_big_int!(quotient);
        init_big_int!(p_minus_one);
        init_big_int!(q_minus_one);

        unsafe {
            // n = p * q, pi_n = (p - 1)(q - 1)
            gmp::mpz_mul(n, p, q);
            gmp::mpz_sub_ui(p_minus_one, p, 1);
            gmp::mpz_sub_ui(q_minus_one, q, 1);
            gmp::mpz_mul(pi_n, p_minus_one, q_minus_one);

            // !!!g value should be checked again!!!
            // 0 <= g < n-1, random integer
            gmp::mpz_urandomm(g, rstate, n);

            // trapdoor = 2^(2^t) mod pi_n
            gmp::mpz_ui_pow_ui(two_t, 2, _t);
            gmp::mpz_ui_pow_ui(two_two_t, 2, gmp::mpz_get_ui(two_t));

            gmp::mpz_mod(remainder, two_two_t, pi_n);
            gmp::mpz_fdiv_q(quotient, two_two_t, pi_n);
        }

        let g_string = Vdf::mpz_t_to_string(g, self.base);

        let two_t_string = Vdf::mpz_t_to_string(two_t, self.base);
        let two_two_t_string = Vdf::mpz_t_to_string(two_two_t, self.base);

        let p_string = Vdf::mpz_t_to_string(p, self.base);
        let q_string = Vdf::mpz_t_to_string(q, self.base);
        let n_string = Vdf::mpz_t_to_string(n, self.base);

        let p_minus_one_string = Vdf::mpz_t_to_string(p_minus_one, self.base);
        let q_minus_one_string = Vdf::mpz_t_to_string(q_minus_one, self.base);
        let pi_n_string = Vdf::mpz_t_to_string(pi_n, self.base);

        let quotient_string = Vdf::mpz_t_to_string(quotient, self.base);
        let remainder_string = Vdf::mpz_t_to_string(remainder, self.base);

        let r_data = ReturnData {
            g: g_string,

            t: _t,
            two_t: two_t_string,
            two_two_t: two_two_t_string,

            p: p_string,
            q: q_string,
            n: n_string,

            p_minus_one: p_minus_one_string,
            q_minus_one: q_minus_one_string,
            pi_n: pi_n_string,
            quotient: quotient_string,
            remainder: remainder_string,
        };

        serde_json::to_string(&r_data).unwrap()
    }

    /// Evaluates the VDF for a given time parameter `_t`, group element `_g`, and modulus `_n`.
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

    /// Evaluates the VDF with a trapdoor for a given time parameter `_t`, group element `_g`,
    /// modulus `_n`, and trapdoor `_trapdoor`.
    pub fn evaluate_with_trapdoor(&self, _t: u64, _g: String, _n: String, _trapdoor: String) -> String {
        init_big_int_from_string!(g, _g, self.base);
        init_big_int_from_string!(n, _n, self.base);
        init_big_int_from_string!(trapdoor, _trapdoor, self.base);
        init_big_int!(y);

        unsafe {
            // y = g^trapdoor mod n
            gmp::mpz_powm(y, g, trapdoor, n);
        }

        // mpz_t -> String
        Vdf::mpz_t_to_string(y, self.base)
    }
}
