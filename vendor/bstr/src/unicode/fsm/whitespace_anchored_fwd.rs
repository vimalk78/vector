// DO NOT EDIT THIS FILE. IT WAS AUTOMATICALLY GENERATED BY:
//
//   ucd-generate dfa --name WHITESPACE_ANCHORED_FWD --anchored --classes --premultiply --minimize --state-size 1 src/unicode/fsm/ \s+
//
// ucd-generate 0.2.9 is available on crates.io.

#[cfg(target_endian = "big")]
lazy_static::lazy_static! {
  pub static ref WHITESPACE_ANCHORED_FWD: ::regex_automata::DenseDFA<&'static [u8], u8> = {
    #[repr(C)]
    struct Aligned<B: ?Sized> {
        _align: [u8; 0],
        bytes: B,
    }

    static ALIGNED: &'static Aligned<[u8]> = &Aligned {
        _align: [],
        bytes: *include_bytes!("whitespace_anchored_fwd.bigendian.dfa"),
    };

    unsafe {
      ::regex_automata::DenseDFA::from_bytes(&ALIGNED.bytes)
    }
  };
}

#[cfg(target_endian = "little")]
lazy_static::lazy_static! {
  pub static ref WHITESPACE_ANCHORED_FWD: ::regex_automata::DenseDFA<&'static [u8], u8> = {
    #[repr(C)]
    struct Aligned<B: ?Sized> {
        _align: [u8; 0],
        bytes: B,
    }

    static ALIGNED: &'static Aligned<[u8]> = &Aligned {
        _align: [],
        bytes: *include_bytes!("whitespace_anchored_fwd.littleendian.dfa"),
    };

    unsafe {
      ::regex_automata::DenseDFA::from_bytes(&ALIGNED.bytes)
    }
  };
}
