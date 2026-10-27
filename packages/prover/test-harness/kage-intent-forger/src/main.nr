//! A different circuit with swap_intent's public shape: it echoes any 27-word intent vector. Proved with
//! `noir-recursive`, its proof and VK have swap_intent's widths, so only swap_settle's INTENT_VK_HASH pin
//! stands between it and a settled swap.
use ::kage_lib::INTENT_PI_LEN;

fn main(intent: [Field; INTENT_PI_LEN]) -> pub [Field; INTENT_PI_LEN] {
    intent
}
