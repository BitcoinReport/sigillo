// Previene una console aggiuntiva su Windows in release, senza toccare quella di debug.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sigillo_lib::run();
}
