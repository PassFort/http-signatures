#[cfg(not(test))]
macro_rules! info {
    ($($arg:tt)*) => {
        log::info!($($arg)*)
    };
}

#[cfg(test)]
macro_rules! info {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}
