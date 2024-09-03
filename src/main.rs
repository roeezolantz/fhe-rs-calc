use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, FheUint16, FheUint32};
use std::fmt::Debug;
use std::time::Instant;
use std::time::Duration;
use std::any::type_name;
use rayon::prelude::*;
use std::sync::{Arc, RwLock};
use lazy_static::lazy_static;
use std::io::{self, Write};
use std::panic::{self, UnwindSafe};

// Initialize the server key globally
lazy_static! {
    static ref SERVER_KEY: tfhe::ServerKey = generate_server_key();
}

fn init_server_key() {
    set_server_key(SERVER_KEY.clone());
}

fn generate_server_key() -> tfhe::ServerKey {
    let config = ConfigBuilder::default().build();
    let (_, server_key) = generate_keys(config);
    server_key
}

// Macro to implement the trait for FHE types
macro_rules! impl_fhe_operations {
    ($($fhe_type:ty => $num_type:ty),*) => {
        $(
            impl FheOperations<$num_type> for $fhe_type {
                fn encrypt(value: $num_type, client_key: &tfhe::ClientKey) -> Self {
                    tfhe::prelude::FheEncrypt::encrypt(value, client_key)
                }

                fn decrypt(&self, client_key: &tfhe::ClientKey) -> $num_type {
                    tfhe::prelude::FheDecrypt::decrypt(self, client_key)
                }

                fn plus(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self {
                    let a_val = a.read().unwrap().clone();
                    let b_val = b.read().unwrap().clone();
                    a_val + b_val
                }

                fn minus(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self {
                    let a_val = a.read().unwrap().clone();
                    let b_val = b.read().unwrap().clone();
                    a_val - b_val
                }

                fn mul(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self {
                    let a_val = a.read().unwrap().clone();
                    let b_val = b.read().unwrap().clone();
                    a_val * b_val
                }

                fn div(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self {
                    let a_val = a.read().unwrap().clone();
                    let b_val = b.read().unwrap().clone();
                    a_val / b_val
                }
            }
        )*
    };
}

// Define a trait for FHE operations
trait FheOperations<T> {
    fn encrypt(value: T, client_key: &tfhe::ClientKey) -> Self;
    fn decrypt(&self, client_key: &tfhe::ClientKey) -> T;
    fn plus(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self;
    fn minus(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self;
    fn mul(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self;
    fn div(a: &Arc<RwLock<Self>>, b: &Arc<RwLock<Self>>) -> Self;
}

// Apply macro to multiple FHE types
impl_fhe_operations! {
    FheUint8 => u8,
    FheUint16 => u16,
    FheUint32 => u32
}

// Utility function to perform an operation, measure time, and print the result
fn measure_and_execute<T, U, F>(
    encrypted_num1: Arc<RwLock<U>>,
    encrypted_num2: Arc<RwLock<U>>,
    client_key: &tfhe::ClientKey,
    operation: F,
    operation_name: &str,
) -> Result<Duration, String> where
    T: std::fmt::Display,
    U: FheOperations<T> + Clone + Send,
    F: FnOnce(&Arc<RwLock<U>>, &Arc<RwLock<U>>) -> U + Send + Sync + UnwindSafe,
{
    init_server_key();

    // Ensure the server key is set
    let result = panic::catch_unwind(|| {
        println!("Running monitored operation: {}", operation_name);
        let start = Instant::now();

        // Perform the operation
        let result = operation(&encrypted_num1, &encrypted_num2);

        // Measure the duration
        let duration: Duration = start.elapsed();

        // Decrypt and print the result
        let decrypted_result = result.decrypt(client_key);
        let a = encrypted_num1.read().unwrap().decrypt(client_key);
        let b = encrypted_num2.read().unwrap().decrypt(client_key);
        println!("Result of {} beween {}, {} = {}, Time Taken: {:?}", operation_name, a, b, decrypted_result, duration);
        io::stdout().flush().unwrap();
        return Ok::<(Duration, U), String>((duration, result));
    });

    if let Err(err) = result {
        let error_message = format!("Error in operation '{}': {:?}", operation_name, err);
        let cloned = error_message.clone();
        eprintln!("{}", error_message);
        io::stderr().flush().unwrap();
        return Err(cloned);
    }

    // Return the duration and result of the successful operation
    let (duration, _) = result.unwrap().unwrap();
    Ok(duration)
}

// Generic function to perform operations on various types of encrypted integers
fn perform_operation<T, U>(value1: T, value2: T, client_key: &tfhe::ClientKey)
where
    T: std::fmt::Display,
    U: FheOperations<T> + std::clone::Clone + Send + Sync,
{
    println!("Experiment on 2 variales of type: {}", type_name::<T>());

    let encrypted_num1 = Arc::new(RwLock::new(U::encrypt(value1, client_key)));
    let encrypted_num2 = Arc::new(RwLock::new(U::encrypt(value2, client_key)));
    
    println!("Encrypted the numbers..");

    // Vector of operations to run in parallel
    let operations: Vec<(&str, Box<dyn FnOnce(&Arc<RwLock<U>>, &Arc<RwLock<U>>) -> U + Send + Sync + UnwindSafe>)> = vec![
        ("Sum", Box::new(|a, b| U::plus(a, b))),
        ("Minus", Box::new(|a, b| U::minus(a, b))),
        // ("Mul", Box::new(|a, b| U::mul(a, b))),
        // ("Div", Box::new(|a, b| U::div(a, b))),
    ];

    // Example usage inside parallel execution
    operations.into_par_iter().for_each(|(name, operation)| {
        println!("Executing opeartion: {:?}", name);
        let result = measure_and_execute::<T, U, _>(Arc::clone(&encrypted_num1), Arc::clone(&encrypted_num2), client_key, operation, name);
        println!("Result: {:?}", result);
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    init_server_key();

    // Perform operations on various FHE types
    perform_operation::<u8, FheUint8>(20, 10, &client_key);
    // perform_operation::<u16, FheUint16>(100, 200, &client_key);
    // perform_operation::<u32, FheUint32>(1000, 2000, &client_key);

    Ok(())
}
