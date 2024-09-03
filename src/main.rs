use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, FheUint16, FheUint32};
// use tfhe::prelude::*;
use std::time::Instant;
use std::time::Duration;
use std::any::type_name;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use std::sync::Once;
use std::io::{self, Write};
use std::panic::{self, UnwindSafe};

// Initialize the server key globally
lazy_static! {
    static ref SERVER_KEY: tfhe::ServerKey = generate_server_key();
    static ref PRINT_LOCK: Mutex<()> = Mutex::new(());
    static ref ERROR_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
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

                fn plus(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self {
                    let a_lock = a.lock().unwrap();
                    let b_lock = b.lock().unwrap();
                    a_lock.clone() + b_lock.clone()
                }

                fn minus(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self {
                    let a_lock = a.lock().unwrap();
                    let b_lock = b.lock().unwrap();
                    a_lock.clone() - b_lock.clone()
                }

                fn mul(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self {
                    let a_lock = a.lock().unwrap();
                    let b_lock = b.lock().unwrap();
                    a_lock.clone() * b_lock.clone()
                }

                fn div(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self {
                    let a_lock = a.lock().unwrap();
                    let b_lock = b.lock().unwrap();
                    a_lock.clone() / b_lock.clone()
                }
            }
        )*
    };
}

// Define a trait for FHE operations
trait FheOperations<T> {
    fn encrypt(value: T, client_key: &tfhe::ClientKey) -> Self;
    fn decrypt(&self, client_key: &tfhe::ClientKey) -> T;
    fn plus(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self;
    fn minus(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self;
    fn mul(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self;
    fn div(a: &Arc<Mutex<Self>>, b: &Arc<Mutex<Self>>) -> Self;
}

// Apply macro to multiple FHE types
impl_fhe_operations! {
    FheUint8 => u8,
    FheUint16 => u16,
    FheUint32 => u32
}

// Utility function to perform an operation, measure time, and print the result
fn measure_and_execute<T, U, F>(
    encrypted_num1: Arc<Mutex<U>>,
    encrypted_num2: Arc<Mutex<U>>,
    client_key: &tfhe::ClientKey,
    operation: F,
    operation_name: &str,
) -> Result<Duration, String> where
    T: std::fmt::Display,
    U: FheOperations<T> + Clone + Send,
    F: FnOnce(&Arc<Mutex<U>>, &Arc<Mutex<U>>) -> U + Send + Sync + UnwindSafe,
{
    init_server_key();

    // Ensure the server key is set
    let result = panic::catch_unwind(|| {
        let start = Instant::now();
        println!("Running monitored operation: {}", operation_name);
        let result = operation(&encrypted_num1, &encrypted_num2);
        let duration: Duration = start.elapsed();
        let decrypted_result = result.decrypt(client_key);
        
        // Print the result and flush stdout
        // let _print_lock = PRINT_LOCK.lock().unwrap(); // Locking print mutex
        println!("{}: {}, Time Taken: {:?}", operation_name, decrypted_result, duration);
        io::stdout().flush().unwrap(); // Ensure the output is flushed
        Ok::<Duration, String>(duration);
    });

    if let Err(err) = result {
        // let _print_lock = PRINT_LOCK.lock().unwrap(); // Locking print mutex
        let error_message = format!("Error in operation '{}': {:?}", operation_name, err);
        let cloned = error_message.clone();
        eprintln!("{}", error_message);
        io::stderr().flush().unwrap(); // Ensure the error is flushed

        // Collect errors
        // let mut errors = ERROR_LOG.lock().unwrap();
        // errors.push(error_message);
        return Err(cloned);
    }

    Ok(Duration::new(0, 0))
}

// Generic function to perform operations on various types of encrypted integers
fn perform_operation<T, U>(value1: T, value2: T, client_key: &tfhe::ClientKey)
where
    T: std::fmt::Display,
    U: FheOperations<T> + std::clone::Clone + Send + Sync,
{
    println!("Experiment on 2 variales of type: {}", type_name::<T>());

    let encrypted_num1 = Arc::new(Mutex::new(U::encrypt(value1, client_key)));
    let encrypted_num2 = Arc::new(Mutex::new(U::encrypt(value2, client_key)));
    
    println!("Encrypted the numbers..");

    // Vector of operations to run in parallel
    let operations: Vec<(&str, Box<dyn FnOnce(&Arc<Mutex<U>>, &Arc<Mutex<U>>) -> U + Send + Sync + UnwindSafe>)> = vec![
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

    // After all operations are done, check for collected errors
    // let errors = ERROR_LOG.lock().unwrap();
    // if !errors.is_empty() {
        // eprintln!("Errors occurred during execution:");
        // for error in errors.iter() {
        //     eprintln!("{}", error);
        // }
    // }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a default configuration and generate keys
    // let config = ConfigBuilder::default().build();
    // let (client_key, server_key) = generate_keys(config);

    // Set the server key
    // set_server_key(server_key);

    // Set the server key in the global state
    // let mut server_key_lock = SERVER_KEY.lock().unwrap();
    // *server_key_lock = Some(server_key.clone());
    // set_server_key(server_key);
    // init_server_key(server_key);

    // The server key is generated and set globally in lazy_static
    // let client_key = {
    //     let config = ConfigBuilder::default().build();
    //     let (client_key, _) = generate_keys(config);
    //     client_key
    // };

    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    init_server_key();

    // Perform operations on various FHE types
    perform_operation::<u8, FheUint8>(10, 20, &client_key);
    // perform_operation::<u16, FheUint16>(100, 200, &client_key);
    // perform_operation::<u32, FheUint32>(1000, 2000, &client_key);

    Ok(())
}
