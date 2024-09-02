use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a default configuration for the encryption scheme
    let config = ConfigBuilder::default().build();

    // Generate keys, client = private, server = public
    let (client_key, server_key) = generate_keys(config);

    // Set the server key
    set_server_key(server_key);

    // Example numbers for operations
    let num1 = 10u16;
    let num2 = 20u16;

    // Encrypt numbers
    let mut start = Instant::now();
    let encrypted_num1 = FheUint16::encrypt(num1, &client_key);
    println!("Time for 1st encryption: {:?}", start.elapsed());

    start = Instant::now();
    let encrypted_num2 = FheUint16::encrypt(num2, &client_key);
    println!("Time for 2nd encryptioin: {:?}", start.elapsed());
    
    // Perform '+' operations
    start = Instant::now();
    let sum = &encrypted_num1 + &encrypted_num2;
    println!("Time for encrypted plus: {:?}", start.elapsed());

    start = Instant::now();
    let decrypted_sum: u16 = sum.decrypt(&client_key);
    println!("Time for decryption: {:?}", start.elapsed());

    // Perform '-' operations
    start = Instant::now();
    let difference = &encrypted_num1 - &encrypted_num2;
    println!("Time for encrypted minus: {:?}", start.elapsed());

    start = Instant::now();
    let decrypted_difference: u16 = difference.decrypt(&client_key);
    println!("Time for decryption: {:?}", start.elapsed());
    
    // Perform '*' operations
    start = Instant::now();
    let product = &encrypted_num1 * &encrypted_num2;
    println!("Time for encrypted *: {:?}", start.elapsed());

    start = Instant::now();
    let decrypted_product: u16 = product.decrypt(&client_key);
    println!("Time for decryption: {:?}", start.elapsed());

    // Perform '/' operations
    start = Instant::now();
    let quotient = &encrypted_num1 / &encrypted_num2;
    println!("Time for encrypted div: {:?}", start.elapsed());

    start = Instant::now();
    let decrypted_quotient: u16 = quotient.decrypt(&client_key);
    println!("Time for decryption: {:?}", start.elapsed());

    // Print results
    println!("Sum: {}", decrypted_sum);
    println!("Difference: {}", decrypted_difference);
    println!("Product: {}", decrypted_product);
    println!("Quotient: {}", decrypted_quotient);

    assert_eq!(decrypted_sum, num1 + num2);

    Ok(())
}
