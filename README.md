# token

```rust
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

impl Message for Messages {}

#[derive(Serialize, Deserialize, Debug)]
struct Messages {
    user_id: i64,
    date: i64,
}

fn main() {
    let key = "123ABC";

    let message = Messages {
        user_id: 10000,
        date: 123456789,
    };

    let token = encode(key, message, Algorithm::SHA256).unwrap();

    println!("{:?}", token);

    let result = decode::<Messages>(key, token);

    println!("{:?}", result);
}
```
